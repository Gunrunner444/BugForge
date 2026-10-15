"""Arithmetic and batch-operation analysis.

Findings need a value flow, not a keyword: an accumulation over caller-supplied
data that can wrap, a narrowing cast of an arithmetic result that is never bounded,
a division that precedes a multiplication on a value-bearing path, or opposing
operations that round the same way. Checked arithmetic on a full-width integer is
not reported, because it reverts instead of corrupting state.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.parsing.solidity_research import (
    ResearchModel,
    RFunction,
    SemanticCandidate,
    cap,
    match_close,
    member_calls,
    plain_calls,
    skeleton,
    split_top,
)
from app.parsing.solidity_version import solidity_language_facts

FAMILY = "arithmetic"
_NARROW = (
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "uint96",
    "uint112",
    "uint128",
    "uint160",
    "int128",
)
_CEIL = re.compile(r"mulDivUp|divUp|ceilDiv|Rounding\.(Up|Ceil)|\+\s*\w+\s*-\s*1\s*\)\s*/", re.I)
_VALUE_EFFECT = re.compile(
    r"\.(transfer|safeTransfer|transferFrom|safeTransferFrom|send)\s*\(|\bcall\s*\{\s*value|\b_?(mint|burn)\s*\("
)


def _arithmetic_mode(model: ResearchModel, function: RFunction) -> str:
    pragma = model.contracts[function.contract].pragma
    return solidity_language_facts(f"pragma solidity {pragma};").arithmetic if pragma else "unknown"


def analyze_arithmetic(model: ResearchModel) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    for function in model.all_functions():
        if not function.has_body or function.contract not in model.contracts:
            continue
        if model.contracts[function.contract].is_interface:
            continue
        mode = _arithmetic_mode(model, function)
        found.extend(_batch_accumulation(function, mode))
        found.extend(_downcast(function))
        found.extend(_division_first(function))
    found.extend(_rounding_asymmetry(model))
    return cap(found)


def _candidate(
    function: RFunction,
    detector: str,
    title: str,
    summary: str,
    offset: int,
    facts: tuple[tuple[str, str], ...],
    observed: tuple[str, ...],
    missing: tuple[str, ...],
    confidence: str,
    in_loop: bool = False,
    tags: tuple[str, ...] = ("value_transfer",),
) -> SemanticCandidate:
    return SemanticCandidate(
        detector=f"arithmetic.{detector}",
        family=FAMILY,
        title=title,
        summary=summary,
        file=function.file,
        line=function.line + function.body[:offset].count("\n"),
        contract=function.contract,
        function=function.signature,
        path=(f"{function.contract}.{function.signature} @{function.file}:{function.line}",),
        facts=(*facts, ("in_loop", str(in_loop).lower())),
        observed=observed,
        missing=missing,
        confidence=confidence,
        impact_tags=(*tags, "arithmetic_in_loop") if in_loop else tags,
    )


def _loop_spans(body: str) -> list[tuple[int, int]]:
    from app.parsing.solidity_research import match_close, skeleton

    skel = skeleton(body)
    spans: list[tuple[int, int]] = []
    for match in re.finditer(r"\bfor\s*\(", skel):
        close_paren = match_close(skel, match.end() - 1)
        if close_paren == -1:
            continue
        brace = skel.find("{", close_paren)
        if brace == -1:
            continue
        end = match_close(skel, brace)
        if end != -1:
            spans.append((brace, end))
    return spans


def _unchecked_ranges(body: str) -> list[tuple[int, int]]:
    from app.parsing.solidity_research import match_close, skeleton

    skel = skeleton(body)
    ranges: list[tuple[int, int]] = []
    for match in re.finditer(r"\bunchecked\s*\{", skel):
        end = match_close(skel, match.end() - 1)
        if end != -1:
            ranges.append((match.end(), end))
    return ranges


def _batch_accumulation(function: RFunction, mode: str) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    body = function.body
    arrays = {p.name for p in function.params if p.type_name.endswith("[]") and p.name}
    if not arrays:
        return found
    unchecked = _unchecked_ranges(body)
    for start, end in _loop_spans(body):
        inside = body[start:end]
        for match in re.finditer(r"\b(\w+)\s*\+=\s*([^;]*);", inside):
            accumulator, operand = match.group(1), match.group(2)
            if not any(re.search(rf"\b{re.escape(a)}\s*\[", operand) for a in arrays):
                continue
            absolute = start + match.start()
            in_unchecked = any(low <= absolute <= high for low, high in unchecked)
            wraps = mode == "wrapping" or in_unchecked
            declaration = re.search(rf"\b(u?int\d*)\s+{re.escape(accumulator)}\b", body)
            kind = declaration.group(1) if declaration else "uint256"
            downcast = re.search(rf"\b(uint\d+)\s*\(\s*{re.escape(accumulator)}\s*\)", body)
            narrow = kind in _NARROW
            if not (wraps or (narrow and downcast)):
                continue
            used = bool(_VALUE_EFFECT.search(body[end:])) or bool(
                re.search(rf"(require|if)\s*\([^;]*\b{re.escape(accumulator)}\b", body[end:])
            )
            if not used:
                continue
            reason = (
                "the sum is unchecked, so it can wrap"
                if wraps
                else f"the sum is narrowed with {downcast.group(1) if downcast else kind} afterwards"
            )
            found.append(
                _candidate(
                    function,
                    "batch_accumulation_overflow",
                    "Caller-supplied batch can overflow its own total",
                    f"{function.contract}.{function.name} sums `{operand.strip()[:40]}` over a "
                    f"caller-supplied array into `{accumulator}` ({kind}); {reason}, and the total "
                    f"then gates a transfer or limit check.",
                    absolute,
                    (
                        ("accumulator", accumulator),
                        ("accumulator_type", kind),
                        ("arithmetic", mode),
                    ),
                    ("array elements are summed in a loop", "the total is used afterwards"),
                    ("checked full-width accumulation or an explicit bound",),
                    "medium",
                    in_loop=True,
                    tags=("value_transfer", "custody"),
                )
            )
    return found


def _downcast(function: RFunction) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    body = function.body
    for match in re.finditer(r"\b(uint(?:8|16|32|64|96|112|128|160))\s*\(", body):
        from app.parsing.solidity_research import match_close, skeleton

        skel = skeleton(body)
        close = match_close(skel, match.end() - 1)
        if close == -1:
            continue
        inner = body[match.end() : close]
        if not re.search(r"[*+\-/]|\*\*", inner):
            continue
        if re.search(r"\b(block\.timestamp|type\s*\()", inner) and "*" not in inner:
            continue
        kind = match.group(1)
        bounded = re.search(rf"type\s*\(\s*{kind}\s*\)\s*\.\s*max", body) or re.search(
            r"SafeCast|toUint\d+", body
        )
        if bounded:
            continue
        statement = body[body.rfind(";", 0, match.start()) + 1 : body.find(";", close)]
        if not (
            _VALUE_EFFECT.search(body)
            or re.search(r"[^=!<>]=[^=]", statement.replace(match.group(0), "", 1))
        ):
            continue
        found.append(
            _candidate(
                function,
                "unsafe_downcast_after_arithmetic",
                "Arithmetic result is narrowed without a bound",
                f"{function.contract}.{function.name} narrows `{inner.strip()[:50]}` to {kind} "
                "with no maximum check or SafeCast. A truncating cast does not revert, so the "
                "stored or transferred value silently loses its high bits.",
                match.start(),
                (("target_type", kind), ("expression", inner.strip()[:60])),
                ("an arithmetic expression is cast to a narrower integer",),
                (f"type({kind}).max bound or SafeCast",),
                "medium",
            )
        )
    return found


def _division_first(function: RFunction) -> list[SemanticCandidate]:
    body = function.body
    found: list[SemanticCandidate] = []
    pattern = re.compile(r"\(\s*[^()]*\w\s*/\s*[^()]*\w\s*\)\s*\*\s*\w|\b\w+\s*/\s*\w+\s*\*\s*\w+")
    for match in pattern.finditer(body):
        text = match.group(0)
        if "//" in text or "1e" in text.split("/", 1)[1].split("*")[0]:
            pass
        effect = bool(_VALUE_EFFECT.search(body)) or bool(
            re.search(r"\b\w+\s*(\[[^\]]*\])*\s*[-+]?=[^=]", body[match.end() :])
        )
        if not effect:
            continue
        found.append(
            _candidate(
                function,
                "division_before_multiplication",
                "Division loses precision before a multiplication",
                f"{function.contract}.{function.name} divides before multiplying in "
                f"`{text.strip()[:60]}`, so the multiplier amplifies the truncated remainder in a "
                "value-bearing result.",
                match.start(),
                (("expression", text.strip()[:80]),),
                ("integer division precedes multiplication",),
                ("multiplication before division, or mulDiv",),
                "medium",
                in_loop=any(low <= match.start() <= high for low, high in _loop_spans(body)),
            )
        )
    return found


# Direct helper chains only. Silo's withdraw path is five calls deep, then an expression.
_MAX_HELPER_DEPTH = 8
_MAX_CONST_HOPS = 3
_SKIP_FOLLOW = frozenset(
    {
        "mulDiv",
        "transfer",
        "safeTransfer",
        "transferFrom",
        "safeTransferFrom",
        "burn",
        "_burn",
        "mint",
        "_mint",
        "require",
        "assert",
        "revert",
        "balanceOf",
        "totalSupply",
        "allowance",
    }
)


@dataclass(frozen=True)
class _Val:
    """A quantity relative to the function that is currently being summarized."""

    kind: str
    name: str = ""
    field: str = ""
    direction: str = ""
    form: str = ""
    source: _Val | None = None
    path: tuple[str, ...] = ()
    fields: tuple[tuple[str, tuple[_Val, ...]], ...] = ()


@dataclass(frozen=True)
class _Effect:
    direction: str
    form: str
    asset: _Val
    shares: str
    path: tuple[str, ...]
    offset: int


@dataclass(frozen=True)
class _Summary:
    effects: tuple[_Effect, ...] = ()
    returns: tuple[tuple[_Val, ...], ...] = ()


@dataclass(frozen=True)
class RoundingPayout:
    """A connected share-burn and fixed asset transfer. Ceiling is not a candidate."""

    contract: str
    function: str
    file: str
    direction: str
    form: str
    asset: str
    shares: str
    helper_path: str
    line: int


_EMPTY = _Summary()


def _rounding_asymmetry(model: ResearchModel) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    grouped: dict[tuple[str, str, str], list[RoundingPayout]] = {}
    for payout in connected_rounding_payouts(model):
        grouped.setdefault((payout.contract, payout.function, payout.asset), []).append(payout)
    for payouts in grouped.values():
        candidate = _payout_candidate(model, payouts)
        if candidate is not None:
            found.append(candidate)
    return found


def connected_rounding_payouts(model: ResearchModel) -> tuple[RoundingPayout, ...]:
    """Burn of a share conversion paired with transfer of that same asset amount.

    ``direction`` is ``floor``, ``ceil``, or ``unknown``. Unknown is not evidence that the
    path is safe, and ceiling is not reported as ``arithmetic.rounding_burn_floor``.
    Only externally reachable functions are entries. Helper math is evidence on that entry.
    """
    cache: dict[str, _Summary] = {}
    constants: dict[str, dict[str, str]] = {}
    found: list[RoundingPayout] = []
    for name in sorted(model.contracts):
        contract = model.contracts[name]
        if contract.is_interface:
            continue
        for function in contract.functions:
            if not function.has_body or not function.exposed:
                continue
            summary = _summary(model, function, cache, constants, [], 0)
            for effect in summary.effects:
                asset = _asset(effect.asset)
                if asset is None:
                    continue
                direction = effect.direction
                if direction.startswith("sym:"):
                    direction = "unknown"
                if direction not in {"floor", "ceil", "unknown"}:
                    direction = "unknown"
                path = (function.identity, *effect.path)
                found.append(
                    RoundingPayout(
                        contract=function.contract,
                        function=function.signature,
                        file=function.file,
                        direction=direction,
                        form=effect.form,
                        asset=_asset_label(asset),
                        shares=effect.shares,
                        helper_path=" -> ".join(path),
                        line=function.line + function.body[: effect.offset].count("\n"),
                    )
                )
    return tuple(found)


def _payout_candidate(
    model: ResearchModel, payouts: list[RoundingPayout]
) -> SemanticCandidate | None:
    directions = {item.direction for item in payouts}
    if directions == {"ceil"}:
        return None
    if directions == {"floor"}:
        detector = "rounding_burn_floor"
        chosen = max(payouts, key=lambda item: (len(item.helper_path), -item.line))
        how = "floor mulDiv" if chosen.form == "muldiv" else "floor division"
        title = "Shares burned for a fixed asset payout are rounded down"
        summary = (
            f"{chosen.contract}.{chosen.function.split('(')[0]} pays out exactly "
            f"`{chosen.asset}` assets and burns `{chosen.shares}` computed with {how}. "
            "The caller can withdraw assets for fewer shares than they are worth, and "
            "repeating the call extracts the rounding difference from other holders."
        )
        observed = ["fixed asset payout", f"share burn uses {how}"]
        missing = ("round-up conversion on the burn side",)
        confidence = "medium"
        conversion = "muldiv_floor" if chosen.form == "muldiv" else "infix_floor"
    elif "floor" in directions or "unknown" in directions:
        detector = "rounding_direction_unresolved"
        pool = [item for item in payouts if item.direction != "ceil"] or payouts
        chosen = max(pool, key=lambda item: (len(item.helper_path), -item.line))
        how = "mulDiv" if chosen.form == "muldiv" else "division"
        title = "Share-burn rounding direction is unresolved"
        summary = (
            f"{chosen.contract}.{chosen.function.split('(')[0]} pays `{chosen.asset}` assets and "
            f"burns `{chosen.shares}` from a {how} whose rounding direction is not a resolved "
            "floor or ceiling. An unresolved direction is not evidence that the path is safe."
        )
        observed = ["fixed asset payout", "rounding direction is unresolved"]
        missing = ("a resolved floor or ceiling rounding literal on the burned conversion",)
        confidence = "low"
        conversion = "muldiv_unresolved" if chosen.form == "muldiv" else "infix_unresolved"
    else:
        return None
    function = _exposed_function(model, chosen.contract, chosen.function)
    if function is None:
        return None
    facts = [
        ("shares_variable", chosen.shares),
        ("assets_parameter", chosen.asset),
        ("conversion", conversion),
        ("rounding", chosen.direction if detector.endswith("floor") else "unknown"),
    ]
    if "->" in chosen.helper_path:
        facts.append(("helper_path", chosen.helper_path))
        observed.append(f"helper path {chosen.helper_path}")
    offset = _offset_at_line(function, chosen.line)
    return _candidate(
        function,
        detector,
        title,
        summary,
        offset,
        tuple(facts),
        tuple(observed),
        missing,
        confidence,
        tags=("vault_accounting", "value_transfer", "reserve_accounting"),
    )


def _exposed_function(model: ResearchModel, contract: str, signature: str) -> RFunction | None:
    item = model.contracts.get(contract)
    if item is None:
        return None
    for function in item.functions:
        if function.signature == signature and function.exposed:
            return function
    return None


def _offset_at_line(function: RFunction, line: int) -> int:
    if line <= function.line:
        return 0
    seen = function.line
    for index, char in enumerate(function.body):
        if char == "\n":
            seen += 1
            if seen >= line:
                return index + 1
    return 0


def _summary(
    model: ResearchModel,
    function: RFunction,
    cache: dict[str, _Summary],
    constants: dict[str, dict[str, str]],
    stack: list[str],
    depth: int,
) -> _Summary:
    ident = function.identity
    if ident in cache:
        return cache[ident]
    if ident in stack or depth > _MAX_HELPER_DEPTH or not function.has_body:
        return _EMPTY
    stack.append(ident)
    try:
        summary = _build_summary(model, function, cache, constants, stack, depth)
    finally:
        stack.pop()
    cache[ident] = summary
    return summary


def _build_summary(
    model: ResearchModel,
    function: RFunction,
    cache: dict[str, _Summary],
    constants: dict[str, dict[str, str]],
    stack: list[str],
    depth: int,
) -> _Summary:
    env: dict[str, frozenset[_Val]] = {}
    for param in function.params:
        if param.name:
            env[param.name] = frozenset({_Val("p", name=param.name)})
    for ret in function.returns:
        if ret.name and ret.name not in env:
            env[ret.name] = frozenset()
    ctx = _Walk(
        model=model,
        function=function,
        cache=cache,
        constants=constants,
        stack=stack,
        depth=depth,
        skel=skeleton(function.body),
    )
    _walk(function.body, 0, len(function.body), env, ctx)
    _fallthrough_returns(function, env, ctx)
    effects = list(ctx.effects)
    for burn in ctx.burns:
        if burn.val.kind != "c" or burn.val.source is None:
            continue
        source = _asset(burn.val.source)
        if source is None:
            continue
        for transferred in ctx.transfers:
            if _asset(transferred) != source:
                continue
            effects.append(
                _Effect(
                    burn.val.direction,
                    burn.val.form,
                    source,
                    burn.label,
                    burn.val.path,
                    burn.offset,
                )
            )
            break
    return _Summary(_dedupe_effects(effects), tuple(tuple(slot) for slot in ctx.slots))


@dataclass
class _Burn:
    val: _Val
    label: str
    offset: int


@dataclass
class _Walk:
    model: ResearchModel
    function: RFunction
    cache: dict[str, _Summary]
    constants: dict[str, dict[str, str]]
    stack: list[str]
    depth: int
    skel: str
    effects: list[_Effect] = field(default_factory=list)
    burns: list[_Burn] = field(default_factory=list)
    transfers: list[_Val] = field(default_factory=list)
    slots: list[set[_Val]] = field(default_factory=list)


def _fallthrough_returns(function: RFunction, env: dict[str, frozenset[_Val]], ctx: _Walk) -> None:
    for index, ret in enumerate(function.returns):
        if not ret.name:
            continue
        values = env.get(ret.name, frozenset())
        if values:
            _add_slot(ctx, index, values)


def _add_slot(ctx: _Walk, index: int, values: frozenset[_Val]) -> None:
    while len(ctx.slots) <= index:
        ctx.slots.append(set())
    ctx.slots[index].update(values)


def _walk(body: str, begin: int, end: int, env: dict[str, frozenset[_Val]], ctx: _Walk) -> None:
    skel = ctx.skel
    i = begin
    while i < end:
        while i < end and skel[i].isspace():
            i += 1
        if i >= end:
            break
        if _at_word(skel, i, "assembly"):
            i = _skip_group(skel, i + len("assembly"), end)
            continue
        if _at_word(skel, i, "unchecked"):
            i = _skip_ws(skel, i + len("unchecked"), end)
            if i < end and skel[i] == "{":
                close = match_close(skel, i)
                if close < 0 or close > end:
                    return
                _walk(body, i + 1, close, env, ctx)
                i = close + 1
            continue
        if _at_word(skel, i, "for") or _at_word(skel, i, "while"):
            i = _after_paren(skel, i, end)
            i = _consume_branch(body, skel, i, end, env, ctx)
            continue
        if _at_word(skel, i, "if"):
            i = _consume_if(body, skel, i, end, env, ctx)
            continue
        if skel[i] == "{":
            close = match_close(skel, i)
            if close < 0 or close > end:
                return
            _walk(body, i + 1, close, env, ctx)
            i = close + 1
            continue
        semi = _find_semi(skel, i, end)
        _exec(body[i:semi], i, env, ctx)
        i = semi + 1 if semi < end else end


def _consume_if(
    body: str,
    skel: str,
    i: int,
    end: int,
    env: dict[str, frozenset[_Val]],
    ctx: _Walk,
) -> int:
    original = dict(env)
    branches: list[dict[str, frozenset[_Val]]] = []
    covered = False
    while True:
        i = _after_paren(skel, i, end)
        branch = dict(original)
        i = _consume_branch(body, skel, i, end, branch, ctx)
        branches.append(branch)
        i = _skip_ws(skel, i, end)
        if _at_word(skel, i, "else"):
            i = _skip_ws(skel, i + 4, end)
            if _at_word(skel, i, "if"):
                continue
            branch = dict(original)
            i = _consume_branch(body, skel, i, end, branch, ctx)
            branches.append(branch)
            covered = True
            break
        break
    if not covered:
        branches.append(original)
    env.clear()
    env.update(_union_env(original, branches))
    return i


def _consume_branch(
    body: str,
    skel: str,
    i: int,
    end: int,
    env: dict[str, frozenset[_Val]],
    ctx: _Walk,
) -> int:
    i = _skip_ws(skel, i, end)
    if i >= end:
        return i
    if _at_word(skel, i, "if"):
        return _consume_if(body, skel, i, end, env, ctx)
    if skel[i] == "{":
        close = match_close(skel, i)
        if close < 0 or close > end:
            return end
        _walk(body, i + 1, close, env, ctx)
        return close + 1
    semi = _find_semi(skel, i, end)
    _exec(body[i:semi], i, env, ctx)
    return semi + 1 if semi < end else end


def _exec(stmt: str, base: int, env: dict[str, frozenset[_Val]], ctx: _Walk) -> None:
    text = stmt.strip()
    if not text or text.startswith("//"):
        return
    if _at_word(text, 0, "emit") or text.startswith("emit "):
        return
    if _at_word(text, 0, "return") or text.startswith("return ") or text == "return":
        _record_return(text[len("return") :].strip(), base, env, ctx)
        return
    eq = _top_eq(text)
    if eq is not None:
        left, right = text[:eq].strip(), text[eq + 1 :].strip()
        if left.startswith("("):
            names = _tuple_names(left)
            values = _tuple_values(right, base, env, ctx)
            for index, name in enumerate(names):
                if name:
                    env[name] = values[index] if index < len(values) else frozenset({_Val("u")})
            return
        if re.fullmatch(r"(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?\s+)*[A-Za-z_]\w*", left):
            env[re.findall(r"[A-Za-z_]\w*", left)[-1]] = _eval(right, base, env, ctx)
            return
        _eval(right, base, env, ctx)
        return
    _scan_effects(text, base, env, ctx)


def _scan_effects(text: str, base: int, env: dict[str, frozenset[_Val]], ctx: _Walk) -> None:
    for match in re.finditer(r"(?<![\w])-=\s*([^;]+)", text):
        rhs = match.group(1).strip()
        _record_burns(_eval(rhs, base, env, ctx), rhs, base, ctx)
    seen: set[tuple[str, int]] = set()
    for call in member_calls(text):
        seen.add((call.name, call.start))
        if call.name in {"transfer", "safeTransfer"} and len(call.arguments) >= 2:
            _record_transfers(_eval(call.arguments[1], base, env, ctx), ctx)
        elif call.name in {"burn", "_burn"}:
            for arg in call.arguments:
                _record_burns(_eval(arg, base, env, ctx), arg, base, ctx)
        elif call.name not in _SKIP_FOLLOW:
            _apply_call(call.receiver, call.name, call.arguments, base, env, ctx)
    for name, args, pos in plain_calls(text):
        if (name, pos) in seen or name in _SKIP_FOLLOW:
            continue
        if name in {"burn", "_burn"}:
            for arg in args:
                _record_burns(_eval(arg, base, env, ctx), arg, base, ctx)
            continue
        _apply_call("", name, args, base, env, ctx)


def _record_return(expr: str, base: int, env: dict[str, frozenset[_Val]], ctx: _Walk) -> None:
    if not expr:
        _fallthrough_returns(ctx.function, env, ctx)
        return
    if expr.startswith("("):
        close = match_close(skeleton(expr), 0)
        if close != -1:
            for index, part in enumerate(split_top(expr[1:close])):
                _add_slot(ctx, index, _eval(part, base, env, ctx))
            return
    _add_slot(ctx, 0, _eval(expr, base, env, ctx))


def _tuple_values(
    expr: str, base: int, env: dict[str, frozenset[_Val]], ctx: _Walk
) -> list[frozenset[_Val]]:
    call = _whole_call(expr)
    if call is None:
        return [_eval(expr, base, env, ctx)]
    receiver, name, args = call
    _apply_call(receiver, name, args, base, env, ctx)
    return _return_slots(receiver, name, args, base, env, ctx)


def _eval(expr: str, base: int, env: dict[str, frozenset[_Val]], ctx: _Walk) -> frozenset[_Val]:
    text = expr.strip()
    if not text:
        return frozenset({_Val("u")})
    if text[0] == "(" and match_close(skeleton(text), 0) == len(text) - 1:
        return _eval(text[1:-1], base, env, ctx)
    if re.fullmatch(r"[A-Za-z_]\w*", text):
        if text in env and env[text]:
            return env[text]
        if text in ctx.function.param_names():
            return frozenset({_Val("p", name=text)})
        return frozenset({_Val("u")})
    if re.fullmatch(r"[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)+", text) and "(" not in text:
        parts = re.split(r"\s*\.\s*", text)
        current = _eval(parts[0], base, env, ctx)
        for field in parts[1:]:
            current = _access(current, field)
        return current
    struct = _struct(text, base, env, ctx)
    if struct is not None:
        return struct
    call = _whole_call(text)
    if call is not None:
        receiver, name, args = call
        return _apply_call(receiver, name, args, base, env, ctx)
    if "*" in text and "/" in text:
        return _eval_infix(text, base, env, ctx)
    return frozenset({_Val("u")})


def _apply_call(
    receiver: str,
    name: str,
    args: tuple[str, ...],
    base: int,
    env: dict[str, frozenset[_Val]],
    ctx: _Walk,
) -> frozenset[_Val]:
    if name == "mulDiv":
        return _eval_muldiv(receiver, args, base, env, ctx)
    if not receiver and len(args) == 1 and re.fullmatch(r"u?int\d*|address|bool|bytes\d*", name):
        return _eval(args[0], base, env, ctx)
    if name in _SKIP_FOLLOW:
        return frozenset({_Val("u")})
    named = _named_args(args)
    arity = len(named) if named is not None else len(args)
    target = _resolve(ctx.model, ctx.function, receiver, name, arity)
    if target is None:
        return frozenset({_Val("u")})
    summary = _summary(ctx.model, target, ctx.cache, ctx.constants, ctx.stack, ctx.depth + 1)
    bindings, exprs = _bindings(target, args, named, base, env, ctx)
    for effect in summary.effects:
        ctx.effects.extend(_propagate(effect, bindings, exprs, target.identity, base, ctx))
    slots = _remap_returns(summary, bindings, exprs, target.identity, ctx)
    if len(slots) == 1:
        return slots[0]
    return frozenset({_Val("u")})


def _return_slots(
    receiver: str,
    name: str,
    args: tuple[str, ...],
    base: int,
    env: dict[str, frozenset[_Val]],
    ctx: _Walk,
) -> list[frozenset[_Val]]:
    named = _named_args(args)
    arity = len(named) if named is not None else len(args)
    target = _resolve(ctx.model, ctx.function, receiver, name, arity)
    if target is None:
        return []
    summary = _summary(ctx.model, target, ctx.cache, ctx.constants, ctx.stack, ctx.depth + 1)
    bindings, exprs = _bindings(target, args, named, base, env, ctx)
    return _remap_returns(summary, bindings, exprs, target.identity, ctx)


def _eval_muldiv(
    receiver: str,
    args: tuple[str, ...],
    base: int,
    env: dict[str, frozenset[_Val]],
    ctx: _Walk,
) -> frozenset[_Val]:
    prefix = f"{receiver}." if receiver else ""
    factors = _muldiv_factors(prefix, list(args))
    if len(factors) >= 4:
        direction = _rounding(factors[3], ctx, env)
    elif len(factors) == 3:
        direction = _muldiv_body_direction(receiver, ctx)
    else:
        return frozenset({_Val("u")})
    out: set[_Val] = set()
    for src in _eval(factors[0], base, env, ctx):
        asset = _asset(src)
        if asset is None:
            continue
        out.add(_Val("c", direction=direction, form="muldiv", source=asset, path=()))
    return frozenset(out) or frozenset({_Val("u")})


def _eval_infix(
    expr: str, base: int, env: dict[str, frozenset[_Val]], ctx: _Walk
) -> frozenset[_Val]:
    slash = _top_level(expr, "/")
    if slash < 0 or "*" not in expr[:slash]:
        return frozenset({_Val("u")})
    direction = "ceil" if _CEIL.search(expr) else "floor"
    out: set[_Val] = set()
    for src in _eval(_infix_numerator(expr[:slash]), base, env, ctx):
        asset = _asset(src)
        if asset is None:
            continue
        out.add(_Val("c", direction=direction, form="infix", source=asset, path=()))
    return frozenset(out) or frozenset({_Val("u")})


def _infix_numerator(left: str) -> str:
    text = left.strip()
    if text.startswith("(") and match_close(skeleton(text), 0) == len(text) - 1:
        text = text[1:-1].strip()
    star = _top_level(text, "*")
    return text[:star] if star >= 0 else text


def _top_level(expr: str, token: str) -> int:
    skel = skeleton(expr)
    depth = 0
    for index, char in enumerate(skel):
        if char in "({[":
            depth += 1
        elif char in ")}]":
            depth -= 1
        elif char == token and depth == 0:
            return index
    return -1


def _muldiv_body_direction(receiver: str, ctx: _Walk) -> str:
    """Three-argument ``mulDiv`` is floor only when its resolved body is a floor division.

    A missing, ambiguous, or non-division body stays unknown. A four-argument call does not
    use this: its direction is the rounding argument, including a ceiling literal.
    """
    owner = _static_owner(receiver)
    owners: tuple[str, ...]
    if owner:
        owners = (owner,)
    else:
        owners = _uint_libraries(ctx.model, ctx.function.contract)
        if len(owners) != 1:
            return "unknown"
    if owners[0] in ctx.model.ambiguous:
        return "unknown"
    bodies = [
        item
        for item in ctx.model.functions_named(owners[0], "mulDiv")
        if len(item.params) == 3 and item.has_body
    ]
    if len(bodies) != 1:
        return "unknown"
    return _body_direction(bodies[0].body)


def _body_direction(body: str) -> str:
    if _CEIL.search(body):
        return "ceil"
    if "mulmod" in body and "inverse" in body and re.search(r"\bprod0\b", body):
        return "floor"
    if re.search(r"\breturn\b[^;]*\w+\s*\*\s*[^;]*\w+\s*/\s*\w+", body):
        return "floor"
    return "unknown"


def _resolve(
    model: ResearchModel, function: RFunction, receiver: str, name: str, arity: int
) -> RFunction | None:
    if name in _SKIP_FOLLOW or name in {"mulDiv"}:
        return None
    owner = function.contract if receiver in {"", "this"} else _static_owner(receiver)
    if not owner or owner in model.ambiguous or owner not in model.contracts:
        return None
    bodies = [
        item
        for item in model.functions_named(owner, name)
        if item.kind == "function" and len(item.params) == arity and item.has_body
    ]
    if len(bodies) != 1:
        return None
    return bodies[0]


def _bindings(
    target: RFunction,
    args: tuple[str, ...],
    named: dict[str, str] | None,
    base: int,
    env: dict[str, frozenset[_Val]],
    ctx: _Walk,
) -> tuple[dict[str, frozenset[_Val]], dict[str, str]]:
    exprs: dict[str, str] = {}
    if named is not None:
        for param in target.params:
            if param.name and param.name in named:
                exprs[param.name] = named[param.name]
    else:
        for param, arg in zip(target.params, args, strict=False):
            if param.name:
                exprs[param.name] = arg
    return {name: _eval(expr, base, env, ctx) for name, expr in exprs.items()}, exprs


def _propagate(
    effect: _Effect,
    bindings: dict[str, frozenset[_Val]],
    exprs: dict[str, str],
    callee: str,
    offset: int,
    ctx: _Walk,
) -> list[_Effect]:
    direction = _remap_direction(effect.direction, exprs, ctx)
    found: list[_Effect] = []
    for value in _remap(effect.asset, bindings, callee):
        asset = _asset(value)
        if asset is None:
            continue
        found.append(
            _Effect(direction, effect.form, asset, effect.shares, (callee, *effect.path), offset)
        )
    return found


def _remap_returns(
    summary: _Summary,
    bindings: dict[str, frozenset[_Val]],
    exprs: dict[str, str],
    callee: str,
    ctx: _Walk,
) -> list[frozenset[_Val]]:
    remapped: list[frozenset[_Val]] = []
    for slot in summary.returns:
        out: set[_Val] = set()
        for value in slot:
            if value.kind == "c":
                direction = _remap_direction(value.direction, exprs, ctx)
                out.update(_remap_conversion(value, bindings, direction, callee))
            else:
                out.update(_remap(value, bindings, callee))
        remapped.append(frozenset(out) or frozenset({_Val("u")}))
    return remapped


def _remap(value: _Val, bindings: dict[str, frozenset[_Val]], callee: str) -> frozenset[_Val]:
    if value.kind == "p":
        return bindings.get(value.name, frozenset({_Val("u")}))
    if value.kind == "f":
        return _access(bindings.get(value.name, frozenset({_Val("u")})), value.field)
    if value.kind == "s":
        pairs: list[tuple[str, tuple[_Val, ...]]] = []
        for field, inners in value.fields:
            mapped: set[_Val] = set()
            for inner in inners:
                mapped.update(_remap(inner, bindings, callee))
            pairs.append((field, tuple(mapped)))
        return frozenset({_Val("s", fields=tuple(pairs))})
    return frozenset({_Val("u")})


def _remap_conversion(
    value: _Val,
    bindings: dict[str, frozenset[_Val]],
    direction: str,
    callee: str,
) -> frozenset[_Val]:
    if value.source is None:
        return frozenset({_Val("u")})
    out: set[_Val] = set()
    for src in _remap(value.source, bindings, callee):
        asset = _asset(src)
        if asset is None:
            continue
        out.add(
            _Val(
                "c", direction=direction, form=value.form, source=asset, path=(callee, *value.path)
            )
        )
    return frozenset(out)


def _remap_direction(direction: str, exprs: dict[str, str], ctx: _Walk) -> str:
    if not direction.startswith("sym:"):
        return direction
    token = direction[4:]
    if "." in token:
        param, field = token.split(".", 1)
        expr = _field_expr(exprs.get(param, ""), field)
        if expr is None:
            return "unknown"
        return _rounding(expr, ctx, {})
    expr = exprs.get(token)
    if expr is None:
        return "unknown"
    return _rounding(expr, ctx, {})


def _rounding(
    expr: str,
    ctx: _Walk,
    env: dict[str, frozenset[_Val]],
    *,
    contract: str | None = None,
    hops: int = 0,
    seen: set[tuple[str, str]] | None = None,
) -> str:
    text = expr.strip()
    if text.startswith("(") and match_close(skeleton(text), 0) == len(text) - 1:
        return _rounding(text[1:-1], ctx, env, contract=contract, hops=hops, seen=seen)
    has_ceil = re.search(r"\.(?:Ceil|Up)\b", text) is not None
    has_floor = re.search(r"\.(?:Floor|Down)\b", text) is not None
    if has_ceil and has_floor:
        return "unknown"
    if has_ceil:
        return "ceil"
    if has_floor:
        return "floor"
    owner = contract or ctx.function.contract
    qualified = re.fullmatch(r"([A-Za-z_]\w*)\.([A-Za-z_]\w*)", text)
    if qualified:
        if contract is None and qualified.group(1) in ctx.function.param_names():
            return f"sym:{qualified.group(1)}.{qualified.group(2)}"
        return _constant_direction(
            ctx, qualified.group(1), qualified.group(2), hops, set() if seen is None else seen
        )
    bare = re.fullmatch(r"[A-Za-z_]\w*", text)
    if bare is None:
        return "unknown"
    if contract is None and (bare.group(0) in ctx.function.param_names() or bare.group(0) in env):
        return f"sym:{bare.group(0)}"
    return _constant_direction(ctx, owner, bare.group(0), hops, set() if seen is None else seen)


def _constant_direction(
    ctx: _Walk, contract: str, name: str, hops: int, seen: set[tuple[str, str]]
) -> str:
    if hops > _MAX_CONST_HOPS or (contract, name) in seen:
        return "unknown"
    if contract in ctx.model.ambiguous or contract not in ctx.model.contracts:
        return "unknown"
    seen.add((contract, name))
    expr = _constant_map(ctx, contract).get(name)
    if expr is None:
        for base in ctx.model.bases_of(contract):
            expr = _constant_map(ctx, base).get(name)
            if expr is not None:
                contract = base
                break
    if expr is None:
        return "unknown"
    return _rounding(expr, ctx, {}, contract=contract, hops=hops + 1, seen=seen)


def _constant_map(ctx: _Walk, contract: str) -> dict[str, str]:
    cached = ctx.constants.get(contract)
    if cached is not None:
        return cached
    item = ctx.model.contracts.get(contract)
    found: dict[str, str] = {}
    if item is not None:
        skel = skeleton(item.body)
        depth = 0
        start = 0
        for index, char in enumerate(skel):
            if char == "{":
                if depth == 0:
                    start = index + 1
                depth += 1
            elif char == "}":
                depth = max(0, depth - 1)
                if depth == 0:
                    start = index + 1
            elif char == ";" and depth == 0:
                statement = item.body[start:index].strip()
                start = index + 1
                match = re.search(r"(?<![\w.])([A-Za-z_]\w*)\s*=\s*(.+)$", statement, re.S)
                if match and match.group(1) not in found:
                    found[match.group(1)] = match.group(2).strip()
    ctx.constants[contract] = found
    return found


def _uint_libraries(model: ResearchModel, contract: str) -> tuple[str, ...]:
    found: list[str] = []
    for owner in model.lineage(contract):
        item = model.contracts.get(owner)
        if item is None:
            continue
        for match in re.finditer(r"\busing\s+([A-Za-z_]\w*)\s+for\s+uint(?:256)?\b", item.body):
            if match.group(1) not in found:
                found.append(match.group(1))
    return tuple(found)


def _struct(
    expr: str, base: int, env: dict[str, frozenset[_Val]], ctx: _Walk
) -> frozenset[_Val] | None:
    text = expr.strip()
    if not text.endswith(")"):
        return None
    skel = skeleton(text)
    open_at = _match_open(skel, len(text) - 1)
    if open_at < 0:
        return None
    inside = text[open_at + 1 : -1].strip()
    if not (inside.startswith("{") and inside.endswith("}")):
        return None
    head = text[:open_at].strip()
    if not _is_type_head(head):
        return None
    pairs: list[tuple[str, tuple[_Val, ...]]] = []
    for part in split_top(inside[1:-1]):
        field_expr = _split_colon(part)
        if field_expr is None:
            continue
        field, value = field_expr
        pairs.append((field, tuple(_eval(value, base, env, ctx))))
    return frozenset({_Val("s", fields=tuple(pairs))})


def _whole_call(expr: str) -> tuple[str, str, tuple[str, ...]] | None:
    text = expr.strip()
    if not text.endswith(")"):
        return None
    skel = skeleton(text)
    open_at = _match_open(skel, len(text) - 1)
    if open_at < 0:
        return None
    inside = text[open_at + 1 : -1].strip()
    head = text[:open_at].strip()
    # ``Type({field: value})`` is a struct. ``_withdraw({_assets: amount})`` is a call.
    if inside.startswith("{") and inside.endswith("}") and _is_type_head(head):
        return None
    args = tuple(split_top(text[open_at + 1 : -1]))
    if args == ("",):
        args = ()
    member = re.fullmatch(r"(.+?)\s*\.\s*([A-Za-z_]\w*)", head, re.S)
    if member:
        return member.group(1).strip(), member.group(2), args
    if re.fullmatch(r"[A-Za-z_]\w*", head):
        return "", head, args
    return None


def _named_args(args: tuple[str, ...]) -> dict[str, str] | None:
    if len(args) != 1:
        return None
    text = args[0].strip()
    if not (text.startswith("{") and text.endswith("}")):
        return None
    found: dict[str, str] = {}
    for part in split_top(text[1:-1]):
        pair = _split_colon(part)
        if pair is None:
            return None
        found[pair[0]] = pair[1]
    return found or None


def _field_expr(expr: str, field: str) -> str | None:
    text = expr.strip()
    named = _named_args((text,))
    if named is not None and field in named:
        return named[field]
    if not text.endswith(")"):
        return None
    skel = skeleton(text)
    open_at = _match_open(skel, len(text) - 1)
    if open_at < 0:
        return None
    inside = text[open_at + 1 : -1].strip()
    named = _named_args((inside,))
    if named is None:
        return None
    return named.get(field)


def _access(values: frozenset[_Val], field: str) -> frozenset[_Val]:
    out: set[_Val] = set()
    for value in values:
        if value.kind == "p":
            out.add(_Val("f", name=value.name, field=field))
        elif value.kind == "s":
            matched = [inners for name, inners in value.fields if name == field]
            if matched:
                out.update(matched[0])
            else:
                out.add(_Val("u"))
        else:
            out.add(_Val("u"))
    return frozenset(out) or frozenset({_Val("u")})


def _asset(value: _Val | None) -> _Val | None:
    if value is not None and value.kind in {"p", "f"}:
        return _Val(value.kind, name=value.name, field=value.field)
    return None


def _asset_label(value: _Val) -> str:
    if value.kind == "f":
        return f"{value.name}.{value.field}"
    return value.name


def _record_burns(values: frozenset[_Val], expr: str, offset: int, ctx: _Walk) -> None:
    label = expr.strip()
    if not re.fullmatch(r"[A-Za-z_]\w*", label):
        label = label[:40]
    for value in values:
        if value.kind == "c":
            ctx.burns.append(_Burn(value, label, offset))


def _record_transfers(values: frozenset[_Val], ctx: _Walk) -> None:
    for value in values:
        asset = _asset(value)
        if asset is not None:
            ctx.transfers.append(asset)


def _dedupe_effects(effects: list[_Effect]) -> tuple[_Effect, ...]:
    seen: set[tuple[str, str, str, str, tuple[str, ...]]] = set()
    out: list[_Effect] = []
    for effect in effects:
        asset = _asset(effect.asset)
        if asset is None:
            continue
        key = (effect.direction, effect.form, asset.kind, _asset_label(asset), effect.path)
        if key in seen:
            continue
        seen.add(key)
        out.append(effect)
    return tuple(out)


def _union_env(
    original: dict[str, frozenset[_Val]], branches: list[dict[str, frozenset[_Val]]]
) -> dict[str, frozenset[_Val]]:
    keys: set[str] = set(original)
    for branch in branches:
        keys.update(branch)
    merged: dict[str, frozenset[_Val]] = {}
    for key in keys:
        values: set[_Val] = set()
        for branch in branches:
            values.update(branch.get(key, original.get(key, frozenset())))
        merged[key] = frozenset(values)
    return merged


def _tuple_names(left: str) -> list[str]:
    text = left.strip()
    if text.startswith("("):
        close = match_close(skeleton(text), 0)
        inner = text[1:close] if close != -1 else text[1:]
    else:
        inner = text
    names: list[str] = []
    for part in split_top(inner):
        idents = re.findall(r"[A-Za-z_]\w*", part)
        names.append(idents[-1] if idents else "")
    return names


def _split_colon(part: str) -> tuple[str, str] | None:
    skel = skeleton(part)
    depth = 0
    for index, char in enumerate(skel):
        if char in "({[":
            depth += 1
        elif char in ")}]":
            depth -= 1
        elif char == ":" and depth == 0:
            name = part[:index].strip()
            if re.fullmatch(r"[A-Za-z_]\w*", name):
                return name, part[index + 1 :].strip()
            return None
    return None


def _top_eq(text: str) -> int | None:
    skel = skeleton(text)
    depth = 0
    for index, char in enumerate(skel):
        if char in "({[":
            depth += 1
        elif char in ")}]":
            depth -= 1
        elif char == "=" and depth == 0:
            prev = skel[index - 1] if index else ""
            nxt = skel[index + 1] if index + 1 < len(skel) else ""
            if prev in "=!<>+-*/%&|^" or nxt == "=":
                continue
            return index
    return None


def _is_type_head(head: str) -> bool:
    tail = head.strip().split(".")[-1]
    return bool(re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", head.strip())) and bool(
        tail and tail[0].isupper()
    )


def _static_owner(receiver: str) -> str:
    tail = receiver.strip().split(".")[-1].strip() if receiver.strip() else ""
    if tail and tail[0].isupper() and re.fullmatch(r"[A-Za-z_]\w*", tail):
        return tail
    return ""


def _muldiv_factors(prefix: str, arguments: list[str]) -> list[str]:
    """Static ``Math.mulDiv(x, y, den)`` and ``x.mulDiv(y, den)`` share one factor list."""
    receiver = prefix.strip()
    if receiver.endswith("."):
        receiver = receiver[:-1].strip()
    tail = receiver.split(".")[-1].strip() if receiver else ""
    if tail and tail[0].isupper():
        return arguments
    return [receiver, *arguments]


def _at_word(text: str, index: int, word: str) -> bool:
    if index < 0 or index >= len(text) or not text.startswith(word, index):
        return False
    end = index + len(word)
    if end < len(text) and (text[end].isalnum() or text[end] == "_"):
        return False
    if index > 0 and (text[index - 1].isalnum() or text[index - 1] == "_"):
        return False
    return True


def _skip_ws(text: str, index: int, end: int) -> int:
    while index < end and text[index].isspace():
        index += 1
    return index


def _after_paren(skel: str, index: int, end: int) -> int:
    paren = skel.find("(", index, end)
    if paren < 0:
        return end
    close = match_close(skel, paren)
    if close < 0:
        return end
    return close + 1


def _find_semi(skel: str, index: int, end: int) -> int:
    depth = 0
    for cursor in range(index, end):
        char = skel[cursor]
        if char in "({[":
            depth += 1
        elif char in ")}]":
            depth -= 1
        elif char == ";" and depth == 0:
            return cursor
    return end


def _skip_group(skel: str, index: int, end: int) -> int:
    while index < end and skel[index] != "{":
        if skel[index] == ";":
            return index + 1
        index += 1
    if index >= end or skel[index] != "{":
        return end
    close = match_close(skel, index)
    return end if close < 0 else close + 1


def _match_open(skel: str, close_index: int) -> int:
    depth = 0
    for index in range(close_index, -1, -1):
        char = skel[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                return index
    return -1
