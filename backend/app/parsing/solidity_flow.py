"""Conservative intra-procedural def-use for one Solidity function.

Definitions come from the CFG statement nodes. A value reaches a sink only when
every reaching definition of the used expression includes that value. Unknown
control flow or an unparsed definition yields None, which is not evidence that
the value is absent or present.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.parsing.solidity_cfg import (
    FunctionCfg,
    _consume_parens,
    _skip_string_or_comment,
    build_function_cfg,
)

_NOISE = frozenset(
    {
        "abi",
        "assert",
        "block",
        "bool",
        "bytes",
        "calldata",
        "ecrecover",
        "encode",
        "encodePacked",
        "false",
        "keccak256",
        "memory",
        "msg",
        "require",
        "sender",
        "sha256",
        "storage",
        "string",
        "this",
        "true",
        "uint",
        "address",
    }
)
_DOMAIN_MARKERS = (
    "DOMAIN_SEPARATOR",
    "domainSeparator",
    "chainid",
    "chainId",
    "address(this)",
    "typeHash",
    "TYPEHASH",
    "typehash",
)
_ORACLE_LABELS = ("roundId", "answer", "startedAt", "updatedAt", "answeredInRound")


@dataclass(frozen=True)
class FlowEdge:
    source: str
    target: str
    kind: str
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class _Def:
    expr: str
    node: int


@dataclass
class FunctionFlow:
    known: bool
    edges: list[FlowEdge] = field(default_factory=list)
    incoming: dict[int, dict[str, frozenset[_Def]]] = field(default_factory=dict)
    cfg: FunctionCfg | None = None


def analyze_flow(function_text: str) -> FunctionFlow:
    cfg = build_function_cfg(function_text)
    flow = FunctionFlow(known=cfg.known, cfg=cfg)
    if not cfg.known:
        return flow
    gens: dict[int, dict[str, _Def]] = {node.node_id: {} for node in cfg.nodes}
    for name in _parameters(function_text):
        gens[cfg.entry][name] = _Def("<param>", cfg.entry)
        _remember(flow, function_text, name, "<param>", "param")
    for node in cfg.nodes:
        if node.kind in {
            "entry",
            "exit",
            "join",
            "if",
            "loop",
            "unchecked",
            "try",
            "break",
            "continue",
        }:
            continue
        for name, expr in _assignments(node.text):
            gens[node.node_id][name] = _Def(expr, node.node_id)
            kind = "hash" if "keccak256" in expr or "sha256" in expr else "assign"
            _remember(flow, function_text, expr, name, kind)
            _remember_indexes(flow, function_text, node.text)
    if not _solve(cfg, gens, flow):
        flow.known = False
    return flow


def digest_contains(function_text: str, marker: str) -> bool | None:
    """Whether every ecrecover digest in the function includes ``marker``."""
    flow = analyze_flow(function_text)
    if not flow.known or flow.cfg is None:
        return None
    uses = [
        node
        for node in flow.cfg.nodes
        if "ecrecover" in node.text and node.kind in {"stmt", "return", "require"}
    ]
    if not uses:
        return None
    results = [_arg_contains(flow, node, marker) for node in uses]
    if any(item is None for item in results):
        return None
    return all(item is True for item in results)


def digest_contains_any(
    function_text: str, markers: tuple[str, ...] = _DOMAIN_MARKERS
) -> bool | None:
    results = [digest_contains(function_text, marker) for marker in markers]
    if any(item is True for item in results):
        return True
    if any(item is None for item in results):
        return None
    return False


def signature_replay_gap(function_text: str) -> str | None:
    """A reason ecrecover may be replayable, or None when a nonce is signed and consumed."""
    if "ecrecover" not in function_text:
        return None
    unknown = False
    for name in ("nonce", "nonces"):
        included = digest_contains(function_text, name)
        if included is None:
            unknown = True
            continue
        if included is True:
            if _nonce_written(function_text, name):
                return None
            return f"{name} reaches the ecrecover digest but is not consumed"
    if unknown:
        return "nonce flow into ecrecover could not be established"
    return "ecrecover digest does not include a nonce from this function"


def signature_domain_gap(function_text: str) -> str | None:
    if "ecrecover" not in function_text:
        return None
    included = digest_contains_any(function_text)
    if included is True:
        return None
    if included is None:
        return "domain binding of the ecrecover digest could not be established"
    return "ecrecover digest is not bound to a domain, chain, or this contract"


def oracle_freshness_protects(function_text: str) -> bool | None:
    """True when a timestamp from the oracle call dominates use of its answer."""
    flow = analyze_flow(function_text)
    if not flow.known or flow.cfg is None:
        return None
    if "latestRoundData" not in function_text and "latestAnswer" not in function_text:
        return None
    answers: set[str] = set()
    fresh: set[str] = set()
    defined: list[tuple[str, str]] = []
    for node in flow.cfg.nodes:
        for name, expr in _assignments(node.text):
            defined.append((name, expr))
    for name, expr in defined:
        if expr == "latestRoundData.answer":
            answers.add(name)
        if expr in {"latestRoundData.updatedAt", "latestRoundData.answeredInRound"}:
            fresh.add(name)
    if "latestAnswer" in function_text and "latestRoundData" not in function_text:
        return False
    if not answers:
        return False
    uses = [
        node.node_id
        for node in flow.cfg.nodes
        if node.kind in {"stmt", "return", "require", "if"}
        and any(re.search(rf"\b{re.escape(name)}\b", node.text) for name in answers)
        and not any(expr.startswith("latestRoundData") for _name, expr in _assignments(node.text))
    ]
    if not uses:
        return True
    if not fresh:
        return False
    checks = [
        node.node_id
        for node in flow.cfg.nodes
        if node.kind in {"require", "if"}
        and any(re.search(rf"\b{re.escape(name)}\b", node.text) for name in fresh)
    ]
    if not checks:
        return False
    return all(any(flow.cfg.dominates(check, use) for check in checks) for use in uses)


def _arg_contains(flow: FunctionFlow, node: object, marker: str) -> bool | None:
    arg = _call_arg(getattr(node, "text", ""), "ecrecover", 0)
    if arg is None or flow.cfg is None:
        return None
    return _expr_contains(arg, marker, flow, int(getattr(node, "node_id")), set())


def _expr_contains(
    expr: str, marker: str, flow: FunctionFlow, node_id: int, seen: set[str]
) -> bool | None:
    if _direct(expr, marker):
        return True
    env = flow.incoming.get(node_id, {})
    idents = [ident for ident in _idents(expr) if ident not in _NOISE and not _is_type_name(ident)]
    any_true = False
    unknown = False
    for ident in idents:
        if ident in seen:
            continue
        defs = env.get(ident)
        if not defs:
            continue
        results: list[bool | None] = []
        for definition in defs:
            if definition.expr == "<unknown>":
                results.append(None)
            else:
                results.append(
                    _expr_contains(definition.expr, marker, flow, definition.node, seen | {ident})
                )
        if any(item is True for item in results) and any(item is False for item in results):
            return False
        if any(item is None for item in results):
            unknown = True
            continue
        if results and all(item is True for item in results):
            any_true = True
    if any_true and unknown:
        return None
    if any_true:
        return True
    if unknown:
        return None
    return False


def _solve(cfg: FunctionCfg, gens: dict[int, dict[str, _Def]], flow: FunctionFlow) -> bool:
    preds: dict[int, list[int]] = {node.node_id: [] for node in cfg.nodes}
    for src, dst, _label in cfg.edges:
        if dst in preds:
            preds[dst].append(src)
    incoming: dict[int, dict[str, frozenset[_Def]]] = {node.node_id: {} for node in cfg.nodes}
    outgoing: dict[int, dict[str, frozenset[_Def]]] = {node.node_id: {} for node in cfg.nodes}
    limit = max(4, len(cfg.nodes) * len(cfg.nodes) + 2)
    for _ in range(limit):
        changed = False
        for node in cfg.nodes:
            merged: dict[str, set[_Def]] = {}
            for pred in preds[node.node_id]:
                for name, defs in outgoing[pred].items():
                    merged.setdefault(name, set()).update(defs)
            frozen = {name: frozenset(defs) for name, defs in merged.items()}
            if frozen != incoming[node.node_id]:
                incoming[node.node_id] = frozen
                changed = True
            out = dict(frozen)
            for name, definition in gens[node.node_id].items():
                out[name] = frozenset((definition,))
            if out != outgoing[node.node_id]:
                outgoing[node.node_id] = out
                changed = True
        if not changed:
            flow.incoming = incoming
            return True
    flow.incoming = incoming
    return False


def _assignments(text: str) -> list[tuple[str, str]]:
    raw = text.strip().rstrip(";").strip()
    if not raw or re.match(
        r"(if|for|while|do|return|require|assert|revert|break|continue|unchecked|try)\b", raw
    ):
        return []
    tuple_match = re.match(r"\((.*)\)\s*=\s*(.+)\Z", raw, re.S)
    if tuple_match:
        rhs = tuple_match.group(2).strip()
        parts = _split_top(tuple_match.group(1))
        oracle = "latestRoundData" in rhs
        found: list[tuple[str, str]] = []
        for index, part in enumerate(parts):
            name = _binding_name(part)
            if not name:
                continue
            if oracle and index < len(_ORACLE_LABELS):
                found.append((name, f"latestRoundData.{_ORACLE_LABELS[index]}"))
            else:
                found.append((name, rhs))
        return found
    split = _split_assign(raw)
    if split is None:
        return []
    lhs, rhs = split
    name = _binding_name(lhs)
    if not name:
        return []
    return [(name, rhs.strip())]


def _split_assign(text: str) -> tuple[str, str] | None:
    depth = 0
    index = 0
    while index < len(text):
        skipped = _skip_string_or_comment(text, index)
        if skipped is not None:
            index = skipped
            continue
        char = text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif (
            depth == 0
            and char == "="
            and not text.startswith("==", index)
            and not text.startswith("=>", index)
        ):
            if index > 0 and text[index - 1] in "=!<>":
                index += 1
                continue
            op = index - 1 if index > 0 and text[index - 1] in "+-*/%" else index
            lhs = text[:op].strip()
            rhs = text[index + 1 :].strip()
            return lhs, rhs
        index += 1
    return None


def _parameters(function_text: str) -> list[str]:
    match = re.search(r"\b(function|constructor|fallback|receive)\b", function_text)
    start = match.end() if match else 0
    open_at = function_text.find("(", start)
    if open_at < 0:
        return []
    try:
        end = _consume_parens(function_text, open_at)
    except ValueError:
        return []
    names: list[str] = []
    for part in _split_top(function_text[open_at + 1 : end - 1]):
        name = _binding_name(part)
        if name:
            names.append(name)
    return names


def _binding_name(part: str) -> str:
    idents = re.findall(r"[A-Za-z_]\w*", part)
    for ident in reversed(idents):
        if ident in _NOISE or _is_type_name(ident) or ident in {"indexed", "payable"}:
            continue
        return str(ident)
    return ""


def _is_type_name(ident: str) -> bool:
    return bool(re.fullmatch(r"u?int\d*|bytes\d*|bytes|string|address|bool", ident))


def _idents(expr: str) -> list[str]:
    return re.findall(r"[A-Za-z_]\w*", expr)


def _direct(expr: str, marker: str) -> bool:
    if marker == "address(this)":
        return "address(this)" in re.sub(r"\s+", "", expr)
    if marker.lower() == "chainid":
        compact = re.sub(r"\s+", "", expr).lower()
        return "chainid" in compact or "block.chainid" in compact
    return bool(re.search(rf"\b{re.escape(marker)}\b", expr))


def _call_arg(text: str, name: str, index: int) -> str | None:
    match = re.search(rf"\b{name}\s*\(", text)
    if not match:
        return None
    open_at = text.find("(", match.start())
    try:
        end = _consume_parens(text, open_at)
    except ValueError:
        return None
    args = _split_top(text[open_at + 1 : end - 1])
    if len(args) <= index:
        return None
    return args[index].strip()


def _split_top(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    index = 0
    while index < len(text):
        skipped = _skip_string_or_comment(text, index)
        if skipped is not None:
            index = skipped
            continue
        char = text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
        index += 1
    parts.append(text[start:])
    return parts


def _nonce_written(function_text: str, name: str) -> bool:
    return bool(
        re.search(
            rf"\b{name}\b\s*(?:\[[^\]]+\])?\s*(?:\+\+|--|\+=|-=|=(?!=))",
            function_text,
        )
    )


def _remember(flow: FunctionFlow, function_text: str, source: str, target: str, kind: str) -> None:
    start = function_text.find(source) if source != "<param>" else 0
    if start < 0:
        start = 0
    end = start + (0 if source == "<param>" else len(source))
    flow.edges.append(FlowEdge(source[:80], target[:80], kind, start, end, source[:120]))
    for ident in _idents(source):
        if ident in _NOISE or ident == target or _is_type_name(ident):
            continue
        origin = function_text.find(ident)
        flow.edges.append(
            FlowEdge(
                ident, target[:80], kind, max(origin, 0), max(origin, 0) + len(ident), source[:120]
            )
        )


def _remember_indexes(flow: FunctionFlow, function_text: str, text: str) -> None:
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\[([^\]]+)\]", text):
        index = match.group(2).strip()
        start = function_text.find(match.group(0))
        if start < 0:
            start = 0
        flow.edges.append(
            FlowEdge(
                index[:80],
                match.group(1),
                "index",
                start,
                start + len(match.group(0)),
                match.group(0),
            )
        )
