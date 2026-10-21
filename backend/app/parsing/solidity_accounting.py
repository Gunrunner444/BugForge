"""Token balance-delta accounting analysis.

The dangerous assumption is that a contract's balance after an operation equals what
the operation received. It fails for fee-on-transfer tokens, rebasing tokens, tokens
that return false, and balances changed by an external transfer. Each candidate
names the credited expression and the missing balance-delta control. The token's
behavior is reported as ``unknown`` unless the source establishes it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.parsing.solidity_research import (
    MemberCall,
    ResearchModel,
    RFunction,
    SemanticCandidate,
    cap,
    member_calls,
    mentions,
)

FAMILY = "balance_delta"
_BALANCE = r"balanceOf\s*\(\s*address\(this\)\s*\)"
_CREDIT = re.compile(
    r"(?:\b\w+\s*(?:\[[^\]]*\]\s*)*(?:\+=|=)\s*[^;=][^;]*;)|(?:\b_?(?:mint|safeMint)\s*\([^;]*;)"
)


def analyze_balance_delta(model: ResearchModel) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    for function in model.all_functions():
        if not function.has_body or function.contract not in model.contracts:
            continue
        if model.contracts[function.contract].is_interface:
            continue
        found.extend(_inflow(model, function))
        found.extend(_pull_all(model, function))
        found.extend(_balance_as_deposit(model, function))
        found.extend(_unchecked_return(function))
        found.extend(_reported_balance(model, function))
    found.extend(_cached_balance(model))
    return cap(found)


def _token_origin(model: ResearchModel, function: RFunction, receiver: str) -> tuple[str, str]:
    """(origin, confidence): is the token any caller-chosen address or a fixed asset?"""
    name = re.sub(r"^\w+\((.*)\)$", r"\1", receiver.strip())
    if any(p.name == name for p in function.params):
        return "caller-chosen token parameter", "medium"
    if name in model.state_vars(function.contract):
        return "configured token variable", "low"
    return "token expression", "low"


def _inflow(model: ResearchModel, function: RFunction) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    body = function.body
    for call in member_calls(body):
        if call.name not in {"transferFrom", "safeTransferFrom"} or len(call.arguments) < 3:
            continue
        if call.arguments[1].strip() not in {"address(this)", "this"}:
            continue
        amount = call.arguments[2].strip()
        tail = body[call.end :]
        before = body[: call.start]
        measured = len(re.findall(_BALANCE, before)) >= 1 and len(re.findall(_BALANCE, tail)) >= 1
        credit = _credited(tail, amount)
        if measured or not credit:
            continue
        origin, confidence = _token_origin(model, function, call.receiver)
        line = function.line + body[: call.start].count("\n")
        found.append(
            SemanticCandidate(
                detector="accounting.fee_on_transfer_mismatch",
                family=FAMILY,
                title="Deposit is credited with the requested amount, not the received amount",
                summary=(
                    f"{function.contract}.{function.name} pulls `{amount}` with "
                    f"`{call.name}` and credits `{credit}` without measuring the balance change. "
                    f"For a fee-on-transfer, rebasing, or non-reverting token the credit exceeds "
                    f"what the contract received. Token behavior: unknown ({origin})."
                ),
                file=function.file,
                line=line,
                contract=function.contract,
                function=function.signature,
                path=(
                    f"{function.contract}.{function.signature} @{function.file}:{function.line}",
                    f"pull: {call.text[:70]}",
                    f"credit: {credit[:70]}",
                ),
                facts=(
                    ("token_behavior", "unknown"),
                    ("token_origin", origin),
                    ("credited_expression", credit[:100]),
                    ("requested_amount", amount[:60]),
                ),
                observed=("tokens are pulled into the contract", "state is credited afterwards"),
                missing=("post-balance minus pre-balance accounting",),
                confidence=confidence,
                impact_tags=("custody", "vault_accounting", "value_transfer"),
            )
        )
    return found


def _credited(tail: str, amount: str) -> str:
    for match in _CREDIT.finditer(tail):
        statement = match.group(0)
        if re.match(r"\s*(require|assert|if|emit|return)\b", statement):
            continue
        right = statement.split("=", 1)[1] if "=" in statement else statement
        if mentions(right, amount) and not re.search(_BALANCE, statement):
            return statement.strip().rstrip(";")
    return ""


def _pull_all(model: ResearchModel, function: RFunction) -> list[SemanticCandidate]:
    if not function.exposed:
        return []
    state = model.contracts[function.contract].state_vars
    tracked = [
        name for name, kind in state if kind.startswith("mapping") or kind.startswith("uint")
    ]
    if not tracked:
        return []
    from app.parsing.solidity_caller_context import has_sender_authorization

    if has_sender_authorization(model, function) is not False:
        return []
    found: list[SemanticCandidate] = []
    for call in member_calls(function.body):
        if call.name not in {"transfer", "safeTransfer"} or len(call.arguments) < 2:
            continue
        amount = call.arguments[1]
        if not re.search(_BALANCE, amount) or re.search(r"[-]", amount):
            continue
        found.append(
            SemanticCandidate(
                detector="accounting.pull_all_balance",
                family=FAMILY,
                title="Function sends the contract's entire token balance",
                summary=(
                    f"{function.contract}.{function.name} transfers the whole absolute balance "
                    f"(`{amount.strip()[:60]}`) while the contract also tracks per-account "
                    f"state, so donated funds and other accounts' funds leave with it."
                ),
                file=function.file,
                line=function.line + function.body[: call.start].count("\n"),
                contract=function.contract,
                function=function.signature,
                path=(
                    f"{function.contract}.{function.signature} @{function.file}:{function.line}",
                ),
                facts=(
                    ("sent_expression", amount.strip()[:80]),
                    ("tracked_state", ",".join(tracked[:4])),
                ),
                observed=("absolute balance is sent", "the contract keeps its own accounting"),
                missing=("a recorded entitlement for the amount sent",),
                confidence="medium",
                impact_tags=("custody", "value_transfer", "vault_accounting"),
            )
        )
    return found


def _balance_as_deposit(model: ResearchModel, function: RFunction) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    body = function.body
    for match in re.finditer(rf"\b(\w+)\s*=\s*([^;]*{_BALANCE}[^;]*);", body):
        variable, expression = match.group(1), match.group(2)
        if re.search(r"[-]\s*\w", expression):
            continue
        tail = body[match.end() :]
        if re.search(rf"/\s*\(?\s*{re.escape(variable)}\b", tail):
            found.extend(_share_price(function, variable, match, tail))
            continue
        credit = _credited(tail, variable)
        if not credit or re.search(
            rf"\b{_BALANCE}", tail[: tail.find(variable) if variable in tail else 0]
        ):
            continue
        before = body[: match.start()]
        if re.search(_BALANCE, before):
            continue
        found.append(
            SemanticCandidate(
                detector="accounting.balance_as_deposit",
                family=FAMILY,
                title="Absolute token balance is credited as one account's deposit",
                summary=(
                    f"{function.contract}.{function.name} credits `{credit[:60]}` where "
                    f"`{variable}` is the contract's whole balance. Funds that were already "
                    f"there, including a donation, are credited to the caller."
                ),
                file=function.file,
                line=function.line + body[: match.start()].count("\n"),
                contract=function.contract,
                function=function.signature,
                path=(
                    f"{function.contract}.{function.signature} @{function.file}:{function.line}",
                ),
                facts=(
                    ("credited_expression", credit[:100]),
                    ("balance_expression", expression.strip()[:80]),
                ),
                observed=("balanceOf(address(this)) is credited",),
                missing=("subtraction of the previously recorded balance",),
                confidence="medium",
                impact_tags=("custody", "vault_accounting", "value_transfer"),
            )
        )
    return found


def _share_price(
    function: RFunction, variable: str, match: re.Match[str], tail: str
) -> list[SemanticCandidate]:
    if re.search(r"\+\s*1\b|MINIMUM_LIQUIDITY|address\(0\)", function.body):
        return []
    use = re.search(rf"[^;]*/\s*\(?\s*{re.escape(variable)}\b[^;]*;", tail)
    if use is None:
        return []
    return [
        SemanticCandidate(
            detector="accounting.donation_share_price",
            family=FAMILY,
            title="Share price depends on the absolute token balance",
            summary=(
                f"{function.contract}.{function.name} divides by `{variable}`, the contract's "
                f"whole token balance, to price new shares. A direct token transfer raises the "
                f"balance without minting shares, so the next depositor receives fewer shares "
                f"than their deposit is worth."
            ),
            file=function.file,
            line=function.line + function.body[: match.start()].count("\n"),
            contract=function.contract,
            function=function.signature,
            path=(f"{function.contract}.{function.signature} @{function.file}:{function.line}",),
            facts=(("denominator", variable), ("conversion", use.group(0).strip()[:100])),
            observed=("balanceOf(address(this)) is the share-price denominator",),
            missing=("internally tracked assets or virtual shares",),
            confidence="medium",
            impact_tags=("vault_accounting", "custody", "value_transfer"),
        )
    ]


def _unchecked_return(function: RFunction) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    body = function.body
    for call in member_calls(body):
        if call.name not in {"transfer", "transferFrom"}:
            continue
        if call.name == "transfer" and len(call.arguments) != 2:
            continue
        if call.name == "transferFrom" and len(call.arguments) != 3:
            continue
        before = body[: call.start]
        line_start = before.rfind(";") + 1
        lead = body[line_start : call.start]
        if (
            re.search(r"(require|assert|if|bool|=|return|&&|\|\|)\s*\(?\s*$", lead)
            or "(" in lead.strip()
        ):
            continue
        if call.receiver.strip() in {"payable", ""} or call.receiver.strip().startswith("payable"):
            continue
        tail = body[call.end :]
        amount = call.arguments[-1].strip()
        credit = _credited(tail, amount) if call.name == "transferFrom" else ""
        before_credit = _credited(before, amount) if call.name == "transfer" else ""
        effect = credit or before_credit
        if not effect:
            continue
        found.append(
            SemanticCandidate(
                detector="accounting.unchecked_token_return",
                family=FAMILY,
                title="Token transfer result is ignored while accounting changes",
                summary=(
                    f"{function.contract}.{function.name} ignores the boolean result of "
                    f"`{call.name}` and updates `{effect[:60]}`. A token that returns false "
                    f"instead of reverting leaves accounting changed without a transfer."
                ),
                file=function.file,
                line=function.line + body[: call.start].count("\n"),
                contract=function.contract,
                function=function.signature,
                path=(
                    f"{function.contract}.{function.signature} @{function.file}:{function.line}",
                ),
                facts=(("ignored_call", call.text[:80]), ("accounting_effect", effect[:80])),
                observed=("transfer result is not checked",),
                missing=("require on the result, or SafeERC20",),
                confidence="medium",
                impact_tags=("custody", "vault_accounting"),
            )
        )
    return found


def _cached_balance(model: ResearchModel) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    for name in sorted(model.contracts):
        contract = model.contracts[name]
        state = dict(contract.state_vars)
        for function in contract.functions:
            if not function.has_body:
                continue
            for match in re.finditer(rf"\b(\w+)\s*=\s*[^;]*{_BALANCE}[^;]*;", function.body):
                variable = match.group(1)
                if variable not in state or "mapping" in state[variable]:
                    continue
                spenders = [
                    other
                    for other in contract.functions
                    if other is not function
                    and other.has_body
                    and re.search(rf"\.(transfer|safeTransfer)\s*\([^;]*\b{variable}\b", other.body)
                ]
                if not spenders:
                    continue
                found.append(
                    SemanticCandidate(
                        detector="accounting.cached_balance",
                        family=FAMILY,
                        title="Token balance is cached and later paid out",
                        summary=(
                            f"{name}.{function.name} stores the contract's token balance in "
                            f"`{variable}` and {name}.{spenders[0].name} later pays out that stored "
                            f"value. A rebasing token or an external transfer changes the real "
                            f"balance without updating the cache. Token behavior: unknown."
                        ),
                        file=function.file,
                        line=function.line + function.body[: match.start()].count("\n"),
                        contract=name,
                        function=function.signature,
                        path=(
                            f"{name}.{function.signature} @{function.file}:{function.line}",
                            f"{name}.{spenders[0].signature} @{spenders[0].file}:{spenders[0].line}",
                        ),
                        facts=(("cached_variable", variable), ("token_behavior", "unknown")),
                        observed=("balance is cached in storage", "the cache is paid out later"),
                        missing=("re-measuring the balance before paying out",),
                        confidence="low",
                        impact_tags=("custody", "vault_accounting"),
                    )
                )
    return found


# ---- reported balance reconciliation -------------------------------------------------------

_CALL_KEYWORDS = frozenset(
    {
        "if",
        "for",
        "while",
        "require",
        "assert",
        "revert",
        "return",
        "emit",
        "abi",
        "uint",
        "uint256",
        "address",
        "new",
    }
)
_LOCAL_FROM_CALL = re.compile(
    r"(?:u?int\d*\s+)?(?P<name>[A-Za-z_]\w*)\s*(?<![=!<>])=(?!=)\s*(?P<rhs>[^;]*\([^;]*)\s*;"
)
_STORE = re.compile(
    r"(?P<lhs>[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*(?<![=!<>])=(?!=)\s*(?P<rhs>[^;]*);"
)
_BALANCE_OF_THIS = re.compile(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)")
_DAYS = re.compile(r"\b(\d+)\s+days\b")
_SENDER_EQ = re.compile(
    r"(?:msg\.sender|_sender)\s*==\s*([^&|;]+)|([^&|;]+)\s*==\s*(?:msg\.sender|_sender)"
)


@dataclass(frozen=True)
class ReportedSite:
    """One exposed function that stores a value obtained from a call.

    ``balance_backed`` is the idle-token form only. A host callback is not idle
    just because some other contract in the model has the same function name.
    ``reported_form`` is ``idle_balance``, ``idle_plus_getter``, or ``other``.
    ``report_scope`` is ``self``, ``lineage``, ``host``, or ``unresolved``.
    """

    local: str
    field: str
    getter: str
    call: str
    balance_backed: bool
    role_getter: str
    unlock_seconds: str
    loss_ignored: bool
    outflow: str
    store_at: int = 0
    reported_form: str = "other"
    report_scope: str = "unresolved"
    external_getter: str = ""
    external_contract: str = ""
    address_getter: str = ""
    host: str = ""
    gain: str = ""
    # ``equal`` when the stored field is assigned the reported local itself.
    # ``upper_bound`` when the assignment is a reduced or scaled expression.
    store_relation: str = "upper_bound"

    @property
    def judgeable(self) -> bool:
        return bool(self.getter) and self.reported_form in {"idle_balance", "idle_plus_getter"}


def reported_site(model: ResearchModel, function: RFunction) -> ReportedSite | None:
    """The reconciliation this function performs, or None when the shape is absent.

    An external call through ``address(this)`` is resolved only on
    ``model.reporting_host``. A same-named function elsewhere in the model is
    not that host.
    """
    if not function.exposed or not function.has_body or function.kind != "function":
        return None
    found = _stored_report(model, function)
    if found is None:
        return None
    local, field, call, assign_at, relation = found
    getter = _stored_getter(model, function.contract, field)
    classified = _classify_reported(model, function.contract, call, 0, "self")
    form = classified.form if classified is not None else "other"
    scope = classified.scope if classified is not None else "unresolved"
    external_getter = classified.external_getter if classified is not None else ""
    external_contract = classified.external_contract if classified is not None else ""
    address_getter = classified.address_getter if classified is not None else ""
    host = model.reporting_host if scope == "host" else ""
    gain = ""
    if form == "idle_plus_getter" and not address_getter and external_getter:
        owner = host or function.contract
        if external_contract in {owner, function.contract}:
            gain = _gain_signature(model, owner, external_getter, function.name)
    role = _role_getter(model, function)
    unlock = _unlock_seconds(model, function.contract)
    ignored = _loss_ignored(function.body, local, field)
    outflow = _outflow_signature(model, function, field)
    backed = form == "idle_balance" and bool(getter)
    return ReportedSite(
        local=local,
        field=field,
        getter=getter,
        call=call[:120],
        balance_backed=backed,
        role_getter=role,
        unlock_seconds=unlock,
        loss_ignored=ignored,
        outflow=outflow,
        store_at=assign_at,
        reported_form=form if getter else "other",
        report_scope=scope if getter else "unresolved",
        external_getter=external_getter if form == "idle_plus_getter" and getter else "",
        external_contract=external_contract if form == "idle_plus_getter" and getter else "",
        address_getter=address_getter if form == "idle_plus_getter" and getter else "",
        host=host,
        gain=gain if form == "idle_plus_getter" and getter else "",
        store_relation=relation,
    )


def _body_line(function: RFunction, index: int) -> int:
    """File line of a body offset. The offset is a character index, not a line count."""
    if index < 0:
        return function.line
    origin = function.body_line or function.line
    return origin + function.body[:index].count("\n")


def _reported_balance(model: ResearchModel, function: RFunction) -> list[SemanticCandidate]:
    site = reported_site(model, function)
    if site is None:
        return []
    line = _body_line(function, site.store_at)
    gaps: list[str] = []
    if not site.judgeable:
        gaps.append(
            "the reported call does not resolve to idle token holdings or idle holdings "
            "plus one public uint getter"
        )
    if site.report_scope == "host" and model.reporting_host_evidence != "validated_profile":
        gaps.append("a validated host profile for the reporting callback")
    if site.unlock_seconds:
        gaps.append("the unlock formula is not judged from the duration literal")
    else:
        gaps.append("no unlock duration was found; unlock behavior is not judged")
    gaps.append("performance-fee share mint is not judged")
    gaps.append("protocol-fee share split is not judged")
    gaps.append("locked-share adjustments are not judged")
    if site.store_relation != "equal":
        gaps.append(
            "the stored assignment is not the reported value itself, so equality is not judged"
        )
    return [
        SemanticCandidate(
            detector="accounting.reported_balance",
            family=FAMILY,
            title="A report stores a called value as the accounted total",
            summary=(
                f"{function.contract}.{function.name} stores `{site.field}` from `{site.local}`, "
                f"which is assigned from `{site.call}`. "
                f"Form: {site.reported_form}. Scope: {site.report_scope}. "
                f"Role getter: {site.role_getter or 'none'}."
            ),
            file=function.file,
            line=max(line, function.line),
            contract=function.contract,
            function=function.signature,
            path=(
                f"{function.contract}.{function.signature} @{function.file}:{function.line}",
                f"reported call: {site.call[:80]}",
                f"stored field: {site.field}",
                f"form: {site.reported_form}",
                f"scope: {site.report_scope}",
            ),
            facts=(
                ("balance_backed", "true" if site.balance_backed else "false"),
                ("stored_getter", site.getter),
                ("reported_call", site.call[:100]),
                ("stored_field", site.field),
                ("role_getter", site.role_getter),
                ("token_behavior", "unknown"),
                ("unlock_seconds", site.unlock_seconds),
                ("loss_ignored", "true" if site.loss_ignored else "false"),
                ("outflow", site.outflow),
                ("reported_form", site.reported_form),
                ("report_scope", site.report_scope),
                ("external_getter", site.external_getter),
                ("external_contract", site.external_contract),
                ("external_address_getter", site.address_getter),
                ("reporting_host", site.host),
                ("reporting_host_evidence", model.reporting_host_evidence if site.host else ""),
                ("gain", site.gain),
                ("store_relation", site.store_relation),
            ),
            observed=("a called value is written into stored accounting",),
            missing=tuple(gaps),
            confidence="medium" if site.judgeable else "low",
            impact_tags=("custody", "vault_accounting"),
        )
    ]


def _store_relation(rhs: str, local: str) -> str:
    """``equal`` only when the stored field is assigned that local and nothing else."""
    if re.sub(r"\s+", "", rhs) == local:
        return "equal"
    return "upper_bound"


def _stored_report(
    model: ResearchModel, function: RFunction
) -> tuple[str, str, str, int, str] | None:
    """(local, field, call expression, assignment index, relation) for the first store."""
    body = function.body
    for match in _LOCAL_FROM_CALL.finditer(body):
        local = match.group("name")
        call = match.group("rhs").strip()
        if local in _CALL_KEYWORDS or "(" not in call:
            continue
        for store in _STORE.finditer(body[match.end() :]):
            rhs = store.group("rhs").strip()
            if not re.search(rf"\b{re.escape(local)}\b", rhs):
                continue
            if _BALANCE_OF_THIS.search(rhs):
                continue
            lhs = re.sub(r"\s+", "", store.group("lhs"))
            field = lhs.split(".")[-1]
            if not field or field == local:
                continue
            if "." not in lhs and field not in model.state_vars(function.contract):
                continue
            return local, field, call, match.end() + store.start(), _store_relation(rhs, local)
    return None


def _unique_function(model: ResearchModel, name: str) -> RFunction | None:
    found = [
        function
        for contract in model.contracts.values()
        if not contract.is_interface
        for function in contract.functions
        if function.kind == "function" and function.name == name and function.has_body
    ]
    if len(found) != 1:
        return None
    return found[0]


def _called_names(expr: str) -> list[str]:
    members = re.findall(r"\.([A-Za-z_]\w*)\s*\(", expr)
    if members:
        return [name for name in members if name not in _CALL_KEYWORDS]
    return [
        name
        for name in re.findall(r"(?<![\w.])([A-Za-z_]\w*)\s*\(", expr)
        if name not in _CALL_KEYWORDS
    ]


def _return_expr(body: str) -> str:
    found = [str(item) for item in re.findall(r"return\s+([^;]+);", body)]
    if len(found) != 1:
        return ""
    return found[0].strip()


def _primary_call(expr: str) -> str:
    """The call that produces the expression, ignoring calls nested in its arguments."""
    compact = expr.strip()
    member = re.search(r"\.([A-Za-z_]\w*)\s*\(", compact)
    if member and compact.rstrip().endswith(")"):
        # The last member call is the value. A cast such as ``T(x).method()`` ends that way.
        names = [str(item) for item in re.findall(r"\.([A-Za-z_]\w*)\s*\(", compact)]
        if names:
            return names[-1]
    plain = re.match(r"([A-Za-z_]\w*)\s*\(", compact)
    return str(plain.group(1)) if plain else ""


@dataclass(frozen=True)
class _ReportedValue:
    form: str
    scope: str
    external_getter: str = ""
    external_contract: str = ""
    address_getter: str = ""


_CAST_HOOK = re.compile(
    r"[A-Za-z_]\w*\s*\(\s*address\s*\(\s*this\s*\)\s*\)\s*\.\s*([A-Za-z_]\w*)\s*\(",
    re.S,
)


def _lookup(model: ResearchModel, owners: tuple[str, ...], name: str) -> RFunction | None:
    """The nearest body of ``name`` in ``owners``. Another contract's body is not a match."""
    for owner in owners:
        item = model.contracts.get(owner)
        if item is None or item.is_interface:
            continue
        matches = [
            function
            for function in item.functions
            if function.kind == "function" and function.name == name and function.has_body
        ]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            return None
    return None


def _is_idle_balance(expr: str) -> bool:
    return _primary_call(expr) == "balanceOf" and bool(_BALANCE_OF_THIS.search(expr))


def _top_sum(expr: str) -> tuple[str, str] | None:
    depth = 0
    splits: list[int] = []
    for index, char in enumerate(expr):
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "+" and depth == 0:
            splits.append(index)
    if len(splits) != 1:
        return None
    cut = splits[0]
    left, right = expr[:cut].strip(), expr[cut + 1 :].strip()
    if not left or not right:
        return None
    return left, right


def _addend(model: ResearchModel, contract: str, expr: str) -> tuple[str, str, str] | None:
    """(public uint getter, declaring contract, address getter) for one readable addend."""
    from app.discovery.bounty.properties import public_getter

    compact = re.sub(r"\s+", "", expr)
    if re.fullmatch(r"[A-Za-z_]\w*", compact):
        kind = model.state_vars(contract).get(compact, "")
        getter = public_getter(model, contract, compact)
        if getter == f"{compact}()" and re.fullmatch(r"u?int\d*", kind.replace(" ", "")):
            return getter, contract, ""
        return None
    member = re.fullmatch(r"([A-Za-z_]\w*)\.([A-Za-z_]\w*)\(\)", compact)
    if member is None:
        return None
    variable, method = member.group(1), member.group(2)
    if public_getter(model, contract, variable) != f"{variable}()":
        return None
    owner = model.contract_for_type(model.state_vars(contract).get(variable, ""))
    if not owner:
        return None
    target = _lookup(model, model.lineage(owner), method)
    if target is None or target.params or not target.exposed:
        return None
    if not target.returns or not target.returns[0].type_name.startswith("uint"):
        return None
    return target.signature, owner, f"{variable}()"


def _classify_reported(
    model: ResearchModel, contract: str, expr: str, depth: int, scope: str
) -> _ReportedValue | None:
    """What ``expr`` reports, following only this contract's lineage or the named host."""
    if depth > 4:
        return None
    expr = expr.strip()
    if not expr:
        return None
    parts = _top_sum(expr)
    if parts is not None:
        left, right = parts
        other = ""
        idle = False
        for side in (left, right):
            if _is_idle_balance(side):
                idle = True
            else:
                other = side
        if not idle or not other:
            return _ReportedValue("other", scope)
        addend = _addend(model, contract, other)
        if addend is None:
            return _ReportedValue("other", scope)
        getter, owner, address_getter = addend
        return _ReportedValue("idle_plus_getter", scope, getter, owner, address_getter)
    hook = _CAST_HOOK.search(expr)
    if hook and _primary_call(expr) == hook.group(1) and hook.group(1) != "balanceOf":
        host = model.reporting_host
        if not host:
            return _ReportedValue("other", "unresolved")
        target = _lookup(model, model.lineage(host), hook.group(1))
        if target is None:
            return _ReportedValue("other", "unresolved")
        returned = _return_expr(target.body)
        if not returned:
            return _ReportedValue("other", "unresolved")
        # Stay on the named host so an override is not resolved on the base that
        # merely forwards to it.
        inner = _classify_reported(model, host, returned, depth + 1, "host")
        if inner is None or inner.form == "other":
            return _ReportedValue("other", "unresolved")
        return _ReportedValue(
            inner.form, "host", inner.external_getter, inner.external_contract, inner.address_getter
        )
    if _is_idle_balance(expr):
        return _ReportedValue("idle_balance", scope)
    name = _primary_call(expr)
    if not name or name in _CALL_KEYWORDS:
        return _ReportedValue("other", scope)
    target = _lookup(model, model.lineage(contract), name)
    if target is None:
        return _ReportedValue("other", "unresolved")
    returned = _return_expr(target.body)
    if not returned:
        return _ReportedValue("other", "unresolved")
    next_scope = (
        scope if scope == "host" else ("self" if target.contract == contract else "lineage")
    )
    return _classify_reported(model, target.contract, returned, depth + 1, next_scope)


def _gain_signature(model: ResearchModel, contract: str, getter: str, report_name: str) -> str:
    """One exposed function, other than the report, that writes the public addend."""
    if not getter.endswith("()"):
        return ""
    variable = getter[:-2]
    if not re.fullmatch(r"[A-Za-z_]\w*", variable):
        return ""
    found: list[str] = []
    for function in model.functions_of(contract):
        if (
            not function.exposed
            or not function.has_body
            or function.kind != "function"
            or function.name == report_name
        ):
            continue
        if re.search(rf"\b{re.escape(variable)}\s*(?:\+=|(?<![=!<>])=(?!=))", function.body):
            found.append(function.signature)
    if len(found) == 1:
        return found[0]
    return ""


def _expr_is_field(model: ResearchModel, expr: str, field: str, depth: int) -> bool:
    if depth > 4:
        return False
    compact = re.sub(r"\s+", "", expr)
    if re.fullmatch(rf"(?:[A-Za-z_]\w*\.)*{re.escape(field)}", compact):
        return True
    name = _primary_call(expr)
    if not name or name in _CALL_KEYWORDS:
        return False
    target = _unique_function(model, name)
    if target is None:
        return False
    returned = _return_expr(target.body)
    if not returned:
        return False
    return _expr_is_field(model, returned, field, depth + 1)


def _stored_getter(model: ResearchModel, contract: str, field: str) -> str:
    from app.discovery.bounty.properties import public_getter

    direct = public_getter(model, contract, field)
    if direct.endswith("()"):
        return direct
    found: list[str] = []
    for function in model.functions_of(contract):
        if (
            not function.exposed
            or not function.has_body
            or function.params
            or function.mutability not in {"view", "pure"}
            or function.kind != "function"
        ):
            continue
        if not function.returns or not function.returns[0].type_name.startswith("uint"):
            continue
        returned = _return_expr(function.body)
        if returned and _expr_is_field(model, returned, field, 0):
            found.append(function.signature)
    if len(found) == 1:
        return found[0]
    return ""


def _authorization_bodies(model: ResearchModel, function: RFunction) -> list[str]:
    texts = [function.body]
    for name in function.modifiers:
        modifier = model.modifier(function.contract, name.split("(")[0])
        if modifier is not None and modifier.body:
            texts.append(modifier.body)
    followed: list[str] = []
    for text in texts:
        for name in _called_names(text):
            target = _unique_function(model, name)
            if target is not None:
                followed.append(target.body)
    return texts + followed


def _role_getter(model: ResearchModel, function: RFunction) -> str:
    fields: list[str] = []
    for text in _authorization_bodies(model, function):
        for match in _SENDER_EQ.finditer(text):
            expr = (match.group(1) or match.group(2) or "").strip()
            idents = re.findall(r"[A-Za-z_]\w*", expr)
            if idents:
                fields.append(idents[-1])
    seen: set[str] = set()
    for field_name in fields:
        if field_name in seen or field_name in {"msg", "sender", "_sender"}:
            continue
        seen.add(field_name)
        for item in model.functions_of(function.contract):
            if (
                item.name == field_name
                and item.exposed
                and not item.params
                and item.has_body
                and item.returns
                and item.returns[0].type_name.replace(" payable", "") == "address"
                and re.search(rf"\b{re.escape(field_name)}\b", item.body)
            ):
                return item.signature
    return ""


def _strip_comments(text: str) -> str:
    """Comments are not duration literals. A remark such as ``365.2425 days`` is not ``N days``."""
    without_block = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", without_block)


def _unlock_seconds(model: ResearchModel, contract: str) -> str:
    numbers: set[int] = set()
    for owner in model.lineage(contract):
        item = model.contracts.get(owner)
        if item is None:
            continue
        for function in item.functions:
            if not function.has_body:
                continue
            for match in _DAYS.finditer(_strip_comments(function.body)):
                numbers.add(int(match.group(1)))
    if len(numbers) != 1:
        return ""
    seconds = next(iter(numbers)) * 86400
    if seconds <= 0 or seconds > 366 * 86400:
        return ""
    return str(seconds)


def _loss_ignored(body: str, local: str, field: str) -> bool:
    stores: list[int] = []
    for match in _STORE.finditer(body):
        lhs = re.sub(r"\s+", "", match.group("lhs"))
        if lhs.split(".")[-1] != field:
            continue
        if not re.search(rf"\b{re.escape(local)}\b", match.group("rhs")):
            continue
        stores.append(match.start())
    if not stores:
        return False
    return all(_inside_increase_guard(body, index, local) for index in stores)


def _inside_increase_guard(body: str, index: int, local: str) -> bool:
    depth = 0
    cursor = index
    while cursor > 0:
        char = body[cursor]
        if char == "}":
            depth += 1
        elif char == "{":
            if depth == 0:
                return _guard_increases(body[max(0, cursor - 400) : cursor], local)
            depth -= 1
        cursor -= 1
    return False


def _guard_increases(head: str, local: str) -> bool:
    text = head.rstrip()
    if not text.endswith(")"):
        return False
    depth = 0
    start = -1
    for cursor in range(len(text) - 1, -1, -1):
        char = text[cursor]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                start = cursor
                break
    if start < 0:
        return False
    prefix = text[:start].rstrip()
    if not prefix.endswith("if"):
        return False
    condition = text[start + 1 : -1]
    return local in condition and ">" in condition


def _outflow_signature(model: ResearchModel, function: RFunction, field: str) -> str:
    found: list[str] = []
    for item in model.functions_of(function.contract):
        if (
            not item.exposed
            or not item.has_body
            or item.signature == function.signature
            or item.kind != "function"
        ):
            continue
        if not re.search(r"\.\s*(?:transfer|safeTransfer)\s*\(", item.body):
            continue
        if re.search(rf"\b{re.escape(field)}\b", item.body):
            continue
        found.append(item.signature)
    if len(found) == 1:
        return found[0]
    return ""


__all__ = ["MemberCall", "ReportedSite", "analyze_balance_delta", "reported_site"]
