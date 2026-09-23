"""Economic and token-aware dataflow for Solidity.

Classifications are evidence about how a call is used. They are not a proof
that a contract implements ERC-20, ERC-4626, or any other standard, and nothing
here marks a finding verified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.parsing.model import SyntaxEvent, SyntaxGraph
from app.parsing.solidity_cfg import _consume_parens, _skip_string_or_comment
from app.parsing.solidity_flow import (
    digest_contains,
    digest_contains_any,
    oracle_freshness_protects,
    signature_replay_gap,
)
from app.parsing.solidity_guards import reentrancy_guard_holds
from app.parsing.solidity_modifiers import resolve_modifier

_TOKEN_NAMES = {
    "ierc20": "erc20",
    "erc20": "erc20",
    "ierc20metadata": "erc20",
    "ierc721": "erc721",
    "erc721": "erc721",
    "ierc1155": "erc1155",
    "erc1155": "erc1155",
    "ierc4626": "erc4626",
    "erc4626": "erc4626",
}
_ERC20_METHODS = {"transfer", "transferfrom", "balanceof", "totalsupply", "approve", "allowance"}
_METHODS = (
    "transferFrom|safeTransferFrom|safeTransfer|increaseAllowance|decreaseAllowance|"
    "transfer|approve|permit|allowance|balanceOf"
)
_EXCHANGES = (
    "swap",
    "deposit",
    "mint",
    "redeem",
    "withdraw",
    "borrow",
    "repay",
    "liquidate",
    "addliquidity",
    "removeliquidity",
)
_BOUND_NAMES = {
    "minamountout",
    "amountoutmin",
    "minshares",
    "maxshares",
    "minassets",
    "maxassets",
    "deadline",
    "minout",
    "amountinmax",
}
_ACCOUNTING = re.compile(
    r"balance|share|deposit|supply|debt|owed|reserve|collateral|stake|liquidity",
    re.I,
)


@dataclass(frozen=True)
class TokenInteraction:
    classification: str
    confidence: str
    method: str
    token: str
    sender: str
    receiver: str
    amount: str
    function: str
    text: str


@dataclass(frozen=True)
class EconomicTransition:
    action: str
    contract: str
    function: str
    user: tuple[str, ...]
    protocol: tuple[str, ...]
    flows: tuple[str, ...]


@dataclass(frozen=True)
class DefiIssue:
    rule_id: str
    function: str
    summary: str


@dataclass
class DefiModel:
    interactions: list[TokenInteraction] = field(default_factory=list)
    transitions: list[EconomicTransition] = field(default_factory=list)
    issues: list[DefiIssue] = field(default_factory=list)
    kinds: dict[str, str] = field(default_factory=dict)


def analyze_defi(graph: SyntaxGraph) -> DefiModel:
    model = DefiModel()
    if graph.language != "solidity" or graph.parser_tier.value == "profile_fallback":
        return model
    model.kinds = _contract_kinds(graph)
    known = _contract_names(graph)
    for function in _functions(graph):
        name = _function_name(function)
        contract = _fields(function.extra).get("contract", "")
        stripped = _strip(function.text)
        types = _variable_types(graph, function, contract)
        calls = _token_calls(stripped, name, types, model.kinds, known)
        model.interactions.extend(calls)
        transition = _transition(name, contract, stripped, calls)
        if transition is not None:
            model.transitions.append(transition)
        model.issues.extend(_function_issues(graph, function, name, stripped, calls))
    model.issues.extend(_vault_issues(graph))
    return model


def _function_issues(
    graph: SyntaxGraph,
    function: SyntaxEvent,
    name: str,
    text: str,
    calls: list[TokenInteraction],
) -> list[DefiIssue]:
    found: list[DefiIssue] = []
    fee = _fee_issue(text, calls)
    if fee:
        found.append(DefiIssue("sol.fee_on_transfer", name, fee))
    donation = _donation_issue(text)
    if donation:
        found.append(DefiIssue("sol.donation_inflation", name, donation))
    rounding = _rounding_issue(name, text)
    if rounding:
        found.append(DefiIssue("sol.rounding_direction", name, rounding))
    slippage = _slippage_issue(name, text)
    if slippage:
        found.append(DefiIssue("sol.slippage", name, slippage))
    oracle = _oracle_issue(text)
    if oracle:
        found.append(DefiIssue("sol.oracle_accounting", name, oracle))
    lending = _lending_issue(name, text)
    if lending:
        found.append(DefiIssue("sol.lending", name, lending))
    amm = _amm_issue(name, text)
    if amm:
        found.append(DefiIssue("sol.amm", name, amm))
    approval = _approval_issue(name, function.text)
    if approval:
        found.append(DefiIssue("sol.approval", name, approval))
    callback = _callback_issue(graph, function, name)
    if callback:
        found.append(DefiIssue("sol.defi_reentrancy", name, callback))
    return found


def _fee_issue(text: str, calls: list[TokenInteraction]) -> str:
    moves = [
        call
        for call in calls
        if call.classification == "erc20" and call.method in {"transfer", "transferFrom"}
    ]
    if not moves:
        return ""
    amount = next((call.amount for call in moves if call.amount), "")
    token = moves[0].token
    if _credits_requested(text, amount) and not _credits_delta(text):
        return (
            f"The function credits `{amount or 'the requested amount'}` from "
            f"`{token}.{moves[0].method}`, but the underlying token balance delta can be smaller "
            "when the token takes a fee or returns a short transfer."
        )
    if _balance_reads(text, token) >= 1 and not _measures_delta(text, token):
        return (
            f"`{token}.{moves[0].method}` moves `{amount or 'an amount'}`, but the function never "
            "records the balance delta, so later accounting can treat the requested amount as received."
        )
    return ""


def _donation_issue(text: str) -> str:
    body = _body(text)
    defs = _simple_defs(body)
    for statement in _statements(body):
        if "/" not in statement:
            continue
        expanded = _expand(statement, defs)
        if not _share_conversion(statement, expanded):
            continue
        if _virtual_offset(statement, defs):
            continue
        return (
            "Share conversion uses this contract's external token balance together with "
            "total supply. An unsolicited donation can change the exchange rate for later "
            "deposits, especially while the vault is empty or nearly empty."
        )
    return ""


def _rounding_issue(name: str, text: str) -> str:
    if re.search(r"\b(for|while)\s*\(", text) and re.search(
        r"\b([A-Za-z_]\w*)\b\s*=\s*\1\b[^;]*/", text
    ):
        return (
            "A running balance is divided on each loop iteration, so truncation accumulates "
            "and can move value toward one side of the conversion."
        )
    if name.lower() in {"withdraw", "redeem", "swap", "removeliquidity"} and re.search(
        r"/\s*[^;+]+\+\s*1\b", text
    ):
        return (
            f"`{name}` adds 1 after division when computing the amount returned to the caller, "
            "which rounds that output in the caller's favor."
        )
    if re.search(r"\w+\s*/\s*\w+\s*\*\s*\w+", text) and re.search(
        r"\b(share|price|asset|collateral|debt)\b", text, re.I
    ):
        return (
            "This conversion divides before it multiplies, so integer truncation happens before "
            "the value is scaled and can favor whichever side receives the rounded result."
        )
    return ""


def _slippage_issue(name: str, text: str) -> str:
    lowered = name.lower()
    if not any(item in lowered for item in _EXCHANGES):
        return ""
    params = _parameter_types(text)
    bounds = [
        param
        for param in params
        if param.lower() in _BOUND_NAMES
        or param.lower().startswith("min")
        or param.lower().startswith("max")
    ]
    if not bounds:
        return ""
    body = _body(text)
    for param in bounds:
        if not re.search(rf"\b{re.escape(param)}\b", body):
            return (
                f"`{param}` is supplied to `{name}`, but the body never compares it with the "
                "value that is actually exchanged."
            )
        if _bound_is_only_nonzero(body, param):
            return (
                f"`{param}` is checked against zero in `{name}`, not against the computed output."
            )
        if _bound_after_credit(body, param):
            return (
                f"`{param}` is checked only after `{name}` has already written the accounting "
                "state the bound was meant to protect."
            )
    return ""


def _oracle_issue(text: str) -> str:
    if "latestRoundData" not in text and "latestAnswer" not in text:
        return ""
    if not re.search(r"\b(collateral|debt|shares|health|liquidat|ltv)\b", text, re.I):
        return ""
    answers = _oracle_answer_names(text)
    if not answers or not any(_name_in_arithmetic(text, name) for name in answers):
        return ""
    fresh = oracle_freshness_protects(text)
    positive = any(
        re.search(rf"\b{re.escape(name)}\b[^;\n]*(?:>|!=)\s*0", text) for name in answers
    ) or bool(re.search(r"\bprice\b[^;\n]*(?:>|!=)\s*0", text))
    scales = set(re.findall(r"1e\d+|10\s*\*\*\s*\d+", re.sub(r"\s+", "", text)))
    if fresh is not True:
        return (
            "An oracle answer is scaled into collateral, debt, or shares, and the freshness "
            "value is missing or comes from a different latestRoundData observation than the "
            "answer that is consumed."
        )
    if not positive:
        return (
            "The oracle answer flows into an asset valuation without a check that the price is "
            "positive, so a zero or negative answer can erase collateral or distort a health factor."
        )
    if len(scales) >= 2:
        joined = " and ".join(sorted(scales))
        return (
            f"The valuation mixes decimal scales {joined}, so the oracle answer and the asset "
            "amount are not normalized in the same units."
        )
    return ""


def _lending_issue(name: str, text: str) -> str:
    if not re.search(r"\b(collateral|debt|health|healthFactor|ltv|liquidat)\b", text, re.I):
        return ""
    if _debt_reduced(text) and not _asset_in(text):
        return (
            "Debt is reduced without a corresponding token or value transfer, so the liability "
            "can disappear without assets arriving."
        )
    if "liquidat" in name.lower():
        scales = set(re.findall(r"1e\d+", text))
        if len(scales) >= 2:
            return (
                "Liquidation math mixes decimal scales, so collateral and debt are not expressed "
                "in the same units."
            )
    if _stale_health(text):
        return (
            "The health factor is read before debt or collateral is updated, and the later check "
            "still uses that stale snapshot."
        )
    return ""


def _amm_issue(name: str, text: str) -> str:
    if not re.search(r"\b(reserve0|reserve1|reserves)\b", text):
        return ""
    if not re.search(r"\b(amountOut|amount0Out|amount1Out)\b", text):
        return ""
    if "/" not in text and "*" not in text:
        return ""
    compact = re.sub(r"\s+", "", text)
    live_balance = "balanceOf(address(this))" in compact
    reserve_from_balance = bool(re.search(r"\breserve\w*\s*=\s*[^;]*balanceOf", text))
    if live_balance and not reserve_from_balance:
        return (
            "Swap output uses the pool's live token balance while stored reserves stay separate, "
            "so a direct donation can move the price without a matching reserve update."
        )
    out_at = _first_index(text, ("amountOut", "amount0Out", "amount1Out"))
    writes = [match.start() for match in re.finditer(r"\b(reserve0|reserve1|reserves)\b\s*=", text)]
    moves_tokens = bool(re.search(r"\.transfer(?:From)?\s*\(", text))
    if moves_tokens and not writes:
        return (
            f"`{name}` prices `amountOut` from reserves and transfers tokens, but those reserves "
            "are not updated, so the recorded pool can diverge from the trade."
        )
    if moves_tokens and out_at >= 0 and writes and max(writes) < out_at:
        return (
            "Reserves are written before the output is computed, so the trade can be priced from "
            "a stale reserve snapshot."
        )
    amount1 = re.search(r"\bamount1\w*\s*=\s*([^;]+)", text)
    if (
        re.search(r"\bamount0\w*\s*=\s*[^;]*\bfee\w*\b", text)
        and amount1 is not None
        and "fee" not in amount1.group(1)
    ):
        return (
            "A swap fee is applied while computing amount0, but the amount1 update does not use "
            "that fee, so the two sides of the pair are not charged consistently."
        )
    return ""


def _approval_issue(name: str, original: str) -> str:
    text = _strip(original)
    lowered = name.lower()
    if lowered == "increaseallowance" and re.search(
        r"\ballowance\b\s*(?:\[[^\]]+\]){1,2}\s*=(?!=)", text
    ):
        if "+=" not in text:
            return (
                "`increaseAllowance` replaces the stored allowance with the requested amount "
                "instead of adding to the allowance that is already set."
            )
    permit_like = "permit" in lowered or ("ecrecover" in text and re.search(r"\ballowance\b", text))
    if not permit_like or "ecrecover" not in original:
        return ""
    params = _parameter_types(original)
    if "spender" in params and digest_contains(original, "spender") is False:
        if re.search(r"\ballowance\b", text):
            return (
                "The approval writes an allowance for `spender`, but that spender does not reach "
                "the ecrecover digest."
            )
    if (
        "token" in params
        and digest_contains(original, "token") is False
        and re.search(r"\btoken\b\s*\.\s*(approve|permit)|\ballowance\b\s*\[", text)
    ):
        return "The permit is applied to `token`, but the signed digest does not bind that token."
    gap = signature_replay_gap(original)
    if gap is not None and re.search(r"\bnonce\b", text):
        return (
            "The permit signature's nonce is not consumed on the verification path, so the same "
            "approval can be replayed. "
            + gap
            + " This is potential evidence, not a confirmed replay."
        )
    if (
        re.search(r"\b(DOMAIN_SEPARATOR|domainSeparator)\b", text)
        and digest_contains_any(original) is False
    ):
        return (
            "A domain separator is in scope, but the permit digest passed to ecrecover does not "
            "include it, so the signature is not bound to this token's domain."
        )
    return ""


def _callback_issue(graph: SyntaxGraph, function: SyntaxEvent, name: str) -> str:
    if _function_locked(graph, function):
        return ""
    span = function.span
    if span is None:
        return ""
    calls = [
        event
        for event in graph.events
        if event.kind == "sol_erc20"
        and event.span is not None
        and span.start_byte <= event.span.start_byte < span.end_byte
    ]
    writes = [
        event
        for event in graph.events
        if event.kind == "sol_state_write"
        and event.span is not None
        and span.start_byte <= event.span.start_byte < span.end_byte
        and _ACCOUNTING.search(_fields(event.extra).get("name", ""))
    ]
    for call in calls:
        assert call.span is not None
        for write in writes:
            assert write.span is not None
            if write.span.start_byte <= call.span.start_byte:
                continue
            variable = _fields(write.extra).get("name", "state")
            return (
                f"`{variable}` is updated after `{call.text[:80]}`. A token callback or a "
                "malicious ERC-20 can re-enter before that accounting write. This is potential "
                "evidence, not a confirmed reentrancy."
            )
    return ""


def _vault_issues(graph: SyntaxGraph) -> list[DefiIssue]:
    bodies = {
        _function_name(event): _strip(event.text)
        for event in _functions(graph)
        if _function_name(event)
    }
    found: list[DefiIssue] = []
    pairs = (
        ("previewDeposit", "deposit"),
        ("previewMint", "mint"),
        ("previewWithdraw", "withdraw"),
        ("previewRedeem", "redeem"),
    )
    for preview, live in pairs:
        if preview not in bodies or live not in bodies:
            continue
        preview_formula = _primary_formula(bodies[preview])
        live_formula = _primary_formula(bodies[live])
        if preview_formula and live_formula and preview_formula != live_formula:
            found.append(
                DefiIssue(
                    "sol.erc4626",
                    live,
                    f"`{preview}` and `{live}` do not use the same conversion, so a caller can "
                    "receive a different amount of assets or shares than the preview promised.",
                )
            )
    for action, noun in (
        ("deposit", "shares"),
        ("mint", "shares"),
        ("withdraw", "assets"),
        ("redeem", "assets"),
    ):
        body = bodies.get(action, "")
        if not body or "/" not in body:
            continue
        if _output_protected(body, noun):
            continue
        found.append(
            DefiIssue(
                "sol.erc4626",
                action,
                f"`{action}` divides assets and shares without requiring a non-zero {noun} result "
                f"or a caller-supplied minimum, so rounding can produce a zero {noun} transfer.",
            )
        )
    return found


def _contract_kinds(graph: SyntaxGraph) -> dict[str, str]:
    methods: dict[str, set[str]] = {}
    bases: dict[str, list[str]] = {}
    for event in graph.events:
        if event.kind == "sol_contract":
            fields = _fields(event.extra)
            bases[event.text.strip()] = [
                item.split("(")[0].strip()
                for item in fields.get("bases", "").split(",")
                if item.strip()
            ]
        elif event.kind == "sol_function":
            fields = _fields(event.extra)
            contract = fields.get("contract", "")
            methods.setdefault(contract, set()).add(fields.get("function", "").lower())
    kinds: dict[str, str] = {}
    for name in set(bases) | set(methods):
        lowered = name.lower()
        if lowered in _TOKEN_NAMES:
            kinds[name] = _TOKEN_NAMES[lowered]
        owned = {item.lower() for item in methods.get(name, set())}
        if {"transfer", "balanceof"} <= owned and owned & _ERC20_METHODS:
            kinds.setdefault(name, "erc20")
        if {"safetransferfrom", "balanceof"} <= owned and "ownerof" in owned:
            kinds.setdefault(name, "erc721")
    changed = True
    while changed:
        changed = False
        for name, parents in bases.items():
            for parent in parents:
                parent_name = re.sub(r"\(.*", "", parent).strip()
                kind = kinds.get(parent_name) or _TOKEN_NAMES.get(parent_name.lower(), "")
                if kind and kinds.get(name) != kind:
                    kinds[name] = kind
                    changed = True
    return kinds


def _contract_names(graph: SyntaxGraph) -> set[str]:
    return {event.text.strip() for event in graph.events if event.kind == "sol_contract"}


def _token_calls(
    text: str,
    function: str,
    types: dict[str, str],
    kinds: dict[str, str],
    known: set[str],
) -> list[TokenInteraction]:
    found: list[TokenInteraction] = []
    for match in re.finditer(rf"\b([A-Za-z_]\w*)\s*\.\s*({_METHODS})\s*\(", text):
        token = match.group(1)
        method = match.group(2)
        open_at = match.end() - 1
        try:
            close_at = _consume_parens(text, open_at)
        except ValueError:
            continue
        args = _split_args(text[open_at + 1 : close_at - 1])
        classification, confidence = _classify_call(
            token, method, len(args), types, kinds, known, text
        )
        sender, receiver, amount = _call_roles(method, args)
        found.append(
            TokenInteraction(
                classification,
                confidence,
                method,
                token,
                sender,
                receiver,
                amount,
                function,
                text[match.start() : close_at],
            )
        )
    return found


def _classify_call(
    token: str,
    method: str,
    arg_count: int,
    types: dict[str, str],
    kinds: dict[str, str],
    known: set[str],
    text: str,
) -> tuple[str, str]:
    if method == "transfer" and arg_count <= 1:
        return "native", "unknown"
    declared = _type_name(types.get(token, ""))
    named = kinds.get(declared) or _TOKEN_NAMES.get(declared.lower(), "")
    if named:
        return named, "strong"
    if declared and declared in known and declared not in kinds:
        return "unknown_external", "unknown"
    if declared.lower() in {"address", ""} and _used_as_token(token, text):
        if method in {
            "transfer",
            "transferFrom",
            "approve",
            "permit",
            "increaseAllowance",
            "decreaseAllowance",
        }:
            return "erc20", "usage"
    if method in {"transfer", "transferFrom", "safeTransfer", "safeTransferFrom"}:
        return "unknown_external", "unknown"
    return "unknown_external", "unknown"


def _used_as_token(token: str, text: str) -> bool:
    return bool(
        re.search(
            rf"\b{re.escape(token)}\s*\.\s*(balanceOf|totalSupply|transferFrom|approve|allowance)\s*\(",
            text,
        )
    )


def _call_roles(method: str, args: list[str]) -> tuple[str, str, str]:
    cleaned = [re.sub(r"\s+", "", arg) for arg in args]
    if method == "transferFrom" and len(cleaned) >= 3:
        return cleaned[0], cleaned[1], cleaned[2]
    if method in {"transfer", "safeTransfer"} and len(cleaned) >= 2:
        return "", cleaned[0], cleaned[1]
    if method == "approve" and len(cleaned) >= 2:
        return "", cleaned[0], cleaned[1]
    if method in {"increaseAllowance", "decreaseAllowance"} and len(cleaned) >= 2:
        return "", cleaned[0], cleaned[1]
    if cleaned:
        return "", "", cleaned[-1]
    return "", "", ""


def _transition(
    name: str, contract: str, text: str, calls: list[TokenInteraction]
) -> EconomicTransition | None:
    action = _action(name)
    user: list[str] = []
    protocol: list[str] = []
    if re.search(r"\bshares?\w*(?:\[[^\]]+\])?\s*\+=", text):
        user.append("shares:credit")
    if re.search(r"\bshares?\w*(?:\[[^\]]+\])?\s*-=", text):
        user.append("shares:debit")
    if re.search(r"\b(debt|debts|borrowed)\w*(?:\[[^\]]+\])?\s*\+=", text):
        user.append("debt:increase")
    if _debt_reduced(text):
        user.append("debt:decrease")
    if re.search(r"\bcollateral\w*(?:\[[^\]]+\])?\s*\+=", text):
        user.append("collateral:increase")
    if re.search(r"\bcollateral\w*(?:\[[^\]]+\])?\s*-=", text):
        user.append("collateral:decrease")
    if re.search(r"\ballowance\b[^;]*=", text):
        user.append("allowance:set")
    if re.search(r"\b(totalSupply|totalShares)\b[^;]*\+=", text):
        protocol.append("totalShares:increase")
    if "balanceOf(address(this))" in re.sub(r"\s+", "", text) or re.search(
        r"\btotalAssets\b", text
    ):
        protocol.append("totalAssets:referenced")
    if re.search(r"\breserve", text):
        protocol.append("reserves:referenced")
    flows = tuple(
        f"{call.classification}:{call.method}:{call.token}"
        for call in calls
        if call.method in {"transfer", "transferFrom", "approve", "permit"}
    )
    if action == "other" and not user and not protocol and not flows:
        return None
    return EconomicTransition(action, contract, name, tuple(user), tuple(protocol), flows)


def _action(name: str) -> str:
    lowered = name.lower()
    for item in (
        "addliquidity",
        "removeliquidity",
        "deposit",
        "withdraw",
        "mint",
        "redeem",
        "borrow",
        "repay",
        "liquidate",
        "swap",
        "permit",
    ):
        if item in lowered:
            return (
                "addLiquidity"
                if item == "addliquidity"
                else ("removeLiquidity" if item == "removeliquidity" else item)
            )
    return "other"


def _share_conversion(statement: str, expanded: str) -> bool:
    blob = re.sub(r"\s+", "", statement + expanded)
    vault = "balanceOf(address(this))" in blob
    supply = "totalSupply" in blob or "totalShares" in blob
    if vault and supply:
        return True
    return "totalAssets" in blob and supply and "balanceOf(address(this))" in blob


def _virtual_offset(statement: str, defs: dict[str, str]) -> bool:
    left, right = _slash_sides(statement)
    if not left or not right:
        return False
    return _has_offset(_expand(left, defs)) and _has_offset(_expand(right, defs))


def _has_offset(text: str) -> bool:
    return bool(re.search(r"\+\s*(1\b|10\b|1e\d+|virtual|offset)", text, re.I))


def _credits_requested(text: str, amount: str) -> bool:
    if not re.fullmatch(r"[A-Za-z_]\w*", amount):
        return False
    name = re.escape(amount)
    accounting = (
        r"(?:shares|share|balances|balance|deposits|deposit|collateral|staked|stake|"
        r"liquidity|received|credited|accounted|minted)"
    )
    return bool(
        re.search(
            rf"\b{accounting}\w*\b(?:\s*\[[^\]]+\])?\s*(?:\+=|=(?!=))\s*[^;]*\b{name}\b", text
        )
    )


def _credits_delta(text: str) -> bool:
    return bool(
        re.search(
            r"\b(?:received|credited|shares|share|balances|deposits|collateral)\w*\b"
            r"(?:\s*\[[^\]]+\])?\s*(?:\+=|=(?!=))\s*[^;]*\b\w+\s*-\s*\w+",
            text,
        )
    )


def _balance_reads(text: str, token: str) -> int:
    if token:
        return len(re.findall(rf"\b{re.escape(token)}\s*\.\s*balanceOf\s*\(", text))
    return text.count("balanceOf")


def _measures_delta(text: str, token: str) -> bool:
    if _balance_reads(text, token) < 2 and text.count("balanceOf") < 2:
        return False
    return bool(re.search(r"-\s*[A-Za-z_]|>=|<=", text))


def _debt_reduced(text: str) -> bool:
    return bool(
        re.search(r"\b(?:debt|debts|borrowed)\w*(?:\s*\[[^\]]+\])?\s*-=", text)
        or re.search(r"\b(?:debt|debts|borrowed)\w*(?:\s*\[[^\]]+\])?\s*=\s*0\b", text)
        or re.search(
            r"\b(?:debt|debts|borrowed)\w*(?:\s*\[[^\]]+\])?\s*=\s*\w+\s*-\s*",
            text,
        )
    )


def _asset_in(text: str) -> bool:
    return bool(
        re.search(r"\.transferFrom\s*\(", text)
        or re.search(r"\.transfer\s*\([^;\n]*,", text)
        or re.search(r"\.call\s*\{", text)
        or re.search(r"\.safeTransferFrom\s*\(", text)
    )


def _stale_health(text: str) -> bool:
    match = re.search(r"\b(hf|health|healthFactor)\b\s*=", text)
    if match is None:
        return False
    variable = match.group(1)
    write = re.search(
        r"\b(?:debt|collateral)\w*(?:\s*\[[^\]]+\])?\s*(?:\+=|-=|=(?!=))",
        text[match.end() :],
    )
    if write is None:
        return False
    rest = text[match.end() + write.end() :]
    require = re.search(rf"require\s*\([^;]*\b{re.escape(variable)}\b", rest)
    if require is None:
        return False
    between = rest[: require.start()]
    return re.search(rf"\b{re.escape(variable)}\b\s*=", between) is None


def _bound_is_only_nonzero(body: str, param: str) -> bool:
    comparisons = re.findall(
        rf"\b{re.escape(param)}\b\s*(?:<=|>=|<|>|==)\s*([^,)&]+)|"
        rf"([^,(&]+)\s*(?:<=|>=|<|>|==)\s*\b{re.escape(param)}\b",
        body,
    )
    if not comparisons:
        return False
    others = []
    for left, right in comparisons:
        side = (left or right).strip()
        if side and side not in {"0", "0x0"}:
            others.append(side)
    return not others


def _bound_after_credit(body: str, param: str) -> bool:
    require = re.search(rf"require\s*\([^;]*\b{re.escape(param)}\b", body)
    if require is None:
        return False
    write = re.search(
        r"\b(?:shares|balances|debt|collateral|reserve\w*)\w*(?:\s*\[[^\]]+\])?\s*(?:\+=|-=|=(?!=))",
        body,
    )
    if write is None:
        return False
    return write.start() < require.start()


def _output_protected(body: str, noun: str) -> bool:
    if re.search(rf"require\s*\([^;]*\b\w*{noun}\w*\b[^;]*(?:>=|>|!=)\s*0", body, re.I):
        return True
    if re.search(r"require\s*\([^;]*\b(?:min|max)[A-Za-z0-9_]*\b", body):
        return True
    return bool(
        re.search(
            r"require\s*\([^;]*\b\w*(?:shares|assets|out)\w*\b[^;]*\b(?:min|max)\w*\b",
            body,
            re.I,
        )
    )


def _oracle_answer_names(text: str) -> set[str]:
    names: set[str] = set()
    for match in re.finditer(r"\(([^)]*)\)\s*=\s*[^;]*latestRoundData\s*\(", text):
        parts = _split_args(match.group(1), keep_empty=True)
        if len(parts) > 1:
            idents = re.findall(r"[A-Za-z_]\w*", parts[1])
            if idents:
                names.add(idents[-1])
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*[^;]*\.latestAnswer\s*\(", text):
        names.add(match.group(1))
    return names


def _name_in_arithmetic(text: str, name: str) -> bool:
    return bool(re.search(rf"\b{re.escape(name)}\b[^;]*[*/]|[*/][^;]*\b{re.escape(name)}\b", text))


def _primary_formula(text: str) -> str:
    atom = r"(?:\([^()]+\)|[A-Za-z_]\w*|\d+)"
    term = rf"{atom}(?:\s*[\*\+\-]\s*{atom})*"
    match = re.search(rf"({term})\s*/\s*({term})", text)
    if match is None:
        return ""
    return re.sub(r"\s+", "", match.group(0))


def _simple_defs(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for statement in _statements(text):
        match = re.match(
            r"(?:u?int\d*|int\d*|address|bool|bytes\d*|uint|int)?\s*([A-Za-z_]\w*)\s*=(?!=)\s*([^;]+)",
            statement.strip(),
        )
        if match is None:
            continue
        name = match.group(1)
        if name in {"if", "require", "return", "for", "while"}:
            continue
        found[name] = match.group(2).strip()
    return found


def _expand(statement: str, defs: dict[str, str]) -> str:
    extra: list[str] = []
    for name, expr in defs.items():
        if re.search(rf"\b{re.escape(name)}\b", statement):
            extra.append(expr)
            for nested, nested_expr in defs.items():
                if re.search(rf"\b{re.escape(nested)}\b", expr):
                    extra.append(nested_expr)
    return statement + " " + " ".join(extra)


def _slash_sides(statement: str) -> tuple[str, str]:
    depth = 0
    for index, char in enumerate(statement):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "/" and depth == 0 and not statement.startswith("/=", index):
            return statement[:index], statement[index + 1 :]
    return "", ""


def _first_index(text: str, names: tuple[str, ...]) -> int:
    indexes = [text.find(name) for name in names if text.find(name) >= 0]
    return min(indexes) if indexes else -1


def _function_locked(graph: SyntaxGraph, function: SyntaxEvent) -> bool:
    contract = _fields(function.extra).get("contract", "")
    for name in _modifier_names(_fields(function.extra).get("modifiers", "")):
        resolution = resolve_modifier(graph, contract, name)
        if resolution.status == "resolved" and reentrancy_guard_holds(resolution.body):
            return True
    return False


def _variable_types(graph: SyntaxGraph, function: SyntaxEvent, contract: str) -> dict[str, str]:
    types = _parameter_types(function.text)
    for event in graph.events:
        if event.kind != "sol_state":
            continue
        fields = _fields(event.extra)
        if fields.get("contract") not in {"", contract}:
            continue
        name = fields.get("name", "")
        if name:
            types.setdefault(name, fields.get("type", ""))
    return types


def _parameter_types(function_text: str) -> dict[str, str]:
    match = re.search(r"\bfunction\b[^(]*\(", function_text)
    if match is None:
        return {}
    open_at = function_text.find("(", match.start())
    try:
        end = _consume_parens(function_text, open_at)
    except ValueError:
        return {}
    found: dict[str, str] = {}
    for part in _split_args(function_text[open_at + 1 : end - 1]):
        idents = re.findall(r"[A-Za-z_]\w*", part)
        if not idents:
            continue
        name = idents[-1]
        type_name = " ".join(idents[:-1])
        found[name] = type_name
    return found


def _type_name(annotation: str) -> str:
    compact = annotation.replace("payable", "").replace("memory", "").replace("calldata", "")
    match = re.search(r"[A-Za-z_]\w*", compact)
    return match.group(0) if match else ""


def _functions(graph: SyntaxGraph) -> list[SyntaxEvent]:
    return [event for event in graph.events if event.kind == "sol_function"]


def _function_name(event: SyntaxEvent) -> str:
    match = re.search(r"function\s+([A-Za-z_]\w*)", event.text)
    return match.group(1) if match else ""


def _modifier_names(modifiers: str) -> list[str]:
    names: list[str] = []
    for item in modifiers.split(","):
        token = re.split(r"[\(\s]", item.strip(), maxsplit=1)[0]
        if token:
            names.append(token)
    return names


def _body(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return text
    return text[start + 1 : end]


def _statements(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == ";" and depth == 0:
            parts.append(text[start:index])
            start = index + 1
        index += 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _split_args(text: str, *, keep_empty: bool = False) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
        index += 1
    tail = text[start:].strip()
    if tail or keep_empty:
        parts.append(tail)
    if keep_empty:
        return parts
    return [part for part in parts if part]


def _strip(text: str) -> str:
    chars: list[str] = []
    index = 0
    while index < len(text):
        skipped = _skip_string_or_comment(text, index)
        if skipped is not None:
            chars.append(" " * (skipped - index))
            index = skipped
            continue
        chars.append(text[index])
        index += 1
    return "".join(chars)


def _fields(extra: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in extra.split("|"):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    return fields
