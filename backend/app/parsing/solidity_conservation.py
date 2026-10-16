"""Conservation hypotheses derived from a contract's own token custody.

These are not defect patterns. A contract that pulls a token from ``msg.sender``,
credits a per-account mapping for ``msg.sender``, and has another function that
reads that credit and pays the same token back to ``msg.sender`` has a value
conservation property that execution can judge: after depositing and withdrawing
its full credit, the caller must not hold more of the token than it started with,
even when another depositor's funds are in custody.

The candidate is emitted on safe and unsafe contracts alike. Only an executed
round trip distinguishes them, so emission alone carries no defect signal and the
confidence stays ``low``.
"""

from __future__ import annotations

import re

from app.parsing.solidity_research import (
    ResearchModel,
    RFunction,
    SemanticCandidate,
    cap,
    member_calls,
)

FAMILY = "conservation"
DETECTOR = "conservation.round_trip_value"
MAX_PAIRS_PER_CONTRACT = 4
_PULL = frozenset({"transferFrom", "safeTransferFrom"})
_PAY = frozenset({"transfer", "safeTransfer"})
_CAST = re.compile(r"^\s*\w+\s*\(\s*([\w.]+)\s*\)\s*$")


def _token_key(receiver: str) -> str:
    """``IERC20(asset)`` and ``asset`` name the same token."""
    text = receiver.strip()
    match = _CAST.match(text)
    return match.group(1) if match else text


def _mutating(function: RFunction) -> bool:
    return (
        function.has_body
        and function.exposed
        and function.kind == "function"
        and function.mutability not in {"view", "pure"}
    )


def _pulls_from_caller(function: RFunction) -> set[str]:
    tokens: set[str] = set()
    for call in member_calls(function.body):
        if call.name not in _PULL or len(call.arguments) < 3:
            continue
        if call.arguments[0].strip() != "msg.sender":
            continue
        if call.arguments[1].strip() not in {"address(this)", "this"}:
            continue
        tokens.add(_token_key(call.receiver))
    return tokens


def _pays_caller(function: RFunction) -> set[str]:
    tokens: set[str] = set()
    for call in member_calls(function.body):
        if call.name not in _PAY or len(call.arguments) < 2:
            continue
        if call.arguments[0].strip() != "msg.sender":
            continue
        tokens.add(_token_key(call.receiver))
    return tokens


def _credited_mappings(model: ResearchModel, contract: str, function: RFunction) -> set[str]:
    mappings = {
        name for name, kind in model.state_vars(contract).items() if kind.startswith("mapping")
    }
    found: set[str] = set()
    for match in re.finditer(r"\b(\w+)\s*\[\s*msg\.sender\s*\]\s*(?:\+=|=(?!=))", function.body):
        if match.group(1) in mappings:
            found.add(match.group(1))
    return found


def _reads_credit(function: RFunction, mapping: str) -> bool:
    return bool(re.search(rf"\b{re.escape(mapping)}\s*\[\s*msg\.sender\s*\]", function.body))


def analyze_conservation(model: ResearchModel) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    for name in sorted(model.contracts):
        contract = model.contracts[name]
        if contract.kind != "contract":
            continue
        functions = [item for item in model.functions_of(name) if _mutating(item)]
        pairs = 0
        for deposit in functions:
            tokens = _pulls_from_caller(deposit)
            if not tokens:
                continue
            for mapping in sorted(_credited_mappings(model, name, deposit)):
                for payout in functions:
                    if payout.signature == deposit.signature or pairs >= MAX_PAIRS_PER_CONTRACT:
                        continue
                    shared = sorted(tokens & _pays_caller(payout))
                    if not shared or not _reads_credit(payout, mapping):
                        continue
                    pairs += 1
                    token = shared[0]
                    found.append(
                        SemanticCandidate(
                            detector=DETECTOR,
                            family=FAMILY,
                            title="A deposit and full withdrawal must conserve the caller's value",
                            summary=(
                                f"{name}.{deposit.name} pulls `{token}` from msg.sender and "
                                f"credits `{mapping}[msg.sender]`; {payout.name} reads that "
                                f"credit and pays `{token}` to msg.sender. Hypothesis: a caller "
                                "that deposits and withdraws its credit ends with no more "
                                "tokens than it started with while another depositor's funds "
                                "are in custody. This is a property to test, not a suspected "
                                "defect."
                            ),
                            file=deposit.file,
                            line=deposit.line,
                            contract=name,
                            function=deposit.signature,
                            path=(deposit.identity, payout.identity),
                            facts=(
                                ("hypothesis_basis", "token_custody"),
                                ("credit_mapping", mapping),
                                ("payout_function", payout.signature),
                                ("token", token),
                            ),
                            observed=(
                                f"{deposit.name} pulls {token} from msg.sender into the contract",
                                f"{deposit.name} writes {mapping}[msg.sender]",
                                f"{payout.name} reads {mapping}[msg.sender] and pays {token} "
                                "to msg.sender",
                            ),
                            missing=(
                                "an executed round trip with another depositor's funds in custody",
                            ),
                            confidence="low",
                            impact_tags=("value_transfer", "custody", "vault_accounting"),
                        )
                    )
    return cap(found)
