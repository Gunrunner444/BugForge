"""Highest-value bounty detectors (Phase 51, owner Phase 6).

Three static, evidence-based detectors that are not covered by the existing Phase 50
families:

* read-only reentrancy: a state-changing function makes an external call before it
  updates a state variable (a check-effects-interactions violation) and an exposed
  ``view`` reads that same variable without the writer's reentrancy guard, so the view
  can be observed mid-update;
* transient-storage misuse: a function writes EIP-1153 transient storage (``tstore`` or
  a ``transient`` variable) and never clears it, so a later call in the same transaction
  observes a stale value;
* EIP-7702 EOA assumption: a security gate assumes an address is a plain EOA
  (``msg.sender == tx.origin``, ``code.length == 0``, ``extcodesize == 0``,
  ``!isContract(...)``), which EIP-7702 makes unsound because an EOA can carry code.

Every result is a static candidate. It is evidence-based (the construct must actually be
present in a guard or a write), never a keyword hit, and never verification.
"""

from __future__ import annotations

import re

from app.parsing.solidity_research import (
    MAX_CANDIDATES_PER_FAMILY,
    ResearchModel,
    RFunction,
    SemanticCandidate,
    line_of_text,
    member_calls,
)

FAMILY = "high_value"

_STATE_WRITE = r"\b{name}\b\s*(?:\[[^\]]*\]\s*)*(?:=(?!=)|\+=|-=|\*=|/=)"
_REENTRANCY_GUARD = re.compile(r"nonReentrant|noReentrancy|reentrancyGuard", re.I)
_EXTERNAL_CALL_NAMES = frozenset({"call", "delegatecall", "send", "transfer"})

# EIP-7702 EOA assumptions, only when used inside a guard (require/if/assert).
_EOA_PATTERNS = (
    (
        re.compile(r"msg\.sender\s*==\s*tx\.origin|tx\.origin\s*==\s*msg\.sender"),
        "msg.sender == tx.origin",
    ),
    (re.compile(r"\.code\.length\s*==\s*0|\.code\.length\s*<\s*1"), "address.code.length == 0"),
    (re.compile(r"extcodesize\s*\([^)]*\)\s*==\s*0"), "extcodesize(a) == 0"),
    (re.compile(r"!\s*isContract\s*\("), "!isContract(a)"),
)
_GUARD_CONTEXT = re.compile(r"\b(require|assert|if)\s*\(")

# EIP-1153 transient storage writes.
_TSTORE = re.compile(r"\btstore\s*\(\s*([^,]+),")
_TLOAD = re.compile(r"\btload\s*\(")
_TRANSIENT_DECL = re.compile(r"\btransient\b[^;=]*\b(\w+)\s*(?:=|;)")


def analyze_high_value(model: ResearchModel) -> list[SemanticCandidate]:
    out: list[SemanticCandidate] = []
    out.extend(_read_only_reentrancy(model))
    out.extend(_transient_misuse(model))
    out.extend(_eip7702_assumptions(model))
    return out[:MAX_CANDIDATES_PER_FAMILY]


# ---- read-only reentrancy -------------------------------------------------------------------


def _read_only_reentrancy(model: ResearchModel) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    for name in sorted(model.contracts):
        state = set(model.state_vars(name))
        if not state:
            continue
        functions = [f for f in model.functions_of(name) if f.has_body]
        # variables written after an external call in a reentrancy-prone function
        prone: dict[str, RFunction] = {}
        for function in functions:
            if function.mutability in {"view", "pure"}:
                continue
            for var in _written_after_external_call(function, state):
                prone.setdefault(var, function)
        if not prone:
            continue
        for function in functions:
            if function.mutability != "view" or not function.exposed:
                continue
            if _has_guard(function):
                continue
            read = _reads_vars(function, set(prone))
            for var in sorted(read):
                writer = prone[var]
                if _has_guard(writer):
                    # the writer is guarded; the classic read-only-reentrancy shape needs an
                    # unguarded view over a variable the guard protects, so still report it
                    pass
                found.append(
                    SemanticCandidate(
                        detector="read_only_reentrancy.view_observes_mid_update",
                        family=FAMILY,
                        title="read-only reentrancy exposure",
                        summary=(
                            f"view {function.name} reads {var}, which {writer.name} updates after "
                            "an external call; the value can be observed mid-update"
                        ),
                        file=function.file,
                        line=function.line,
                        contract=name,
                        function=function.signature,
                        facts=(
                            ("state_variable", var),
                            ("writer", writer.signature),
                            ("writer_guarded", str(_has_guard(writer)).lower()),
                        ),
                        observed=("external_call_before_state_write", "unguarded_view_read"),
                        missing=("confirm the view is consumed by an external integrator",),
                        confidence="low",
                        impact_tags=("read_only_reentrancy",),
                    )
                )
                if len(found) >= MAX_CANDIDATES_PER_FAMILY:
                    return found
    return found


def _written_after_external_call(function: RFunction, state: set[str]) -> set[str]:
    calls = member_calls(function.body)
    call_offsets = [
        call.start for call in calls if "value" in call.options or call.name in _EXTERNAL_CALL_NAMES
    ]
    if not call_offsets:
        return set()
    first_call = min(call_offsets)
    tail = function.body[first_call:]
    written: set[str] = set()
    for var in state:
        if re.search(_STATE_WRITE.format(name=re.escape(var)), tail):
            written.add(var)
    return written


def _reads_vars(function: RFunction, variables: set[str]) -> set[str]:
    read: set[str] = set()
    for var in variables:
        # read = appears but not (only) as a write target
        if re.search(rf"\b{re.escape(var)}\b", function.body):
            read.add(var)
    return read


def _has_guard(function: RFunction) -> bool:
    return any(_REENTRANCY_GUARD.search(mod) for mod in function.modifiers)


# ---- transient-storage misuse ---------------------------------------------------------------


def _transient_misuse(model: ResearchModel) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    for name in sorted(model.contracts):
        contract = model.contracts[name]
        transient_vars = set(_TRANSIENT_DECL.findall(contract.body))
        for function in model.functions_of(name, inherited=False):
            if not function.has_body:
                continue
            writes = _TSTORE.findall(function.body)
            slot_writes = {slot.strip() for slot in writes}
            cleared = {
                slot.strip()
                for slot in re.findall(r"\btstore\s*\(\s*([^,]+),\s*0\s*\)", function.body)
            }
            uncleared = slot_writes - cleared
            transient_assigned = {
                var
                for var in transient_vars
                if re.search(rf"\b{re.escape(var)}\b\s*=(?!=)", function.body)
                and not re.search(rf"\bdelete\s+{re.escape(var)}\b", function.body)
                and f"{var} = 0" not in function.body
            }
            if not uncleared and not transient_assigned:
                continue
            detail = []
            if uncleared:
                detail.append(f"tstore slots {sorted(uncleared)} are not cleared")
            if transient_assigned:
                detail.append(f"transient vars {sorted(transient_assigned)} are not cleared")
            found.append(
                SemanticCandidate(
                    detector="transient_storage.not_cleared",
                    family=FAMILY,
                    title="transient storage left set",
                    summary=(
                        f"{function.name} writes transient storage without clearing it; "
                        + "; ".join(detail)
                        + "; a later call in the same transaction may read a stale value"
                    ),
                    file=function.file,
                    line=line_of_text(function, "tstore") if uncleared else function.line,
                    contract=name,
                    function=function.signature,
                    facts=(
                        ("uncleared_slots", ",".join(sorted(uncleared))),
                        ("uncleared_vars", ",".join(sorted(transient_assigned))),
                    ),
                    observed=("transient_write_without_clear",),
                    missing=("confirm no later clear on every path",),
                    confidence="low",
                    impact_tags=("transient_storage",),
                )
            )
            if len(found) >= MAX_CANDIDATES_PER_FAMILY:
                return found
    return found


# ---- EIP-7702 EOA assumptions ---------------------------------------------------------------


def _eip7702_assumptions(model: ResearchModel) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    for name in sorted(model.contracts):
        for function in model.functions_of(name, inherited=False):
            if not function.has_body:
                continue
            for pattern, label in _EOA_PATTERNS:
                match = pattern.search(function.body)
                if match is None:
                    continue
                if not _within_guard(function.body, match.start()):
                    continue
                found.append(
                    SemanticCandidate(
                        detector="eip7702.eoa_assumption",
                        family=FAMILY,
                        title="EIP-7702 unsafe EOA assumption",
                        summary=(
                            f"{function.name} gates on '{label}', which EIP-7702 makes unsound "
                            "because an externally owned account can carry code"
                        ),
                        file=function.file,
                        line=line_of_text(function, match.group(0).split("(")[0]),
                        contract=name,
                        function=function.signature,
                        facts=(("assumption", label),),
                        observed=("eoa_assumption_in_guard",),
                        missing=("confirm the gate is a security boundary post-7702",),
                        confidence="low",
                        impact_tags=("eip7702", "access_control"),
                    )
                )
                break
            if len(found) >= MAX_CANDIDATES_PER_FAMILY:
                return found
    return found


def _within_guard(body: str, index: int) -> bool:
    window = body[max(0, index - 80) : index]
    return bool(_GUARD_CONTEXT.search(window))
