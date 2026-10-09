"""V3 corrections for ``caller_context.swallowed_call_failure``.

1. Gas-guard sufficiency: NO_GUARD / GUARD_PRESENT_BUT_INSUFFICIENT_OR_UNPROVEN /
   GUARD_PROVEN_SUFFICIENT under a bounded source-text model (stipend, EIP-150 63/64,
   fixed CALL overhead). Only a proven guard removes a call site.
2. Empty-calldata value calls are analysed, not exempt; ambiguity is labelled.

Static candidates only; nothing here runs a tool or touches a network.
"""

from __future__ import annotations

from app.parsing.solidity_call_outcome import (
    CALL_OVERHEAD,
    DETECTOR,
    GUARD_PROVEN,
    GUARD_UNPROVEN,
    NO_GUARD,
    gas_guard,
)
from app.parsing.solidity_research import SemanticCandidate
from tests.test_phase50.phase50_support import analyze_text

HEAD = "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n"
SW = '\n    if (!ok) emit Bad("");'


def _fn(body: str, extra: str = "") -> str:
    return HEAD + (
        "contract C {\n  uint256 limit;\n  event Ok(bytes r);\n  event Bad(bytes r);\n"
        f"  error E();\n{extra}"
        "  function run(address target, bytes calldata data, uint256 amount) external {\n"
        f"{body}\n  }}\n}}\n"
    )


def _found(text: str) -> list[SemanticCandidate]:
    result = analyze_text(text, ("caller_context",))
    return [c for c in result.candidates if c.detector == DETECTOR]


def _one(text: str) -> dict[str, str]:
    found = _found(text)
    assert len(found) == 1, found
    item = found[0]
    assert item.status == "candidate" and item.verified is False and item.confidence == "low"
    return dict(item.facts)


def _guard(body: str, options: str = "gas: limit") -> str:
    return gas_guard(body, body.index("target.call"), options).status


# ---- 1. gas-guard sufficiency -------------------------------------------------------------------


def test_guard_equal_to_the_stipend_is_not_proven() -> None:
    body = "    require(gasleft() >= limit);\n    (bool ok, ) = target.call{gas: limit}(data);" + SW
    facts = _one(_fn(body))
    assert facts["gas_guard"] == GUARD_UNPROVEN
    assert "EIP-150" in facts["gas_guard_reason"]
    assert "fixed stipend of `limit`" in facts["gas_forwarded"]
    assert "all remaining gas" not in facts["gas_forwarded"]


def test_guard_with_insufficient_overhead_is_not_proven() -> None:
    body = (
        "    if (gasleft() < limit + limit / 63 + 100) revert E();\n"
        "    (bool ok, ) = target.call{gas: limit}(data);" + SW
    )
    facts = _one(_fn(body))
    assert facts["gas_guard"] == GUARD_UNPROVEN
    assert f"at least {CALL_OVERHEAD}" in facts["gas_guard_reason"]


def test_guard_accounting_for_stipend_and_eip150_is_proven() -> None:
    body = (
        "    if (gasleft() < limit + limit / 63 + 7000) revert E();\n"
        "    (bool ok, ) = target.call{gas: limit}(data);" + SW
    )
    assert _found(_fn(body)) == []
    assert _guard(body) == GUARD_PROVEN
    note = gas_guard(body, body.index("target.call"), "gas: limit").note
    assert "only under the bounded source-text gas model" in note
    assert "not a runtime safety proof" in note


def test_literal_stipend_folds_numerically() -> None:
    ok = "    require(gasleft() >= 210000);\n    (bool ok, ) = target.call{gas: 200000}(data);" + SW
    low = (
        "    require(gasleft() >= 203000);\n    (bool ok, ) = target.call{gas: 200000}(data);" + SW
    )
    assert _guard(ok, "gas: 200000") == GUARD_PROVEN
    assert _guard(low, "gas: 200000") == GUARD_UNPROVEN


def test_guard_through_a_local_and_named_constant_is_proven() -> None:
    extra = "  uint256 private constant GAS_OVERHEAD = 7000;\n"
    body = (
        "    uint256 required = limit + limit / 63 + GAS_OVERHEAD;\n"
        "    if (gasleft() < required) revert E();\n"
        "    (bool ok, ) = target.call{gas: limit}(data);" + SW
    )
    assert _found(_fn(body, extra)) == []


def test_unresolved_named_overhead_is_unproven() -> None:
    body = (
        "    uint256 required = limit + limit / 63 + amount;\n"
        "    if (gasleft() < required) revert E();\n"
        "    (bool ok, ) = target.call{gas: limit}(data);" + SW
    )
    facts = _one(_fn(body))
    assert facts["gas_guard"] == GUARD_UNPROVEN
    assert "cannot be evaluated" in facts["gas_guard_reason"]


def test_guard_that_protects_another_call_does_not_bound_this_one() -> None:
    body = (
        "    if (amount > 0) {\n      if (gasleft() < limit + limit / 63 + 7000) revert E();\n"
        "      (bool a, ) = target.call{gas: limit}(data);\n      if (!a) revert E();\n    }\n"
        "    (bool ok, ) = target.call{gas: limit}(data);" + SW
    )
    found = _found(_fn(body))
    assert len(found) == 1
    facts = dict(found[0].facts)
    assert facts["gas_guard"] == NO_GUARD
    assert "does not protect this call" in facts["gas_guard_reason"]


def test_required_amount_reassigned_before_use_is_unproven() -> None:
    body = (
        "    uint256 required = limit + limit / 63 + 7000;\n    required = 1;\n"
        "    if (gasleft() < required) revert E();\n"
        "    (bool ok, ) = target.call{gas: limit}(data);" + SW
    )
    facts = _one(_fn(body))
    assert facts["gas_guard"] == GUARD_UNPROVEN
    assert "assigned 2 times" in facts["gas_guard_reason"]


def test_stipend_reassigned_between_check_and_call_is_unproven() -> None:
    body = (
        "    uint256 g = limit;\n    if (gasleft() < g + g / 63 + 7000) revert E();\n"
        "    g = g * 2;\n    (bool ok, ) = target.call{gas: g}(data);" + SW
    )
    facts = _one(_fn(body))
    assert facts["gas_guard"] == GUARD_UNPROVEN
    assert "reassigned between the check and the call" in facts["gas_guard_reason"]


def test_unbounded_fallback_path_is_reported() -> None:
    body = (
        "    bool ok;\n    if (limit > 0) {\n"
        "      if (gasleft() < limit + limit / 63 + 7000) revert E();\n"
        "      (ok, ) = target.call{gas: limit}(data);\n"
        "    } else {\n      (ok, ) = target.call(data);\n    }" + SW
    )
    facts = _one(_fn(body))
    assert facts["gas_guard"] == NO_GUARD
    assert facts["bounded_call_paths"] == "1"
    assert "all remaining gas" in facts["gas_forwarded"]


def test_guard_whose_adequacy_cannot_be_established_is_kept_and_disclosed() -> None:
    body = (
        "    if (gasleft() < limit * 2 - 5) revert E();\n"
        "    (bool ok, ) = target.call{gas: limit}(data);" + SW
    )
    facts = _one(_fn(body))
    assert facts["gas_guard"] == GUARD_UNPROVEN
    assert facts["gas_guard_reason"].startswith("unproven")
    assert "bounded gas model" in facts["analysis"]


# ---- 2. empty-calldata value calls --------------------------------------------------------------


def test_nonzero_literal_transfer_with_ignored_failure_is_a_candidate() -> None:
    facts = _one(_fn('    (bool ok, ) = target.call{value: 1 ether}("");\n    ok;'))
    assert facts["call_kind"] == "eth_transfer_literal"
    assert "best-effort" in facts["intent"]


def test_variable_value_transfer_may_be_zero_and_is_labelled() -> None:
    facts = _one(_fn('    (bool ok, ) = target.call{value: amount}("");\n    ok;'))
    assert facts["call_kind"] == "eth_transfer_variable"
    assert "cannot tell whether it is zero at runtime" in facts["calldata"]


def test_explicit_zero_value_call_runs_receive_or_fallback() -> None:
    facts = _one(_fn('    (bool ok, ) = target.call{value: 0}("");\n    ok;'))
    assert facts["call_kind"] == "empty_no_value"
    assert "intent" not in facts


def test_empty_calldata_without_value_is_a_candidate() -> None:
    assert _one(_fn('    (bool ok, ) = target.call("");' + SW))["call_kind"] == "empty_no_value"


def test_empty_calldata_with_fixed_gas_stipend_is_a_candidate() -> None:
    facts = _one(_fn('    (bool ok, ) = target.call{gas: 2300}("");' + SW))
    assert facts["call_kind"] == "empty_no_value"
    assert facts["gas_guard"] == NO_GUARD
    assert "fixed stipend of `2300`" in facts["gas_forwarded"]


def test_value_transfer_whose_failure_reverts_is_not_a_candidate() -> None:
    body = '    (bool ok, ) = target.call{value: amount}("");\n    if (!ok) revert E();'
    assert _found(_fn(body)) == []


def test_deliberate_best_effort_transfer_stays_low_confidence_and_explained() -> None:
    body = (
        "    // refund is best-effort by design\n"
        '    (bool ok, ) = payable(msg.sender).call{value: amount, gas: 2300}("");\n    ok;'
    )
    found = _found(_fn(body))
    assert len(found) == 1
    item = found[0]
    facts = dict(item.facts)
    assert item.confidence == "low" and item.verified is False
    assert item.title.startswith("Ether transfer failure may be ignored")
    assert "possible false positive" in facts["intent"]
    assert "possible false positive" in item.summary
