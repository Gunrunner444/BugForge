"""Source-backed report sequences, judged by Forge. Labels stay in the test."""

from __future__ import annotations

import textwrap

from app.discovery.bounty.properties import build_property
from app.discovery.bounty.stateful import Outcome, StatefulExecutor
from app.discovery.bounty.vfcs import SequenceIdentity, generate, stamp_source_identity
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite
from tests.test_phase52.phase52_support import requires_forge

pytestmark = requires_forge

_ERC = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""


def _desk(report_body: str, *, extra: str = "", days: str = "") -> str:
    delay = f"uint256 public delay = {days};" if days else ""
    return (
        textwrap.dedent(
            f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Desk {{
            struct Store {{ address keeper; uint256 accounted; }}
            Store private data;
            IERC20 public immutable token;
            address public beneficiary;
            {delay}
            constructor(IERC20 token_) {{
                token = token_;
                data.keeper = msg.sender;
                beneficiary = address(0xBEEF);
            }}
            modifier onlyKeeper() {{ require(msg.sender == data.keeper, "!keeper"); _; }}
            function keeper() external view returns (address) {{ return data.keeper; }}
            function accounted() external view returns (uint256) {{ return data.accounted; }}
            function _live() internal view returns (uint256) {{
                return token.balanceOf(address(this));
            }}
            function report() external onlyKeeper {{
                uint256 live = _live();
                {report_body}
            }}
            {extra}
        }}
        """
        ).strip()
        + "\n"
    )


def _run(source: str) -> dict[str, object]:
    files = {"Desk.sol": source}
    model = build_research_model(files)
    found = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance"
    ]
    assert len(found) == 1, [item.detector for item in run_suite(model).candidates]
    generated = generate(model, found, SequenceIdentity(campaign_id="phase64"))
    executor = StatefulExecutor()
    rows = []
    for sequence in generated.sequences:
        bound = stamp_source_identity(sequence, files)
        spec = build_property(bound, model, found[0])
        observed = executor.execute(bound, model, files, spec=spec)
        rows.append(
            {
                "template": sequence.template,
                "outcome": observed.outcome,
                "reason": observed.reason,
                "code": observed.reason_code,
                "strong": observed.strong_candidate,
                "disposition": observed.applicability_disposition,
                "declaration": spec.declaration.value,
                "getter": spec.oracle.getter,
                "fixture": spec.oracle.token_fixture,
                "statement": sequence.property_under_test,
                "calls": tuple((call.role, call.actor, call.function) for call in sequence.calls),
            }
        )
    return {"candidate": found[0], "rows": rows}


def _by(rows: list[dict[str, object]], template: str) -> dict[str, object]:
    return next(row for row in rows if row["template"] == template)


def test_safe_report_holds_for_profit_loss_and_no_change() -> None:
    extra = "function skim(uint256 amount) external { token.transfer(msg.sender, amount); }"
    result = _run(_desk("data.accounted = live;", extra=extra))
    rows = result["rows"]
    assert isinstance(rows, list)
    for template in ("donate→report", "report", "donate→report→outflow→report"):
        row = _by(rows, template)
        assert row["outcome"] is Outcome.PROPERTY_HELD, row
        assert row["strong"] is False
        assert row["getter"] == "accounted()"
        assert row["fixture"] == "standard"
    unauthorized = _by(rows, "unauthorized-report")
    assert unauthorized["outcome"] is Outcome.PROPERTY_HELD
    assert "caller check" in str(unauthorized["statement"])
    assert unauthorized["strong"] is False


def test_ignored_loss_violates_only_the_loss_sequence() -> None:
    extra = "function skim(uint256 amount) external { token.transfer(msg.sender, amount); }"
    result = _run(_desk("if (live > data.accounted) { data.accounted = live; }", extra=extra))
    rows = result["rows"]
    assert isinstance(rows, list)
    assert _by(rows, "donate→report")["outcome"] is Outcome.PROPERTY_HELD
    assert _by(rows, "report")["outcome"] is Outcome.PROPERTY_HELD
    loss = _by(rows, "donate→report→outflow→report")
    assert loss["outcome"] is Outcome.PROPERTY_VIOLATED
    assert loss["strong"] is True
    assert loss["disposition"] == "target_applicable"
    assert _by(rows, "unauthorized-report")["outcome"] is Outcome.PROPERTY_HELD


def test_scaled_report_is_a_standard_token_candidate() -> None:
    result = _run(_desk("data.accounted = live * 2;"))
    row = _by(result["rows"], "donate→report")  # type: ignore[arg-type]
    assert row["outcome"] is Outcome.PROPERTY_VIOLATED
    assert row["strong"] is True
    assert row["disposition"] == "target_applicable"
    assert row["fixture"] == "standard"


def test_fee_paid_to_the_beneficiary_is_not_attacker_extraction() -> None:
    body = """
        uint256 fee = live / 10;
        if (fee != 0) token.transfer(beneficiary, fee);
        data.accounted = live - fee;
    """
    result = _run(_desk(body))
    row = _by(result["rows"], "donate→report")  # type: ignore[arg-type]
    assert row["outcome"] is Outcome.PROPERTY_HELD, row
    assert "theft" not in str(row["reason"]).lower()
    assert row["strong"] is False


def test_source_duration_is_the_warp_boundary_and_reconciliation_holds() -> None:
    extra = "function arm() external pure returns (uint256) { return 1 days; }"
    result = _run(_desk("data.accounted = live;", extra=extra))
    rows = result["rows"]
    assert isinstance(rows, list)
    warp = _by(rows, "donate→report→warp→report")
    assert warp["outcome"] is Outcome.PROPERTY_HELD, warp
    assert any(call[2] == "warp(uint256)" for call in warp["calls"])  # type: ignore[union-attr]
    assert result["candidate"].fact("unlock_seconds") == "86400"  # type: ignore[union-attr]
    assert "unlock formula" in str(warp["statement"])


def test_unreadable_role_is_not_a_held_property() -> None:
    # The getter still names the role field, so the source binds it, and then reverts.
    source = _desk("data.accounted = live;").replace(
        "function keeper() external view returns (address) { return data.keeper; }",
        "function keeper() external view returns (address) { if (data.keeper == address(0)) "
        "return address(0); revert(); }",
    )
    result = _run(source)
    row = _by(result["rows"], "donate→report")  # type: ignore[arg-type]
    assert row["outcome"] is Outcome.INCONCLUSIVE
    assert row["code"] == "role_unconfirmed"
    assert row["strong"] is False
    assert row["disposition"] == "not_applicable"
    assert "authorized caller" in str(row["reason"])


def test_a_stored_constant_is_not_a_report_candidate() -> None:
    source = _desk("data.accounted = live;").replace(
        "uint256 live = _live();\n                data.accounted = live;",
        "uint256 quoted = 1;\n                data.accounted = quoted;",
    )
    model = build_research_model({"Desk.sol": source})
    hits = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance"
    ]
    assert hits == []
