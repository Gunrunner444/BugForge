"""Deployed-asset profit and loss, judged by the ordinary generator. Labels stay here."""

from __future__ import annotations

import textwrap

from app.discovery.bounty.properties import build_property
from app.discovery.bounty.stateful import Outcome, StatefulExecutor
from app.discovery.bounty.vfcs import SequenceIdentity, generate, stamp_source_identity
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite
from tests.test_phase52.phase52_support import requires_forge
from tests.test_phase64.judge_diff import compare_judges, verdict_class

pytestmark = requires_forge

_ERC = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""


def _desk(body: str) -> str:
    return (
        textwrap.dedent(
            f"""
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;
            {_ERC}
            contract Desk {{
                IERC20 public immutable token;
                uint256 public deployed;
                uint256 public accounted;
                address public beneficiary;
                constructor(IERC20 token_) {{
                    token = token_;
                    beneficiary = address(0xBEEF);
                }}
                function _live() internal view returns (uint256) {{
                    return token.balanceOf(address(this)) + deployed;
                }}
                function report() external {{
                    uint256 live = _live();
                    {body}
                }}
                function accrue(uint256 amount) external {{
                    deployed += amount;
                }}
                function skim(uint256 amount) external {{
                    token.transfer(msg.sender, amount);
                }}
            }}
            """
        ).strip()
        + "\n"
    )


def _rows(source: str) -> list[dict[str, object]]:
    files = {"Desk.sol": source}
    model = build_research_model(files)
    found = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance"
    ]
    assert len(found) == 1
    assert found[0].fact("reported_form") == "idle_plus_getter"
    assert found[0].fact("external_getter") == "deployed()"
    generated = generate(model, found, SequenceIdentity(campaign_id="phase65"), sources=files)
    executor = StatefulExecutor()
    rows: list[dict[str, object]] = []
    for sequence in generated.sequences:
        bound = stamp_source_identity(sequence, files)
        spec = build_property(bound, model, found[0])
        observed = executor.execute(bound, model, files, spec=spec)
        compared = compare_judges(observed, bound, files)
        rows.append(
            {
                "template": sequence.template,
                "outcome": observed.outcome,
                "reason": observed.reason,
                "strong": observed.strong_candidate,
                "disposition": observed.applicability_disposition,
                "verified": observed.verified,
                "compared": compared,
                "candidate": found[0],
            }
        )
    return rows


def _one(rows: list[dict[str, object]], template: str) -> dict[str, object]:
    return next(row for row in rows if row["template"] == template)


def _agree(row: dict[str, object]) -> None:
    compared = row["compared"]
    assert isinstance(compared, dict)
    assert compared.get("supported") is True, compared
    assert compared.get("compiled") is True, compared
    python_class = verdict_class(str(compared["python_verdict"]))
    evm_class = verdict_class(str(compared["evm_verdict"]))
    production_class = verdict_class(str(compared["production_verdict"]))
    assert python_class == evm_class == production_class, compared


def test_safe_deployed_report_holds_for_profit_and_loss() -> None:
    rows = _rows(_desk("accounted = live;"))
    for template in ("donate→report", "report", "gain→report", "donate→report→outflow→report"):
        row = _one(rows, template)
        assert row["outcome"] is Outcome.PROPERTY_HELD, row
        assert row["strong"] is False
        assert row["verified"] is False
        _agree(row)
    gain = _one(rows, "gain→report")
    assert "deployed()" in str(gain["reason"])


def test_ignored_deployed_loss_is_judged_only_on_the_loss_sequence() -> None:
    rows = _rows(_desk("if (live > accounted) { accounted = live; }"))
    assert _one(rows, "donate→report")["outcome"] is Outcome.PROPERTY_HELD
    assert _one(rows, "gain→report")["outcome"] is Outcome.PROPERTY_HELD
    loss = _one(rows, "donate→report→outflow→report")
    assert loss["outcome"] is Outcome.PROPERTY_VIOLATED, loss
    assert loss["strong"] is True
    assert loss["disposition"] == "target_applicable"
    assert loss["verified"] is False
    _agree(loss)


def test_a_fee_paid_to_the_beneficiary_is_not_theft() -> None:
    body = """
        uint256 fee = live / 10;
        if (fee != 0) token.transfer(beneficiary, fee);
        accounted = live - fee;
    """
    row = _one(_rows(_desk(body)), "donate→report")
    assert row["outcome"] is Outcome.PROPERTY_HELD, row
    assert "theft" not in str(row["reason"]).lower()
    assert row["strong"] is False
    _agree(row)
