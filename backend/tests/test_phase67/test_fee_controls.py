"""Synthetic fee-share controls. Labels stay in this file. The pipeline is not told the verdict."""

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


def _desk(
    *,
    proto_bps: int = 0,
    swap: bool = False,
    revert_report: bool = False,
    revert_supply: bool = False,
) -> str:
    """A local fee desk. It is not Yearn and it is not an upstream edit."""
    mint_perf = (
        "sharesOf[protoWho] += perfShares;" if swap else "sharesOf[feeRecipient] += perfShares;"
    )
    mint_proto = (
        "sharesOf[feeRecipient] += protocolShares;"
        if swap
        else "sharesOf[protoWho] += protocolShares;"
    )
    stop = 'if (feeBps != 999999) revert("stop");' if revert_report else ""
    supply_stop = 'if (supply != type(uint256).max) revert("unread");' if revert_supply else ""
    return (
        textwrap.dedent(
            f"""
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;
            {_ERC}
            contract Desk {{
                IERC20 public immutable token;
                uint256 public constant MAX_BPS = 10000;
                uint256 public feeBps;
                address public feeRecipient;
                uint256 public protoBps;
                address public protoRecipient;
                mapping(address => uint256) private sharesOf;
                uint256 public supply;
                uint256 public accounted;
                constructor(IERC20 token_) {{
                    token = token_;
                    feeBps = 1000;
                    feeRecipient = address(0xBEEF);
                    protoBps = {proto_bps};
                    protoRecipient = address(0xCAFE);
                }}
                function totalSupply() external view returns (uint256) {{
                    {supply_stop}
                    return supply;
                }}
                function balanceOf(address account) external view returns (uint256) {{
                    return sharesOf[account];
                }}
                function protocolFee() public view returns (uint256, address) {{
                    return (protoBps, protoRecipient);
                }}
                function _live() internal view returns (uint256) {{
                    return token.balanceOf(address(this));
                }}
                function report() external {{
                    {stop}
                    uint256 live = _live();
                    uint256 oldAssets = accounted;
                    uint256 profit = live > oldAssets ? live - oldAssets : 0;
                    uint256 shares = supply == 0
                        ? profit
                        : (oldAssets == 0 ? 0 : (profit * supply) / oldAssets);
                    uint256 totalFeeShares;
                    totalFeeShares = (shares * feeBps) / MAX_BPS;
                    (uint256 protocolFeeBps, address protoWho) = protocolFee();
                    uint256 protocolShares;
                    protocolShares = (totalFeeShares * protocolFeeBps) / MAX_BPS;
                    uint256 perfShares = totalFeeShares - protocolShares;
                    if (protocolShares != 0) {{ {mint_proto} }}
                    if (perfShares != 0) {{ {mint_perf} }}
                    uint256 locked = shares - totalFeeShares;
                    if (locked != 0) sharesOf[address(this)] += locked;
                    supply += shares;
                    accounted = live;
                }}
            }}
            """
        ).strip()
        + "\n"
    )


def _rows(source: str, templates: set[str] | None = None) -> list[dict[str, object]]:
    files = {"Desk.sol": source}
    model = build_research_model(files)
    found = [
        item for item in run_suite(model).candidates if item.detector == "accounting.fee_shares"
    ]
    assert len(found) == 1, [item.detector for item in run_suite(model).candidates]
    generated = generate(model, found, SequenceIdentity(campaign_id="phase67"), sources=files)
    executor = StatefulExecutor()
    rows: list[dict[str, object]] = []
    for sequence in generated.sequences:
        if templates is not None and sequence.template not in templates:
            continue
        bound = stamp_source_identity(sequence, files)
        spec = build_property(bound, model, found[0])
        observed = executor.execute(bound, model, files, spec=spec)
        compared = compare_judges(observed, bound, files) if spec.oracle.executable else {}
        rows.append(
            {
                "template": sequence.template,
                "outcome": observed.outcome,
                "reason": observed.reason,
                "oracle": spec.oracle.kind.value,
                "executable": spec.oracle.executable,
                "strong": observed.strong_candidate,
                "disposition": observed.applicability_disposition,
                "verified": observed.verified,
                "compared": compared,
                "complete": found[0].fact("fee_complete"),
            }
        )
    return rows


def _one(rows: list[dict[str, object]], template: str) -> dict[str, object]:
    matches = [row for row in rows if row["template"] == template]
    assert len(matches) == 1, (
        template,
        [(row["template"], row["outcome"], row["reason"]) for row in rows],
    )
    return matches[0]


def _agree(row: dict[str, object], expected: str) -> None:
    compared = row["compared"]
    assert isinstance(compared, dict)
    assert compared.get("supported") is True, compared
    assert compared.get("compiled") is True, compared
    python_class = verdict_class(str(compared["python_verdict"]))
    evm_class = verdict_class(str(compared["evm_verdict"]))
    production_class = verdict_class(str(compared["production_verdict"]))
    assert python_class == evm_class == production_class == expected, compared
    assert row["verified"] is False
    assert "theft" not in str(row["reason"]).lower()


def test_safe_performance_fee_with_zero_protocol_fee_holds() -> None:
    rows = _rows(_desk(proto_bps=0))
    assert _one(rows, "fee-no-change")["reason"]
    for template, needle in (
        ("fee-no-change", "profit 0"),
        ("fee-profit", "performance delta 100000000000000000 == 100000000000000000"),
        ("fee-rounding", "performance delta 1 == 1"),
        ("fee-dust", "profit 9"),
    ):
        row = _one(rows, template)
        assert row["outcome"] is Outcome.PROPERTY_HELD, row
        assert needle in str(row["reason"])
        assert "protocol delta 0 == 0" in str(row["reason"]) or template == "fee-dust"
        assert row["strong"] is False
        _agree(row, "held")
    assert "protocol delta 0 == 0" in str(_one(rows, "fee-profit")["reason"])
    assert "is not a fee" in str(_one(rows, "fee-profit")["reason"])


def test_safe_nonzero_protocol_fee_splits_the_performance_shares() -> None:
    rows = _rows(_desk(proto_bps=2000))
    profit = _one(rows, "fee-profit")
    assert profit["outcome"] is Outcome.PROPERTY_HELD, profit
    assert "performance delta 80000000000000000 == 80000000000000000" in str(profit["reason"])
    assert "protocol delta 20000000000000000 == 20000000000000000" in str(profit["reason"])
    _agree(profit, "held")
    rounding = _one(rows, "fee-rounding")
    assert rounding["outcome"] is Outcome.PROPERTY_HELD, rounding
    assert "performance delta 1 == 1" in str(rounding["reason"])
    assert "protocol delta 0 == 0" in str(rounding["reason"])
    _agree(rounding, "held")
    assert _one(rows, "fee-dust")["outcome"] is Outcome.PROPERTY_HELD
    assert _one(rows, "fee-no-change")["outcome"] is Outcome.PROPERTY_HELD


def test_a_swapped_fee_split_is_a_violation_and_not_theft() -> None:
    rows = _rows(_desk(proto_bps=2000, swap=True))
    profit = _one(rows, "fee-profit")
    assert profit["outcome"] is Outcome.PROPERTY_VIOLATED, profit
    assert profit["strong"] is True
    assert profit["disposition"] == "target_applicable"
    assert "!=" in str(profit["reason"])
    _agree(profit, "violated")
    rounding = _one(rows, "fee-rounding")
    assert rounding["outcome"] is Outcome.PROPERTY_VIOLATED, rounding
    _agree(rounding, "violated")
    # A zero mint has no recipient to swap. Those boundaries stay held.
    assert _one(rows, "fee-dust")["outcome"] is Outcome.PROPERTY_HELD
    assert _one(rows, "fee-no-change")["outcome"] is Outcome.PROPERTY_HELD


def test_a_reverting_report_and_an_unreadable_supply_are_not_verdicts() -> None:
    reverted = _one(_rows(_desk(revert_report=True), templates={"fee-profit"}), "fee-profit")
    assert reverted["outcome"] is Outcome.INCONCLUSIVE, reverted
    assert reverted["strong"] is False
    _agree(reverted, "not_evaluated")
    unread = _one(_rows(_desk(revert_supply=True), templates={"fee-profit"}), "fee-profit")
    assert unread["outcome"] is Outcome.INCONCLUSIVE, unread
    assert "not zero" in str(unread["reason"]) or "revert" in str(unread["reason"])
    _agree(unread, "not_evaluated")


def test_credit_report_revert_is_not_a_violation() -> None:
    source = (
        textwrap.dedent(
            f"""
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;
            {_ERC}
            contract Desk {{
                IERC20 public immutable token;
                uint256 public accounted;
                constructor(IERC20 token_) {{ token = token_; }}
                function _live() internal view returns (uint256) {{
                    return token.balanceOf(address(this));
                }}
                function report() external {{
                    if (accounted != type(uint256).max) revert("stop");
                    uint256 live = _live();
                    accounted = live;
                }}
            }}
            """
        ).strip()
        + "\n"
    )
    files = {"Desk.sol": source}
    model = build_research_model(files)
    found = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance"
    ]
    assert len(found) == 1
    assert found[0].fact("store_relation") == "equal"
    generated = generate(
        model, found, SequenceIdentity(campaign_id="phase67-credit"), sources=files
    )
    sequence = next(item for item in generated.sequences if item.template == "report")
    bound = stamp_source_identity(sequence, files)
    spec = build_property(bound, model, found[0])
    assert spec.oracle.kind.value == "credit_matches_reported"
    observed = StatefulExecutor().execute(bound, model, files, spec=spec)
    assert observed.outcome is Outcome.INCONCLUSIVE, observed.reason
    assert observed.strong_candidate is False
    compared = compare_judges(observed, bound, files)
    assert verdict_class(str(compared["python_verdict"])) == "not_evaluated"
    assert verdict_class(str(compared["evm_verdict"])) == "not_evaluated"
    assert verdict_class(str(compared["production_verdict"])) == "not_evaluated"
