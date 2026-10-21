"""Scenario identity, applicability strength, asset units, and judge guards. No Forge."""

from __future__ import annotations

import textwrap

import pytest

from app.discovery.bounty.engine_adapters import _judge
from app.discovery.bounty.findings import is_strong
from app.discovery.bounty.properties import (
    OracleKind,
    OracleObservation,
    OracleSpec,
    PropertyVerdict,
    _expected_fee_shares,
    evaluate,
)
from app.discovery.bounty.vfcs import SequenceIdentity, Vfcs, VfcsCall
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite
from tests.test_phase64.test_yearn_replay import _expect_scenarios

_ERC = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""


class _Seq:
    def __init__(self, template: str, sequence_id: str) -> None:
        self.template = template
        self.sequence_id = sequence_id


def _row(sequence_id: str, **overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "sequence_id": sequence_id,
        "outcome": "property_held",
        "oracle_kind": "credit_matches_reported",
        "reason": "credit 1 == holdings 1",
        "verified": False,
    }
    body.update(overrides)
    return body


def _src(body: str) -> str:
    return textwrap.dedent(body).strip() + "\n"


def test_duplicate_missing_and_unexpected_observations_are_rejected() -> None:
    sequences = [_Seq("report", "vf_a"), _Seq("donate→report", "vf_b")]
    expected = {
        "report": {"outcome": "property_held", "oracle_kind": "credit_matches_reported"},
        "donate→report": {
            "outcome": "property_held",
            "oracle_kind": "credit_matches_reported",
        },
    }
    _expect_scenarios(sequences, [_row("vf_a"), _row("vf_b")], expected)
    with pytest.raises(AssertionError, match="vf_a: 2 observations") as duplicate:
        _expect_scenarios(sequences, [_row("vf_a"), _row("vf_a")], expected)
    assert "missing observations" in str(duplicate.value)
    assert "vf_b" in str(duplicate.value)
    with pytest.raises(AssertionError, match="missing observations") as missing:
        _expect_scenarios(sequences, [_row("vf_a")], expected)
    assert "vf_b" in str(missing.value)
    with pytest.raises(AssertionError, match="unexpected observations") as extra:
        _expect_scenarios(sequences, [_row("vf_a"), _row("vf_b"), _row("vf_extra")], expected)
    assert "vf_extra" in str(extra.value)


def test_an_unlisted_template_and_an_inconclusive_scenario_fail() -> None:
    sequences = [_Seq("report", "vf_a"), _Seq("fee-profit", "vf_fee")]
    expected = {
        "report": {"outcome": "property_held", "oracle_kind": "credit_matches_reported"},
    }
    with pytest.raises(AssertionError, match="neither an expected scenario"):
        _expect_scenarios(sequences, [_row("vf_a"), _row("vf_fee")], expected)
    with pytest.raises(AssertionError, match="does not judge this scenario"):
        _expect_scenarios(
            [_Seq("report", "vf_a")],
            [_row("vf_a", outcome="inconclusive", reason="compile failed")],
            expected,
        )
    with pytest.raises(AssertionError, match="does not judge this scenario"):
        _expect_scenarios(
            [_Seq("report", "vf_a")],
            [_row("vf_a", outcome="compile_failed", reason="solc failed")],
            expected,
        )


def test_an_explicit_exclusion_is_accepted_and_cannot_hide_a_verdict() -> None:
    sequences = [_Seq("report", "vf_a"), _Seq("fee-unread", "vf_gap")]
    expected = {
        "report": {"outcome": "property_held", "oracle_kind": "credit_matches_reported"},
    }
    gap = _row(
        "vf_gap",
        outcome="sequence_executed_no_oracle",
        oracle_kind="none",
        reason="the fee configuration is not readable",
    )
    _expect_scenarios(
        sequences,
        [_row("vf_a"), gap],
        expected,
        excluded={"fee-unread": "not readable"},
    )
    hidden = _row("vf_gap", reason="the fee configuration is not readable")
    with pytest.raises(AssertionError, match="cannot hide a judged"):
        _expect_scenarios(
            sequences,
            [_row("vf_a"), hidden],
            expected,
            excluded={"fee-unread": "not readable"},
        )


def _record(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "outcome": "property_violated",
        "declaration": "property_under_test",
        "verdict": "property_violated",
        "oracle_kind": "credit_matches_reported",
        "identity_status": "bound",
        "stale": False,
        "token_fixture": "standard",
        "applicability": {"disposition": "target_applicable", "assumptions": []},
    }
    body.update(overrides)
    return body


def test_conflicting_applicability_cannot_promote_a_candidate() -> None:
    assert is_strong(_record()) is True
    assert is_strong(_record(token_fixture="")) is False
    assert is_strong(_record(token_fixture="unknown_fixture")) is False
    harness = {
        "disposition": "target_applicable",
        "assumptions": [
            {
                "name": "token_behavior",
                "value": "fee_on_transfer",
                "status": "confirmed",
                "evidence": "harness setting records token_behavior=fee_on_transfer",
                "material": True,
            }
        ],
    }
    assert is_strong(_record(applicability=harness, token_fixture="fee_on_transfer")) is False
    stale = _record(identity_status="identity_mismatch", stale=True)
    assert is_strong(stale) is False
    role = {
        "disposition": "target_applicable",
        "assumptions": [
            {
                "name": "privileged_actor",
                "value": "keeper()",
                "status": "confirmed",
                "evidence": "execution vf_one and property pr_one",
                "material": True,
            }
        ],
    }
    assert (
        is_strong(_record(applicability=role, sequence_id="vf_other", property_id="pr_one"))
        is False
    )
    conflict = {
        "disposition": "target_applicable",
        "assumptions": [
            {
                "name": "token_behavior",
                "value": "fee_on_transfer",
                "status": "contradicted",
                "evidence": "source evidence records token_behavior=standard",
                "material": True,
            }
        ],
    }
    assert is_strong(_record(applicability=conflict, token_fixture="fee_on_transfer")) is False


def _reports(source: str) -> list[object]:
    model = build_research_model({"Desk.sol": source})
    return [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance"
    ]


def test_a_public_counter_is_not_an_asset_amount_and_a_transfer_is() -> None:
    counter = _src(
        f"""
        pragma solidity ^0.8.20;
        {_ERC}
        contract Desk {{
            IERC20 public immutable token;
            uint256 public ticks;
            uint256 public accounted;
            constructor(IERC20 token_) {{ token = token_; }}
            function poke() external {{ ticks += 1; }}
            function _live() internal view returns (uint256) {{
                return token.balanceOf(address(this)) + ticks;
            }}
            function report() external {{
                uint256 live = _live();
                accounted = live;
            }}
        }}
        """
    )
    found = _reports(counter)
    assert len(found) == 1
    assert found[0].fact("reported_form") == "unproven_units"  # type: ignore[attr-defined]
    assert found[0].fact("external_getter") == "ticks()"  # type: ignore[attr-defined]
    assert found[0].fact("reported_form") != "idle_plus_getter"  # type: ignore[attr-defined]
    backed = _src(
        f"""
        pragma solidity ^0.8.20;
        {_ERC}
        contract Desk {{
            IERC20 public immutable token;
            uint256 public deployed;
            uint256 public accounted;
            constructor(IERC20 token_) {{ token = token_; }}
            function accrue(uint256 amount) external {{
                token.transferFrom(msg.sender, address(this), amount);
                deployed += amount;
            }}
            function _live() internal view returns (uint256) {{
                return token.balanceOf(address(this)) + deployed;
            }}
            function report() external {{
                uint256 live = _live();
                accounted = live;
            }}
        }}
        """
    )
    model = build_research_model({"Desk.sol": backed})
    assert "validated_profile" not in model.asset_unit_evidence
    sourced = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance"
    ]
    assert sourced[0].fact("reported_form") == "idle_plus_getter"
    assert sourced[0].fact("asset_units") == "source"
    assert sourced[0].fact("external_getter") == "deployed()"


def _credit_sequence() -> Vfcs:
    return Vfcs(
        sequence_id="vf_credit",
        template="report",
        origin="test",
        calls=(VfcsCall("Desk", "report()", "report", "attacker"),),
        property_under_test="stored total",
        derived_from="accounting.reported_balance@Desk.report()",
        identity=SequenceIdentity(campaign_id="phase67"),
    )


def test_credit_judges_reject_a_missing_read_and_a_reverting_probe() -> None:
    sequence = _credit_sequence()
    for kind in (OracleKind.CREDIT_LE_HOLDINGS, OracleKind.CREDIT_MATCHES_REPORTED):
        oracle = OracleSpec(
            kind=kind,
            probe_role="report",
            probe_function="report()",
            getter="accounted()",
            external_getter="deployed()",
        )
        missing = evaluate(
            sequence,
            oracle,
            OracleObservation((1,), readable=True, credit_after=5, holdings_after=1),
        )
        assert missing.verdict is PropertyVerdict.NOT_EVALUATED
        assert missing.evaluated is False
        assert "not zero" in missing.reason
        reverted = evaluate(
            sequence,
            oracle,
            OracleObservation(
                (0,), readable=True, credit_after=5, holdings_after=1, external_after=0
            ),
        )
        assert reverted.verdict is PropertyVerdict.NOT_EVALUATED
        assert "revert" in reverted.reason
        unread = evaluate(
            sequence,
            oracle,
            OracleObservation(
                (1,),
                readable=False,
                credit_after=5,
                holdings_after=1,
                external_after=0,
            ),
        )
        assert unread.verdict is PropertyVerdict.NOT_EVALUATED
        _judged, violated = _judge(sequence, oracle) or ("", "")
        assert "bfReadFailed" in violated
        assert "_bfOk" in violated
        assert "!bfSeen" in violated


def _fee_evidence(**overrides: int) -> tuple[tuple[str, int], ...]:
    body = {
        "fee_assets_before": 0,
        "fee_assets_after": 1_000_000_000_000_000_000,
        "fee_supply_before": 0,
        "fee_performance_bps": 1000,
        "fee_protocol_bps": 0,
        "fee_performance_before": 0,
        "fee_performance_after": 100_000_000_000_000_000,
        "fee_protocol_before": 0,
        "fee_protocol_after": 0,
        "fee_self_before": 0,
        "fee_self_after": 900_000_000_000_000_000,
    }
    body.update(overrides)
    return tuple(body.items())


def test_fee_share_math_and_missing_observations_stay_unjudged() -> None:
    assert _expected_fee_shares(0, 10**18, 0, 1000, 0, 10_000) == (10**17, 0, 10**18)
    assert _expected_fee_shares(0, 10**18, 0, 1000, 2000, 10_000) == (
        8 * 10**16,
        2 * 10**16,
        10**18,
    )
    assert _expected_fee_shares(0, 15, 0, 1000, 2000, 10_000) == (1, 0, 15)
    assert _expected_fee_shares(0, 9, 0, 1000, 0, 10_000) == (0, 0, 9)
    assert _expected_fee_shares(0, 0, 0, 1000, 2000, 10_000) == (0, 0, 0)
    sequence = Vfcs(
        sequence_id="vf_fee",
        template="fee-profit",
        origin="test",
        calls=(
            VfcsCall("token", "transfer(address,uint256)", "donation", "attacker", (), True, ""),
            VfcsCall("Desk", "report()", "report", "attacker"),
        ),
        property_under_test="fee shares",
        derived_from="accounting.fee_shares@Desk.report()",
        identity=SequenceIdentity(campaign_id="phase67"),
    )
    oracle = OracleSpec(
        kind=OracleKind.FEE_SHARES_MATCH,
        probe_role="report",
        probe_function="report()",
        precondition_roles=("donation",),
        share_getter="balanceOf(address)",
        max_bps=10_000,
    )
    held = evaluate(
        sequence,
        oracle,
        OracleObservation((1, 1), readable=True, evidence=_fee_evidence()),
    )
    assert held.verdict is PropertyVerdict.PROPERTY_HELD
    assert "is not a fee" in held.reason
    assert "theft" not in held.reason
    wrong = evaluate(
        sequence,
        oracle,
        OracleObservation(
            (1, 1),
            readable=True,
            evidence=_fee_evidence(fee_performance_after=0, fee_protocol_after=10**17),
        ),
    )
    assert wrong.verdict is PropertyVerdict.PROPERTY_VIOLATED
    assert "theft" not in wrong.reason
    missing = evaluate(
        sequence,
        oracle,
        OracleObservation((1, 1), readable=True, evidence=_fee_evidence()[:-1]),
    )
    assert missing.verdict is PropertyVerdict.NOT_EVALUATED
    assert "not zero" in missing.reason
    reverted = evaluate(
        sequence,
        oracle,
        OracleObservation((1, 0), readable=True, evidence=_fee_evidence()),
    )
    assert reverted.verdict is PropertyVerdict.NOT_EVALUATED
    _judged, violated = _judge(sequence, oracle) or ("", "")
    assert "bfReadFailed" in violated
    assert "_bfOk" in violated
    assert "_bfFeeShares" in violated


def test_a_fee_site_without_a_readable_configuration_is_not_executable() -> None:
    source = _src(
        f"""
        pragma solidity ^0.8.20;
        {_ERC}
        contract Desk {{
            IERC20 public immutable token;
            uint256 private feeBps;
            uint256 public constant MAX_BPS = 10000;
            address public feeRecipient;
            uint256 public supply;
            uint256 public accounted;
            mapping(address => uint256) private sharesOf;
            constructor(IERC20 token_) {{
                token = token_;
                feeBps = 1000;
                feeRecipient = address(0xBEEF);
            }}
            function totalSupply() external view returns (uint256) {{ return supply; }}
            function balanceOf(address account) external view returns (uint256) {{
                return sharesOf[account];
            }}
            function protocolFee() external view returns (uint256, address) {{
                return (0, address(0xCAFE));
            }}
            function report() external {{
                uint256 live = token.balanceOf(address(this));
                uint256 profit = live;
                uint256 shares = supply == 0 ? profit : profit;
                uint256 totalFeeShares;
                totalFeeShares = (shares * feeBps) / MAX_BPS;
                (uint256 protocolFeeBps, address protoWho) = protocolFee();
                uint256 protocolShares;
                protocolShares = (totalFeeShares * protocolFeeBps) / MAX_BPS;
                sharesOf[feeRecipient] += totalFeeShares - protocolShares;
                sharesOf[protoWho] += protocolShares;
                supply += shares;
                accounted = live;
            }}
        }}
        """
    )
    model = build_research_model({"Desk.sol": source})
    found = [
        item for item in run_suite(model).candidates if item.detector == "accounting.fee_shares"
    ]
    assert len(found) == 1
    assert found[0].fact("fee_complete") == "false"
    from app.discovery.bounty.properties import build_property
    from app.discovery.bounty.vfcs import generate

    generated = generate(model, found, SequenceIdentity(campaign_id="phase67"))
    assert [item.template for item in generated.sequences] == ["fee-no-change"]
    spec = build_property(generated.sequences[0], model, found[0])
    assert spec.oracle.executable is False
    flat = source.replace(
        "totalFeeShares = (shares * feeBps) / MAX_BPS;",
        "totalFeeShares = shares;",
    ).replace(
        "protocolShares = (totalFeeShares * protocolFeeBps) / MAX_BPS;",
        "protocolShares = 0;",
    )
    flat_model = build_research_model({"Desk.sol": flat})
    flat_found = [
        item
        for item in run_suite(flat_model).candidates
        if item.detector == "accounting.fee_shares"
    ]
    assert flat_found == []
