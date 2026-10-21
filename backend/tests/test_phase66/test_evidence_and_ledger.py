"""Fail-closed strength and the stored-total equality oracle. No Forge."""

from __future__ import annotations

import textwrap

from app.discovery.bounty.applicability import (
    apply_execution_applicability,
    assess,
    confirm_validated_role,
)
from app.discovery.bounty.findings import is_strong
from app.discovery.bounty.properties import (
    OracleKind,
    OracleObservation,
    OracleSpec,
    PropertyVerdict,
    evaluate,
)
from app.discovery.bounty.vfcs import SequenceIdentity, Vfcs, VfcsCall
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite

_ERC = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""


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


def _strip(record: dict[str, object]) -> dict[str, object]:
    record.pop("applicability", None)
    return record


def test_an_empty_fixture_without_applicability_is_not_strong() -> None:
    assert is_strong(_strip(_record(token_fixture=""))) is False
    missing = _strip(_record())
    del missing["token_fixture"]
    assert is_strong(missing) is False
    assert is_strong(_strip(_record(token_fixture="standard"))) is True
    assert is_strong(_strip(_record(token_fixture="standard_erc20"))) is True
    assert is_strong(_strip(_record(token_fixture="standrd"))) is False
    assert is_strong(_strip(_record(token_fixture="fee_on_transfer"))) is False


def test_a_role_proof_is_bound_to_one_execution() -> None:
    facts = {"role_getter": "keeper()"}
    first = assess(token_fixture="standard", facts=facts)
    second = assess(token_fixture="standard", facts=facts)
    proven = apply_execution_applicability(
        first,
        identity_status="bound",
        reason_code="property_violated",
        role_proven=True,
        role_denied=False,
        execution_id="vf_one",
        property_id="pr_one",
    )
    denied = apply_execution_applicability(
        second,
        identity_status="bound",
        reason_code="role_unconfirmed",
        role_proven=False,
        role_denied=True,
        execution_id="vf_two",
        property_id="pr_two",
    )
    assert first.disposition == "unconfirmed"
    assert proven.disposition == "target_applicable"
    assert denied.disposition == "not_applicable"
    role = next(item for item in proven.assumptions if item.name == "privileged_actor")
    assert "vf_one" in role.evidence
    assert "pr_one" in role.evidence
    assert is_strong(_record(applicability=proven.as_dict())) is True
    assert is_strong(_record(applicability=denied.as_dict())) is False
    stale = apply_execution_applicability(
        proven,
        identity_status="identity_mismatch",
        reason_code="property_violated",
        role_proven=True,
        role_denied=False,
        execution_id="vf_one",
        property_id="pr_one",
    )
    assert stale.disposition == "not_applicable"
    assert (
        is_strong(
            _record(applicability=stale.as_dict(), identity_status="identity_mismatch", stale=True)
        )
        is False
    )
    other = confirm_validated_role(second, execution_id="vf_other", property_id="pr_other")
    other_role = next(item for item in other.assumptions if item.name == "privileged_actor")
    assert "vf_other" in other_role.evidence
    assert role.evidence != other_role.evidence


def test_host_and_fixture_gaps_stay_visible_and_not_strong() -> None:
    unknown_host = assess(
        token_fixture="standard",
        facts={"report_scope": "host", "reporting_host": "IdleHost"},
    )
    assert unknown_host.disposition == "unconfirmed"
    assert is_strong(_record(applicability=unknown_host.as_dict())) is False
    fixture_only = assess(
        token_fixture="fee_on_transfer",
        facts={"token_behavior": "standard", "token_behavior_evidence": "source"},
    )
    assert fixture_only.disposition == "fixture_only"
    visible = _record(
        applicability=fixture_only.as_dict(),
        token_fixture="fee_on_transfer",
        outcome="property_violated",
        verdict="property_violated",
    )
    assert visible["outcome"] == "property_violated"
    assert is_strong(visible) is False
    harness = assess(
        token_fixture="fee_on_transfer",
        facts={"token_behavior": "fee_on_transfer", "token_behavior_evidence": "harness"},
    )
    assert harness.disposition == "unconfirmed"


def test_equality_is_not_the_upper_bound_and_a_missing_addend_is_not_zero() -> None:
    sequence = Vfcs(
        sequence_id="vf_eq",
        template="report",
        origin="test",
        calls=(VfcsCall("Desk", "report()", "report", "deployer"),),
        property_under_test="stored total equals the reported amount",
        derived_from="accounting.reported_balance@Desk.report()",
        identity=SequenceIdentity(campaign_id="phase66"),
    )
    equal = OracleSpec(
        kind=OracleKind.CREDIT_MATCHES_REPORTED,
        probe_role="report",
        probe_function="report()",
        external_getter="deployed()",
    )
    upper = OracleSpec(
        kind=OracleKind.CREDIT_LE_HOLDINGS,
        probe_role="report",
        probe_function="report()",
        external_getter="deployed()",
    )
    missing = OracleObservation(call_ok=(1,), readable=True, credit_after=5, holdings_after=1)
    missed = evaluate(sequence, equal, missing)
    assert missed.verdict is PropertyVerdict.NOT_EVALUATED
    assert "not zero" in missed.reason
    observed = OracleObservation(
        call_ok=(1,), readable=True, credit_after=5, holdings_after=1, external_after=4
    )
    assert evaluate(sequence, equal, observed).verdict is PropertyVerdict.PROPERTY_HELD
    short = OracleObservation(
        call_ok=(1,), readable=True, credit_after=4, holdings_after=1, external_after=4
    )
    low = evaluate(sequence, equal, short)
    assert low.verdict is PropertyVerdict.PROPERTY_VIOLATED
    assert evaluate(sequence, upper, short).verdict is PropertyVerdict.PROPERTY_HELD
    zero = OracleObservation(
        call_ok=(1,), readable=True, credit_after=0, holdings_after=0, external_after=0
    )
    assert evaluate(sequence, equal, zero).verdict is PropertyVerdict.PROPERTY_HELD


def test_a_direct_store_is_equality_and_a_fee_store_is_only_an_upper_bound() -> None:
    source = (
        textwrap.dedent(
            f"""
        pragma solidity ^0.8.20;
        {_ERC}
        contract Desk {{
            IERC20 public immutable token;
            uint256 public accounted;
            uint256 public deployed;
            constructor(IERC20 token_) {{ token = token_; }}
            function _live() internal view returns (uint256) {{
                return token.balanceOf(address(this)) + deployed;
            }}
            function report() external {{
                uint256 live = _live();
                accounted = live;
            }}
            function accrue(uint256 amount) external {{ deployed += amount; }}
        }}
        """
        ).strip()
        + "\n"
    )
    model = build_research_model({"Desk.sol": source})
    found = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance"
    ]
    assert len(found) == 1
    assert found[0].fact("store_relation") == "equal"
    assert any("performance-fee share mint" in item for item in found[0].missing)
    assert any("protocol-fee share split" in item for item in found[0].missing)
    assert any("locked-share" in item for item in found[0].missing)
    fee = source.replace("accounted = live;", "accounted = live - live / 10;")
    fee_model = build_research_model({"Desk.sol": fee})
    fee_found = [
        item
        for item in run_suite(fee_model).candidates
        if item.detector == "accounting.reported_balance"
    ]
    assert fee_found[0].fact("store_relation") == "upper_bound"
    assert any("equality is not judged" in item for item in fee_found[0].missing)
