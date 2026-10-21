"""Source-line provenance, host scope, and report-oracle preconditions. No Forge."""

from __future__ import annotations

import textwrap

from app.discovery.bounty.analysis import CampaignAnalysis
from app.discovery.bounty.properties import (
    OracleKind,
    OracleObservation,
    OracleSpec,
    PropertyVerdict,
    evaluate,
)
from app.discovery.bounty.vfcs import SequenceIdentity, Vfcs, VfcsCall, generate
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite

_ERC = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""


def _src(body: str) -> str:
    return textwrap.dedent(body).strip() + "\n"


def _reports(sources: dict[str, str]) -> tuple[object, list[object]]:
    model = build_research_model(sources)
    found = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance"
    ]
    return model, found


def test_a_multiline_report_uses_the_store_line_not_a_character_offset() -> None:
    source = _src(
        f"""
        pragma solidity ^0.8.20;
        {_ERC}
        contract Desk {{
            IERC20 public immutable token;
            uint256 public accounted;
            constructor(IERC20 token_) {{ token = token_; }}
            function report()
                external
            {{
                uint256 pad = 1;
                pad = 2;
                pad = 3;
                pad = 4;
                pad = 5;
                uint256 live = token.balanceOf(address(this));
                accounted = live;
            }}
        }}
        """
    )
    model, found = _reports({"Desk.sol": source})
    assert len(found) == 1
    candidate = found[0]
    expected = source[: source.index("accounted = live")].count("\n") + 1
    function = model.function("Desk", "report")  # type: ignore[attr-defined]
    assert function is not None
    assert candidate.line == expected  # type: ignore[attr-defined]
    assert candidate.line != function.line + function.body.find("live")  # type: ignore[attr-defined]
    assert candidate.line > function.line + 1  # type: ignore[attr-defined]
    generated = generate(model, found, SequenceIdentity(campaign_id="line"))  # type: ignore[arg-type]
    assert generated.sequences
    assert "#" not in generated.sequences[0].derived_from
    bag = type("Bag", (), {"candidates": tuple(found)})()
    assert CampaignAnalysis.candidate_for(bag, generated.sequences[0].derived_from) is candidate


def test_idle_and_deployed_hosts_are_not_the_same_report() -> None:
    source = _src(
        f"""
        pragma solidity ^0.8.20;
        {_ERC}
        interface IHook {{
            function harvestAndReport() external view returns (uint256);
        }}
        contract Desk {{
            IERC20 public immutable token;
            uint256 public totalAssets;
            constructor(IERC20 token_) {{ token = token_; }}
            function report() external {{
                uint256 live = IHook(address(this)).harvestAndReport();
                totalAssets = live;
            }}
        }}
        contract IdleHost {{
            IERC20 public immutable token;
            constructor(IERC20 token_) {{ token = token_; }}
            function harvestAndReport() external view returns (uint256) {{
                return token.balanceOf(address(this));
            }}
        }}
        contract DeployedHost {{
            IERC20 public immutable token;
            uint256 public deployed;
            constructor(IERC20 token_) {{ token = token_; }}
            function harvestAndReport() external view returns (uint256) {{
                return token.balanceOf(address(this)) + deployed;
            }}
        }}
        """
    )
    model = build_research_model({"Hosts.sol": source})
    bare = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance" and item.contract == "Desk"
    ]
    assert len(bare) == 1
    assert bare[0].fact("balance_backed") == "false"
    assert bare[0].fact("report_scope") == "unresolved"
    model.reporting_host = "IdleHost"
    model.reporting_host_evidence = "validated_profile"
    idle = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance" and item.contract == "Desk"
    ]
    assert idle[0].fact("reported_form") == "idle_balance"
    assert idle[0].fact("balance_backed") == "true"
    assert idle[0].fact("report_scope") == "host"
    model.reporting_host = "DeployedHost"
    deployed = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance" and item.contract == "Desk"
    ]
    assert deployed[0].fact("reported_form") == "idle_plus_getter"
    assert deployed[0].fact("balance_backed") == "false"
    assert deployed[0].fact("external_getter") == "deployed()"
    assert deployed[0].fact("report_scope") == "host"
    assert idle[0].fact("reported_form") != deployed[0].fact("reported_form")


def test_a_private_component_is_not_guessed_as_zero() -> None:
    source = _src(
        f"""
        pragma solidity ^0.8.20;
        {_ERC}
        contract Desk {{
            IERC20 public immutable token;
            uint256 private deployed;
            uint256 public accounted;
            constructor(IERC20 token_) {{ token = token_; }}
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
    _model, found = _reports({"Desk.sol": source})
    assert len(found) == 1
    assert found[0].fact("reported_form") == "other"  # type: ignore[attr-defined]
    assert found[0].fact("balance_backed") == "false"  # type: ignore[attr-defined]


def test_a_missing_external_reading_is_not_a_held_zero() -> None:
    sequence = Vfcs(
        sequence_id="vf_phase65",
        template="report",
        origin="test",
        calls=(VfcsCall("Desk", "report()", "report", "attacker"),),
        property_under_test="stored total matches idle plus deployed",
        derived_from="accounting.reported_balance@Desk.report()",
        identity=SequenceIdentity(campaign_id="phase65"),
    )
    oracle = OracleSpec(
        kind=OracleKind.CREDIT_LE_HOLDINGS,
        probe_role="report",
        probe_function="report()",
        getter="accounted()",
        external_getter="deployed()",
    )
    missing = evaluate(
        sequence,
        oracle,
        OracleObservation((1,), holdings_after=1, credit_after=5),
    )
    assert missing.verdict is PropertyVerdict.NOT_EVALUATED
    assert missing.evaluated is False
    assert "not zero" in missing.reason
    held = evaluate(
        sequence,
        oracle,
        OracleObservation((1,), holdings_after=1, credit_after=5, external_after=4),
    )
    assert held.verdict is PropertyVerdict.PROPERTY_HELD
    violated = evaluate(
        sequence,
        oracle,
        OracleObservation((1,), holdings_after=1, credit_after=5, external_after=1),
    )
    assert violated.verdict is PropertyVerdict.PROPERTY_VIOLATED
    zero = evaluate(
        sequence,
        oracle,
        OracleObservation((1,), holdings_after=0, credit_after=0, external_after=0),
    )
    assert zero.verdict is PropertyVerdict.PROPERTY_HELD
    assert "0" in zero.reason
