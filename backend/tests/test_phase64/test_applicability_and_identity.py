"""Applicability, provenance, and report-candidate discovery. No Forge."""

from __future__ import annotations

import textwrap

from app.discovery.bounty.analysis import CampaignAnalysis
from app.discovery.bounty.applicability import (
    applicability_is_strong,
    apply_execution_applicability,
    assess,
    deny_unconfirmed_role,
    mark_not_applicable,
    reconcile_identity,
)
from app.discovery.bounty.findings import execution_summary, is_strong
from app.discovery.bounty.properties import PropertyDeclaration, build_property
from app.discovery.bounty.vfcs import SequenceIdentity, VfcsCall, generate, sequence_id_of
from app.parsing.solidity_research import SemanticCandidate, build_research_model
from app.parsing.solidity_research_suite import run_suite

_ERC = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""


def _src(body: str) -> str:
    return textwrap.dedent(body).strip() + "\n"


def _desk(report_body: str, *, extra: str = "") -> str:
    return _src(
        f"""
        pragma solidity ^0.8.20;
        {_ERC}
        contract Desk {{
            struct Store {{ address keeper; uint256 accounted; }}
            Store private data;
            IERC20 public immutable token;
            constructor(IERC20 token_) {{ token = token_; data.keeper = msg.sender; }}
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
    )


def _candidates(source: str, detector: str) -> tuple[object, list[SemanticCandidate]]:
    model = build_research_model({"Desk.sol": source})
    found = [item for item in run_suite(model).candidates if item.detector == detector]
    return model, found


def _record(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "outcome": "property_violated",
        "declaration": "property_under_test",
        "verdict": "property_violated",
        "oracle_kind": "credit_le_holdings",
        "identity_status": "bound",
        "stale": False,
        "token_fixture": "standard",
        "applicability": {"disposition": "target_applicable", "assumptions": []},
    }
    body.update(overrides)
    return body


def test_fee_fixture_without_support_is_not_target_applicable() -> None:
    result = assess(token_fixture="fee_on_transfer", facts={"token_behavior": "unknown"})
    assert result.disposition == "unconfirmed"
    assert result.assumptions[0].status == "unknown"
    assert result.assumptions[0].material is True
    record = _record(
        token_fixture="fee_on_transfer",
        oracle_kind="credit_le_received",
        applicability=result.as_dict(),
    )
    assert is_strong(record) is False


def test_contradicted_fee_assumption_is_fixture_only() -> None:
    result = assess(
        token_fixture="fee_on_transfer",
        facts={"token_behavior": "standard", "token_behavior_evidence": "source"},
    )
    assert result.disposition == "fixture_only"
    assert (
        is_strong(_record(applicability=result.as_dict(), token_fixture="fee_on_transfer")) is False
    )
    unproven = assess(token_fixture="fee_on_transfer", facts={"token_behavior": "standard"})
    assert unproven.disposition == "unconfirmed"


def test_standard_token_violation_stays_eligible() -> None:
    result = assess(token_fixture="standard", facts={"token_behavior": "unknown"})
    assert result.disposition == "target_applicable"
    assert is_strong(_record(applicability=result.as_dict())) is True
    alias = assess(token_fixture="standard_erc20")
    assert alias.disposition == "target_applicable"
    assert alias.assumptions[0].material is False


def test_a_source_fact_that_matches_the_fixture_stays_eligible() -> None:
    result = assess(
        token_fixture="fee_on_transfer",
        facts={"token_behavior": "fee_on_transfer", "token_behavior_evidence": "source"},
    )
    assert result.disposition == "target_applicable"
    assert result.assumptions[0].status == "confirmed"
    assert is_strong(_record(applicability=result.as_dict(), token_fixture="fee_on_transfer"))
    harness = assess(
        token_fixture="fee_on_transfer",
        facts={"token_behavior": "fee_on_transfer", "token_behavior_evidence": "harness"},
    )
    assert harness.disposition == "unconfirmed"
    assert harness.assumptions[0].status == "unknown"


def test_an_unbound_identity_blocks_applicability() -> None:
    built = assess(token_fixture="standard", identity_status="identity_mismatch")
    assert built.disposition == "not_applicable"
    reconciled = reconcile_identity(
        assess(token_fixture="standard"),
        "identity_mismatch",
    )
    assert reconciled.disposition == "not_applicable"
    assert reconcile_identity(built, "bound").disposition == "not_applicable"
    stale = mark_not_applicable(assess(token_fixture="standard"), "source set changed")
    assert stale.disposition == "not_applicable"
    assert is_strong(_record(applicability=stale.as_dict(), stale=True)) is False


def test_a_failed_role_proof_is_not_target_applicable() -> None:
    unproven = assess(token_fixture="standard", facts={"role_getter": "keeper()"})
    assert unproven.disposition == "unconfirmed"
    role = next(item for item in unproven.assumptions if item.name == "privileged_actor")
    assert role.status == "unknown"
    granted = assess(
        token_fixture="standard",
        facts={"role_getter": "keeper()", "role_evidence": "runtime"},
    )
    assert granted.disposition == "target_applicable"
    denied = deny_unconfirmed_role(granted)
    assert denied.disposition == "not_applicable"
    denied_role = next(item for item in denied.assumptions if item.name == "privileged_actor")
    assert denied_role.status == "contradicted"
    assert is_strong(_record(applicability=denied.as_dict())) is False


def test_unknown_fixture_names_fail_closed_on_the_finding_path() -> None:
    missing = assess(token_fixture="")
    assert missing.disposition == "target_applicable"
    assert all(item.name != "token_behavior" for item in missing.assumptions)
    unknown = assess(token_fixture="misspelled_fee")
    assert unknown.disposition == "unconfirmed"
    record = _record(applicability=unknown.as_dict(), token_fixture="misspelled_fee")
    assert is_strong(record) is False
    host = assess(
        token_fixture="standard",
        facts={
            "report_scope": "host",
            "reporting_host": "IdleHost",
            "reporting_host_evidence": "validated_profile",
        },
    )
    assert host.disposition == "unconfirmed"
    named = next(item for item in host.assumptions if item.name == "reporting_host")
    assert named.status == "unknown"
    assert named.material is True
    assert "does not establish" in named.evidence
    assert is_strong(_record(applicability=host.as_dict())) is False
    observed = assess(
        token_fixture="standard",
        facts={
            "report_scope": "host",
            "reporting_host": "IdleHost",
            "reporting_host_evidence": "validated_profile",
            "host_dependence": "observed_inputs",
        },
    )
    assert observed.disposition == "target_applicable"
    observed_host = next(item for item in observed.assumptions if item.name == "reporting_host")
    assert observed_host.status == "confirmed"
    assert observed_host.material is False
    unnamed = assess(token_fixture="standard", facts={"report_scope": "host"})
    assert unnamed.disposition == "unconfirmed"
    built = assess(token_fixture="standard", facts={"role_getter": "keeper()"})
    proven = apply_execution_applicability(
        built,
        identity_status="bound",
        reason_code="property_violated",
        role_proven=True,
        role_denied=False,
        execution_id="vf_one",
        property_id="pr_one",
    )
    assert proven.disposition == "target_applicable"
    assert (
        is_strong(
            _record(
                applicability=proven.as_dict(),
                sequence_id="vf_one",
                property_id="pr_one",
            )
        )
        is True
    )
    assert (
        is_strong(
            _record(
                applicability=proven.as_dict(),
                sequence_id="vf_other",
                property_id="pr_one",
            )
        )
        is False
    )
    blocked = apply_execution_applicability(
        built,
        identity_status="identity_mismatch",
        reason_code="property_violated",
        role_proven=True,
        role_denied=False,
    )
    assert blocked.disposition == "not_applicable"
    denied = apply_execution_applicability(
        built,
        identity_status="bound",
        reason_code="role_unconfirmed",
        role_proven=False,
        role_denied=True,
    )
    assert denied.disposition == "not_applicable"
    untouched = apply_execution_applicability(
        assess(token_fixture="standard"),
        identity_status="bound",
        reason_code="property_held",
        role_proven=False,
        role_denied=False,
    )
    assert untouched.disposition == "target_applicable"
    assert (
        is_strong(_record(applicability=blocked.as_dict(), identity_status="identity_mismatch"))
        is False
    )


def test_legacy_fee_record_without_applicability_is_not_strong() -> None:
    record = _record(token_fixture="fee_on_transfer")
    del record["applicability"]
    assert is_strong(record) is False
    assert is_strong(_record()) is True
    explicit = _record(token_fixture="standard")
    del explicit["applicability"]
    assert is_strong(explicit) is True
    bare = _record(token_fixture="")
    del bare["applicability"]
    assert is_strong(bare) is False
    missing_name = _record()
    del missing_name["applicability"]
    del missing_name["token_fixture"]
    assert is_strong(missing_name) is False
    custom = _record(token_fixture="custom_rebase")
    del custom["applicability"]
    assert is_strong(custom) is False


def test_stale_or_unbound_identity_blocks_a_violation() -> None:
    assert is_strong(_record(stale=True)) is False
    assert is_strong(_record(identity_status="identity_mismatch")) is False
    unevaluated = _record(outcome="property_held", verdict="property_held")
    assert is_strong(unevaluated) is False


def test_same_function_candidates_keep_separate_execution_results() -> None:
    source = _src(
        f"""
        pragma solidity ^0.8.20;
        {_ERC}
        contract Desk {{
            IERC20 public immutable token;
            mapping(address => uint256) public book;
            mapping(address => uint256) public bonus;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount, address receiver) external {{
                token.transferFrom(msg.sender, address(this), amount);
                book[receiver] += amount;
                token.transferFrom(msg.sender, address(this), amount);
                bonus[receiver] += amount;
            }}
        }}
        """
    )
    model = build_research_model({"Desk.sol": source})
    found = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.fee_on_transfer_mismatch"
    ]
    assert len(found) == 2
    assert found[0].line != found[1].line
    generated = generate(model, found, SequenceIdentity(campaign_id="same"))
    keys = {item.derived_from for item in generated.sequences}
    assert len(keys) == 2
    assert all("#" in key for key in keys)
    bag = type("Bag", (), {"candidates": tuple(found)})()
    for candidate in found:
        key = f"{candidate.detector}@Desk.deposit(uint256,address)#{candidate.line}"
        assert CampaignAnalysis.candidate_for(bag, key) is candidate
    violated, held = found
    base = "accounting.fee_on_transfer_mismatch@Desk.deposit(uint256,address)"
    executions = (
        {
            "derived_from": f"{base}#{violated.line}",
            "outcome": "property_violated",
            "declaration": "property_under_test",
            "verdict": "property_violated",
            "oracle_kind": "credit_le_received",
            "identity_status": "bound",
            "property_id": "pr_a",
            "bundle_id": "b_a",
            "applicability": {"disposition": "target_applicable", "assumptions": []},
        },
        {
            "derived_from": f"{base}#{held.line}",
            "outcome": "property_held",
            "declaration": "property_under_test",
            "verdict": "property_held",
            "oracle_kind": "credit_le_received",
            "identity_status": "bound",
            "property_id": "pr_b",
            "bundle_id": "b_b",
        },
    )
    assert execution_summary(violated, executions).status == "property_violated"
    assert execution_summary(held, executions).status == "property_held"
    assert execution_summary(held, executions).strength != "strong_candidate"


def test_sequence_id_ignores_source_hash_and_keeps_deployment() -> None:
    calls = (VfcsCall("Desk", "report()", "report", "deployer"),)
    left = SequenceIdentity(campaign_id="c", source_hashes=(("Desk.sol", "a"),))
    right = SequenceIdentity(campaign_id="c", source_hashes=(("Desk.sol", "b"),))
    assert sequence_id_of(calls, "report", left, derived_from="k") == sequence_id_of(
        calls, "report", right, derived_from="k"
    )
    deployed = SequenceIdentity(campaign_id="c", deployment="1:0x1")
    other = SequenceIdentity(campaign_id="c", deployment="1:0x2")
    assert sequence_id_of(calls, "report", deployed) != sequence_id_of(calls, "report", other)


def test_equivalent_sequences_deduplicate() -> None:
    source = _desk("data.accounted = live;")
    model, found = _candidates(source, "accounting.reported_balance")
    once = generate(model, found, SequenceIdentity(campaign_id="c"))
    twice = generate(model, found + found, SequenceIdentity(campaign_id="c"))
    assert [item.sequence_id for item in once.sequences] == [
        item.sequence_id for item in twice.sequences
    ]
    assert any("deduplicated" in reason for _key, reason in twice.skipped)


def test_report_candidate_is_balance_backed_only_when_the_call_resolves() -> None:
    model, found = _candidates(_desk("data.accounted = live;"), "accounting.reported_balance")
    assert len(found) == 1
    assert found[0].fact("balance_backed") == "true"
    assert found[0].fact("reported_form") == "idle_balance"
    assert found[0].fact("report_scope") == "self"
    assert found[0].fact("stored_getter") == "accounted()"
    assert found[0].fact("role_getter") == "keeper()"
    generated = generate(model, found, SequenceIdentity(campaign_id="role"))
    spec = build_property(generated.sequences[0], model, found[0])
    assert spec.applicability.disposition == "unconfirmed"
    proven = apply_execution_applicability(
        spec.applicability,
        identity_status="bound",
        reason_code="property_violated",
        role_proven=True,
        role_denied=False,
        execution_id="vf_report",
        property_id="pr_report",
    )
    assert proven.disposition == "target_applicable"
    assert (
        is_strong(
            _record(
                applicability=proven.as_dict(),
                sequence_id="vf_report",
                property_id="pr_report",
            )
        )
        is True
    )
    opaque = _desk(
        "data.accounted = live;",
        extra="function _live() internal pure returns (uint256) { return 1; }",
    )
    # The second _live is a duplicate; the unique-body rule must refuse it.
    model = build_research_model({"Desk.sol": opaque})
    hits = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance"
    ]
    assert hits
    assert hits[0].fact("balance_backed") == "false"
    generated = generate(model, hits, SequenceIdentity(campaign_id="opaque"))
    spec = build_property(generated.sequences[0], model, hits[0])
    assert spec.declaration is PropertyDeclaration.PROPERTY_UNSUPPORTED
    assert spec.applicability.disposition == "not_applicable"


def test_loss_ignoring_is_a_different_transition_from_a_safe_report() -> None:
    _model, safe = _candidates(_desk("data.accounted = live;"), "accounting.reported_balance")
    _model, loss = _candidates(
        _desk(
            "if (live > data.accounted) { data.accounted = live; }",
            extra="function skim(uint256 amount) external { token.transfer(msg.sender, amount); }",
        ),
        "accounting.reported_balance",
    )
    assert safe[0].fact("loss_ignored") == "false"
    assert loss[0].fact("loss_ignored") == "true"
    assert loss[0].fact("outflow") == "skim(uint256)"


def _assumption(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "name": "token_behavior",
        "value": "fee_on_transfer",
        "status": "confirmed",
        "evidence": "source evidence records token_behavior=fee_on_transfer",
        "material": True,
    }
    body.update(overrides)
    return body


def test_a_stored_target_applicable_disposition_cannot_override_the_evidence() -> None:
    """Strength is recomputed. A stored disposition does not win a contradiction."""
    assert is_strong(_record()) is True
    assert is_strong(_record(token_fixture="")) is False
    assert is_strong(_record(token_fixture="misspelled_fee")) is False
    assert is_strong(_record(oracle_kind="call_must_fail", token_fixture="")) is True
    assert is_strong(_record(applicability={"disposition": "target_applicable"})) is False
    contradicted = {
        "disposition": "target_applicable",
        "assumptions": [
            _assumption(
                status="contradicted",
                evidence=(
                    "source evidence records token_behavior=standard, which contradicts "
                    "fixture fee_on_transfer"
                ),
            )
        ],
    }
    assert is_strong(_record(applicability=contradicted, token_fixture="fee_on_transfer")) is False
    harness = {
        "disposition": "target_applicable",
        "assumptions": [
            _assumption(evidence="harness setting records token_behavior=fee_on_transfer")
        ],
    }
    assert is_strong(_record(applicability=harness, token_fixture="fee_on_transfer")) is False
    unlabeled = {
        "disposition": "target_applicable",
        "assumptions": [_assumption(evidence="someone said the token takes a fee")],
    }
    assert is_strong(_record(applicability=unlabeled, token_fixture="fee_on_transfer")) is False
    sourced = {"disposition": "target_applicable", "assumptions": [_assumption()]}
    assert is_strong(_record(applicability=sourced, token_fixture="fee_on_transfer")) is True
    profiled = {
        "disposition": "target_applicable",
        "assumptions": [
            _assumption(
                evidence="validated_profile evidence records token_behavior=fee_on_transfer"
            )
        ],
    }
    assert is_strong(_record(applicability=profiled, token_fixture="fee_on_transfer")) is True
    mismatched_fixture = {
        "disposition": "target_applicable",
        "assumptions": [_assumption(value="rebasing")],
    }
    assert (
        is_strong(_record(applicability=mismatched_fixture, token_fixture="fee_on_transfer"))
        is False
    )
    extra = {
        "disposition": "target_applicable",
        "assumptions": [{**_assumption(), "note": "stale"}],
    }
    assert is_strong(_record(applicability=extra, token_fixture="fee_on_transfer")) is False
    broken = {
        "disposition": "target_applicable",
        "assumptions": [_assumption(status="maybe")],
    }
    assert is_strong(_record(applicability=broken)) is False
    host = {
        "disposition": "target_applicable",
        "assumptions": [
            {
                "name": "reporting_host",
                "value": "IdleHost",
                "status": "confirmed",
                "evidence": "validated profile names IdleHost for this local replay",
                "material": True,
            }
        ],
    }
    assert is_strong(_record(applicability=host)) is False
    non_material = {
        "disposition": "target_applicable",
        "assumptions": [
            {
                "name": "reporting_host",
                "value": "IdleHost",
                "status": "confirmed",
                "evidence": "fee inputs are observed totals",
                "material": False,
            }
        ],
    }
    assert is_strong(_record(applicability=non_material)) is True
    role = {
        "disposition": "target_applicable",
        "assumptions": [
            {
                "name": "privileged_actor",
                "value": "keeper()",
                "status": "confirmed",
                "evidence": (
                    "the harness read the role getter and it returned the deploying contract "
                    "for execution vf_one and property pr_one"
                ),
                "material": True,
            }
        ],
    }
    assert is_strong(_record(applicability=role)) is False
    assert (
        is_strong(_record(applicability=role, sequence_id="vf_one", property_id="pr_one")) is True
    )
    assert (
        is_strong(_record(applicability=role, sequence_id="vf_two", property_id="pr_one")) is False
    )
    assert is_strong(_record(oracle_kind="call_must_fail", token_fixture="custom_name")) is False
    assert applicability_is_strong({"applicability": "target_applicable"}) is False
    assert (
        applicability_is_strong(
            {"applicability": {"disposition": "target_applicable", "assumptions": "no"}}
        )
        is False
    )
    for broken_assumption in (
        {"name": 1, "status": "confirmed"},
        {
            "name": "token_behavior",
            "status": "confirmed",
            "evidence": 1,
            "value": "x",
            "material": True,
        },
        {
            "name": "token_behavior",
            "status": "confirmed",
            "evidence": "source x",
            "value": 1,
            "material": True,
        },
        {
            "name": "token_behavior",
            "status": "confirmed",
            "evidence": "source x",
            "value": "x",
            "material": "yes",
        },
    ):
        assert (
            applicability_is_strong(
                {
                    "applicability": {
                        "disposition": "target_applicable",
                        "assumptions": [broken_assumption],
                    },
                    "oracle_kind": "call_must_fail",
                    "token_fixture": "standard",
                }
            )
            is False
        )
