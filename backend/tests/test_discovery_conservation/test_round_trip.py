"""Round-trip conservation hypotheses: emission, property, harness, verdict, feedback, ledger."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from app.discovery.bounty.engine_adapters import _judge
from app.discovery.bounty.findings import build_findings
from app.discovery.bounty.priority import prioritize
from app.discovery.bounty.properties import (
    OracleKind,
    OracleObservation,
    OracleSpec,
    PropertyDeclaration,
    PropertyFamily,
    PropertyVerdict,
    build_property,
    evaluate,
    probe_index,
)
from app.discovery.bounty.research_ledger import build_ledger
from app.discovery.bounty.stateful import (
    K_ACTOR,
    K_EVIDENCE,
    build_harness,
    observation_from_events,
)
from app.discovery.bounty.vfcs import FeedbackSignal, generate, mutate
from app.parsing.solidity_conservation import DETECTOR
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite
from app.security.solidity.rules import HYPOTHESIS_FAMILIES, _research_rules
from tests.test_phase50.phase50_support import manifest

HISTORY = Path(__file__).resolve().parents[1] / "fixtures" / "phase52_history"
PAIRS = ("missing_debit", "post_transfer_price", "index_rounding", "unbound_token", "helper_debit")


def _fixture(stem: str, role: str) -> tuple[str, str]:
    name = f"roundtrip_{stem}_{role}.sol"
    return name, (HISTORY / name).read_text(encoding="utf-8")


def _round_trip(stem: str, role: str):  # type: ignore[no-untyped-def]
    name, text = _fixture(stem, role)
    model = build_research_model({name: text})
    hits = [c for c in run_suite(model).candidates if c.detector == DETECTOR]
    assert len(hits) == 1, (stem, role, hits)
    built = generate(model, hits, sources={name: text})
    assert len(built.sequences) == 1
    sequence = built.sequences[0]
    return model, hits[0], sequence, build_property(sequence, model, hits[0]), {name: text}


@pytest.mark.parametrize("stem", PAIRS)
@pytest.mark.parametrize("role", ("vulnerable", "safe"))
def test_the_hypothesis_fires_on_both_twins_with_low_confidence(stem: str, role: str) -> None:
    _, candidate, sequence, spec, _ = _round_trip(stem, role)
    assert candidate.confidence == "low"
    assert candidate.fact("hypothesis_basis") == "token_custody"
    assert "not a suspected defect" in candidate.summary
    assert [c.role for c in sequence.calls] == [
        "deposit",
        "victim_deposit",
        "withdraw",
        "withdraw_again",
    ]
    assert [c.actor for c in sequence.calls] == ["attacker", "victim", "attacker", "attacker"]
    assert spec.family is PropertyFamily.SOLVENCY
    assert spec.declaration is PropertyDeclaration.PROPERTY_UNDER_TEST
    assert spec.oracle.kind is OracleKind.BALANCE_NOT_INCREASED
    assert spec.oracle.probe_role == "withdraw_again"
    assert spec.oracle.precondition_roles == ("deposit", "victim_deposit", "withdraw")
    assert spec.verified is False and sequence.verified is False


def test_no_hypothesis_without_a_caller_round_trip() -> None:
    text = """pragma solidity ^0.8.20;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
contract Treasury {
    IERC20 public immutable token;
    address public immutable owner;
    mapping(address => uint256) public paid;
    constructor(IERC20 t) { token = t; owner = msg.sender; }
    function fund(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        paid[msg.sender] += amount;
    }
    function sweep(uint256 amount) external {
        require(msg.sender == owner, "owner");
        token.transfer(owner, amount);
    }
}
"""
    model = build_research_model({"Treasury.sol": text})
    assert not [c for c in run_suite(model).candidates if c.detector == DETECTOR]


def test_the_hypothesis_never_becomes_a_static_observation() -> None:
    assert "conservation" in HYPOTHESIS_FAMILIES
    assert all(rule.rule_id != "sol.research.conservation" for rule in _research_rules())


def test_the_withdrawal_reads_the_public_credit_or_records_the_fallback() -> None:
    _, _, _, spec, _ = _round_trip("missing_debit", "vulnerable")
    assert spec.oracle.getter == "balances(address)"
    assert any("reports for it" in item for item in spec.provenance.assumptions)
    name, text = _fixture("missing_debit", "vulnerable")
    hidden = text.replace(
        "mapping(address => uint256) public balances", "mapping(address => uint256) balances"
    )
    model = build_research_model({name: hidden})
    hit = next(c for c in run_suite(model).candidates if c.detector == DETECTOR)
    sequence = generate(model, [hit], sources={name: hidden}).sequences[0]
    fallback = build_property(sequence, model, hit)
    assert fallback.oracle.getter == ""
    assert any("no traced getter" in item for item in fallback.provenance.assumptions)


def test_the_harness_reads_the_attacker_before_and_after_and_funds_the_victim() -> None:
    model, _, sequence, spec, sources = _round_trip("missing_debit", "vulnerable")
    harness = build_harness(sequence, model, oracle=spec.oracle, sources=sources)
    assert harness.buildable, harness.reason
    body = harness.body
    first = body.index(f"BugForgeObservation({K_ACTOR}, 0,")
    last = body.index(f"BugForgeObservation({K_ACTOR}, 1,")
    assert first < body.index("vm.prank(address(0xA11CE));\n        (bool ok_0") < last
    assert "bfToken.balanceOf(address(0xA11CE))" in body
    assert "bfToken.balanceOf(address(0xD1A1))" in body
    assert "bfToken.mint(address(0xB0B)" in body
    sizing = '_bfRead(address(t), abi.encodeWithSignature("balances(address)", address(0xA11CE))'
    assert body.count(sizing) == 2
    for slot in range(4):
        assert f"BugForgeObservation({K_EVIDENCE}, {slot}, bfToken.balanceOf(" in body
    for slot, actor in ((4, "0xA11CE"), (5, "0xA11CE"), (6, "0xB0B"), (7, "0xB0B")):
        assert (
            f'_bfEvidence({slot}, address(t), abi.encodeWithSignature("balances(address)", '
            f"address({actor})));" in body
        )
    assert body.index(f"BugForgeObservation({K_EVIDENCE}, 1,") > body.index("(bool ok_3")


def _obs(**kwargs: object) -> OracleObservation:
    base: dict[str, object] = {
        "call_ok": (1, 1, 1, 1),
        "actor_before": 100,
        "actor_after": 100,
        "recipient_before": 0,
        "recipient_after": 0,
    }
    base.update(kwargs)
    return OracleObservation(**base)  # type: ignore[arg-type]


def test_the_verdict_compares_the_attackers_own_balance() -> None:
    _, _, sequence, spec, _ = _round_trip("missing_debit", "vulnerable")
    oracle = spec.oracle
    gained = evaluate(sequence, oracle, _obs(actor_after=150))
    assert gained.verdict is PropertyVerdict.PROPERTY_VIOLATED and "+50" in gained.reason
    assert evaluate(sequence, oracle, _obs(actor_after=99)).verdict is PropertyVerdict.PROPERTY_HELD
    refused = evaluate(sequence, oracle, _obs(call_ok=(1, 1, 1, 0)))
    assert refused.verdict is PropertyVerdict.PROPERTY_HELD and "reverted" in refused.reason
    unread = evaluate(sequence, oracle, _obs(actor_after=None))
    assert unread.verdict is PropertyVerdict.NOT_EVALUATED
    side = evaluate(sequence, oracle, _obs(recipient_after=40))
    assert side.verdict is PropertyVerdict.PROPERTY_VIOLATED and "+40" in side.reason
    no_recipient = evaluate(sequence, oracle, _obs(recipient_before=None, recipient_after=None))
    assert no_recipient.verdict is PropertyVerdict.NOT_EVALUATED
    assert "recipient" in no_recipient.reason
    assert evaluate(sequence, oracle, _obs(readable=False)).verdict is PropertyVerdict.NOT_EVALUATED
    pre_failed = evaluate(sequence, oracle, _obs(call_ok=(1, 0, 1, 1), actor_after=500))
    assert pre_failed.verdict is PropertyVerdict.NOT_EVALUATED


def test_supplementary_evidence_is_decoded_and_reported_without_a_loss_claim() -> None:
    _, _, sequence, spec, _ = _round_trip("missing_debit", "vulnerable")
    events = (
        (K_ACTOR, 0, 100),
        (K_ACTOR, 1, 150),
        (K_ACTOR, 2, 0),
        (K_ACTOR, 3, 0),
        (K_EVIDENCE, 0, 0),
        (K_EVIDENCE, 1, 50),
        (K_EVIDENCE, 4, 0),
        (K_EVIDENCE, 5, 0),
        (K_EVIDENCE, 99, 7),
    )
    observation, _, _ = observation_from_events(events, 4)
    assert observation.evidence == (
        ("holdings_before", 0),
        ("holdings_after", 50),
        ("attacker_credit_before", 0),
        ("attacker_credit_after", 0),
    )
    judged = evaluate(sequence, spec.oracle, replace(observation, call_ok=(1, 1, 1, 1)))
    assert judged.verdict is PropertyVerdict.PROPERTY_VIOLATED
    assert "contract holdings 0 -> 50" in judged.reason
    assert "Victim loss is not established" in judged.reason
    assert judged.as_dict()["evidence"]["holdings_after"] == "50"
    assert "victim_balance_before" not in judged.as_dict()["evidence"]


def test_a_reverted_sole_withdrawal_is_not_judged() -> None:
    _, _, sequence, spec, _ = _round_trip("missing_debit", "vulnerable")
    single = replace(spec.oracle, probe_role="withdraw", precondition_roles=("deposit",))
    calls = tuple(c for c in sequence.calls if c.role != "withdraw_again")
    trimmed = replace(sequence, calls=calls)
    refused = evaluate(trimmed, single, _obs(call_ok=(1, 1, 0)))
    assert refused.verdict is PropertyVerdict.NOT_EVALUATED
    assert "did not complete" in refused.reason


def test_credit_and_receipt_no_longer_decide_the_balance_oracle() -> None:
    _, _, sequence, spec, _ = _round_trip("missing_debit", "vulnerable")
    over_credited = _obs(credited=10, received=1)
    assert evaluate(sequence, spec.oracle, over_credited).verdict is PropertyVerdict.PROPERTY_HELD
    credit = replace(spec.oracle, kind=OracleKind.CREDIT_LE_RECEIVED, probe_role="deposit")
    credit = replace(credit, probe_function=sequence.calls[0].function, precondition_roles=())
    verdict = evaluate(sequence, credit, _obs(credited=10, received=1))
    assert verdict.verdict is PropertyVerdict.PROPERTY_VIOLATED


def test_a_reverted_withdrawal_is_judged_only_after_a_completed_payout() -> None:
    """Ordinary and additional payouts are different results, in both judges."""
    model, candidate, sequence, spec, _ = _round_trip("missing_debit", "vulnerable")
    oracle = spec.oracle
    roles = [call.role for call in sequence.calls]
    ordinary = roles.index("withdraw")
    extra = roles.index("withdraw_again")
    succeeded = [1, 1, 1, 1]

    additional = succeeded.copy()
    additional[extra] = 0
    held = evaluate(sequence, oracle, _obs(call_ok=tuple(additional)))
    assert held.verdict is PropertyVerdict.PROPERTY_HELD
    assert "additional payout reverted" in held.reason
    assert "earlier" in held.reason

    failed_first = succeeded.copy()
    failed_first[ordinary] = 0
    missed = evaluate(sequence, oracle, _obs(call_ok=tuple(failed_first), actor_after=500))
    assert missed.verdict is PropertyVerdict.NOT_EVALUATED
    assert "intended withdrawal did not succeed" in missed.reason
    assert "does not establish normal withdrawal" in missed.reason

    overpaid = evaluate(sequence, oracle, _obs(actor_after=150))
    assert overpaid.verdict is PropertyVerdict.PROPERTY_VIOLATED
    assert "+50" in overpaid.reason

    unread = evaluate(sequence, oracle, _obs(actor_before=None))
    assert unread.verdict is PropertyVerdict.NOT_EVALUATED
    assert "could not be read" in unread.reason

    swapped = replace(
        sequence,
        calls=(sequence.calls[1], sequence.calls[0], sequence.calls[2], sequence.calls[3]),
    )
    assert probe_index(swapped, oracle) == 3
    rebound = build_property(swapped, model, candidate)
    assert rebound.oracle.probe_role == "withdraw_again"
    assert probe_index(swapped, rebound.oracle) == 3
    assert evaluate(swapped, rebound.oracle, _obs(actor_after=140)).verdict is (
        PropertyVerdict.PROPERTY_VIOLATED
    )

    # The probe's role name is not evidence that an ordinary payout already happened.
    early = replace(
        sequence,
        calls=(sequence.calls[0], sequence.calls[1], sequence.calls[3], sequence.calls[2]),
    )
    early_spec = build_property(early, model, candidate)
    early_probe = probe_index(early, early_spec.oracle)
    assert early.calls[early_probe].role == "withdraw_again"
    assert "withdraw" not in early_spec.oracle.precondition_roles
    early_ok = [1, 1, 1, 1]
    early_ok[early_probe] = 0
    early_verdict = evaluate(early, early_spec.oracle, _obs(call_ok=tuple(early_ok)))
    assert early_verdict.verdict is PropertyVerdict.NOT_EVALUATED
    assert "intended withdrawal did not succeed" in early_verdict.reason

    judged, violated = _judge(sequence, oracle)
    assert judged is not None and f"if (!_bfOk({ordinary})) return false;" in judged
    assert f"if (!_bfOk({extra})) return false;" not in judged
    assert f"bfSeen[{K_ACTOR}][0]" in judged and f"bfSeen[{K_ACTOR}][1]" in judged
    summed = (
        f"bfVal[{K_ACTOR}][1] + bfVal[{K_ACTOR}][3] > bfVal[{K_ACTOR}][0] + bfVal[{K_ACTOR}][2]"
    )
    assert violated is not None and summed in violated

    sole_calls = tuple(call for call in sequence.calls if call.role != "withdraw_again")
    sole = replace(sequence, calls=sole_calls)
    sole_oracle = build_property(sole, model, candidate).oracle
    assert sole_oracle.probe_role == "withdraw"
    sole_judged, _sole_violated = _judge(sole, sole_oracle) or ("", "")
    sole_probe = probe_index(sole, sole_oracle)
    assert f"if (!_bfOk({sole_probe})) return false;" in sole_judged
    sole_failed = evaluate(sole, sole_oracle, _obs(call_ok=(1, 1, 0), actor_after=100))
    assert sole_failed.verdict is PropertyVerdict.NOT_EVALUATED
    assert "intended withdrawal did not succeed" in sole_failed.reason
    sole_overpaid = evaluate(sole, sole_oracle, _obs(call_ok=(1, 1, 1), actor_after=160))
    assert sole_overpaid.verdict is PropertyVerdict.PROPERTY_VIOLATED


def test_a_second_actor_is_funded_for_a_non_balance_oracle() -> None:
    model, _, sequence, _, sources = _round_trip("missing_debit", "vulnerable")
    calls = tuple(call for call in sequence.calls if call.role in {"victim_deposit", "withdraw"})
    trimmed = replace(sequence, calls=calls)
    oracle = OracleSpec(
        kind=OracleKind.CALL_MUST_FAIL,
        probe_role="withdraw",
        probe_function=calls[-1].function,
        precondition_roles=("victim_deposit",),
    )
    harness = build_harness(trimmed, model, oracle=oracle, sources=sources)
    assert harness.buildable, harness.reason
    assert "bfToken.mint(address(0xB0B)" in harness.body
    assert "bfToken.approve(address(t), type(uint256).max)" in harness.body


def test_engine_harness_judges_the_same_balance() -> None:
    _, _, sequence, spec, _ = _round_trip("missing_debit", "vulnerable")
    judged, violated = _judge(sequence, spec.oracle) or ("", "")
    assert f"bfSeen[{K_ACTOR}][0]" in judged and f"bfSeen[{K_ACTOR}][1]" in judged
    assert violated.strip() == (
        f"return bfVal[{K_ACTOR}][1] + bfVal[{K_ACTOR}][3] > "
        f"bfVal[{K_ACTOR}][0] + bfVal[{K_ACTOR}][2];"
    )
    assert "K_CREDITED" not in violated


def test_a_held_round_trip_is_retried_at_small_deposit_amounts_once() -> None:
    _, _, sequence, _, _ = _round_trip("index_rounding", "vulnerable")
    signal = FeedbackSignal("near_miss", sequence.sequence_id, 3, engine="foundry")
    children = mutate([sequence], [signal])
    operators = sorted(child.origin.split(":")[2] for child in children)
    assert operators == ["small_amount_one", "small_amount_three", "small_amount_two"]
    for child in children:
        changed = [c for c, p in zip(child.calls, sequence.calls, strict=True) if c != p]
        assert [c.role for c in changed] == ["deposit"]
        again = mutate([child], [replace(signal, sequence_id=child.sequence_id)])
        assert not [c for c in again if c.origin.split(":")[2].startswith("small_amount")]


def _ledger(sequences, outcomes):  # type: ignore[no-untyped-def]
    model, candidate, sequence, spec, _ = _round_trip("missing_debit", "safe")
    specs = {s.sequence_id: spec for s in sequences}
    return build_ledger(
        models=[model],
        candidates=[candidate],
        sequences=sequences,
        specs=specs,
        skipped={},
        executions={sid: {"outcome": outcome} for sid, outcome in outcomes.items()},
        engines=[],
    )


def test_a_held_property_is_kept_and_asks_for_a_variation_until_one_was_tried() -> None:
    _, _, sequence, _, _ = _round_trip("missing_debit", "safe")
    ledger = _ledger([sequence], {sequence.sequence_id: "property_held"})
    kinds = [gap["kind"] for gap in ledger["RESEARCH_GAPS"]]
    assert kinds == ["held_untested_variation"]
    gap = ledger["RESEARCH_GAPS"][0]
    assert "regression" in gap["reason"] and "one ordering" in gap["reason"]
    assert ledger["RESEARCH_COVERAGE"]["properties_held"] == 1
    signal = FeedbackSignal("near_miss", sequence.sequence_id, 3, engine="foundry")
    child = mutate([sequence], [signal])[0]
    tried = _ledger(
        [sequence, child],
        {sequence.sequence_id: "property_held", child.sequence_id: "property_held"},
    )
    assert "held_untested_variation" not in [g["kind"] for g in tried["RESEARCH_GAPS"]]
    assert tried["RESEARCH_COVERAGE"]["properties_held_after_variation"] == 1
    assert tried["verified"] is False


def test_a_hypothesis_is_a_finding_only_after_an_executed_violation() -> None:
    _, candidate, _, _, _ = _round_trip("missing_debit", "vulnerable")
    mani = manifest()
    identity = mani.to_campaign_identity()
    assert build_findings([candidate], manifest=mani, identity=identity) == ()
    key = f"{candidate.detector}@{candidate.contract}.{candidate.function}"
    held = {"x": {"derived_from": key, "outcome": "property_held"}}
    assert build_findings([candidate], manifest=mani, identity=identity, executions=held) == ()
    violated = {
        "x": {
            "derived_from": key,
            "outcome": "property_violated",
            "declaration": "property_under_test",
            "verdict": "property_violated",
            "oracle_kind": "balance_not_increased",
            "identity_status": "bound",
            "token_fixture": "standard",
        }
    }
    (finding,) = build_findings([candidate], manifest=mani, identity=identity, executions=violated)
    assert finding.candidate_strength == "strong_candidate"
    assert finding.verified is False
    incomplete = {
        "x": {key: value for key, value in violated["x"].items() if key != "token_fixture"}
    }
    (blocked,) = build_findings(
        [candidate], manifest=mani, identity=identity, executions=incomplete
    )
    assert blocked.candidate_strength == "unconfirmed_assumption"


def test_a_hypothesis_adds_no_triage_weight() -> None:
    model, candidate, _, _, _ = _round_trip("missing_debit", "vulnerable")
    with_hypothesis = prioritize(model, candidates=[candidate])
    without = prioritize(model, candidates=[])
    assert [(e.identity, e.score) for e in with_hypothesis.ranked] == [
        (e.identity, e.score) for e in without.ranked
    ]
