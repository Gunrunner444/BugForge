"""Hypothesis cases in the local benchmark: scored apart from detectors, judged by execution."""

from __future__ import annotations

import json
from pathlib import Path

from app.discovery.bounty.benchmark import run_benchmark
from app.discovery.bounty.stateful import StatefulExecutor
from tests.test_phase52.phase52_support import requires_forge

HISTORY = Path(__file__).resolve().parents[1] / "fixtures" / "phase52_history"


def test_static_benchmark_scores_hypotheses_apart_from_detectors() -> None:
    report = run_benchmark(HISTORY)
    cases = json.loads((HISTORY / "benchmark.json").read_text())["cases"]
    detectors = [c for c in cases if c.get("kind", "detector") == "detector"]
    hypotheses = [c for c in cases if c.get("kind") == "hypothesis"]
    assert report["totals"] == {
        "tp": len(detectors),
        "fn": 0,
        "fp": 0,
        "tn": len(detectors),
    }
    assert report["hypotheses"]["cases"] == len(hypotheses) == 6
    assert report["hypotheses"]["emitted_vulnerable"] == 6
    assert report["hypotheses"]["emitted_safe"] == 6
    statics = {c["id"]: c["static"] for c in report["cases"] if c["kind"] == "hypothesis"}
    assert set(statics.values()) == {"emitted_both"}
    assert report["verified"] is False and report["real_world_rate"] is None


@requires_forge
def test_execution_discriminates_round_trip_twins_and_feedback_finds_the_rounding_twin() -> None:
    report = run_benchmark(HISTORY, executor=StatefulExecutor())
    by_id = {c["id"]: c for c in report["cases"]}
    for stem in ("missing_debit", "post_transfer_price", "helper_debit", "struct_index"):
        case = by_id[f"roundtrip_{stem}"]
        assert case["stateful"] == {"vulnerable": "property_violated", "safe": "property_held"}
        assert case["execution_discriminates"] is True
        assert case["vulnerability_label"] == "local_property_violation_unverified"
    rounding = by_id["roundtrip_index_rounding"]
    assert rounding["stateful"] == {"vulnerable": "property_held", "safe": "property_held"}
    assert rounding["execution_discriminates"] is False
    assert rounding["feedback"] == {"vulnerable": "property_violated", "safe": "property_held"}
    assert rounding["execution_discriminates_after_feedback"] is True
    unbound = by_id["roundtrip_unbound_token"]
    assert unbound["stateful"] == {"vulnerable": "inconclusive", "safe": "inconclusive"}
    assert unbound["vulnerability_label"] == "inconclusive_not_judged"
    assert report["hypotheses"]["execution_discriminated"] == 4
    assert report["hypotheses"]["discriminated_after_feedback"] == 5
    feedback = report["feedback"]
    assert feedback["by_role"]["safe"]["variants_violated"] == 0
    assert feedback["cases_with_violating_variant"] == {"vulnerable": 1, "safe": 0}
    assert feedback["by_role"]["vulnerable"]["variants_violated"] >= 1
    before = feedback["cases_distinguished_before_feedback"]
    assert feedback["cases_distinguished_after_feedback"] == before + 1
    assert feedback["variants_generated"] == (
        feedback["variants_executed"] + feedback["variants_not_executed"]
    )
    assert feedback["variants_executed"] == (
        feedback["variants_judged"] + feedback["variants_compiled_inconclusive"]
    )
    for role in ("vulnerable", "safe"):
        per = feedback["by_role"][role]
        assert per["variants_executed"] == (
            per["variants_violated"] + per["variants_held"] + per["variants_compiled_inconclusive"]
        )
    recorded = [item for case in report["cases"] for item in case.get("feedback_variants", [])]
    assert len(recorded) == feedback["variants_generated"]
    assert {item["status"] for item in recorded} <= {
        "judged",
        "compiled_inconclusive",
        "not_executed",
    }
    assert report["stateful"]["disagree"] == 0
    assert all(c["checks"]["overstated"] is False for c in report["cases"] if "checks" in c)
