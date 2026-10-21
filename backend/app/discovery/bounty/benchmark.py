"""Local regression benchmark over compact incident-class fixtures (Phase 52, Slice D).

Each case is a vulnerable fixture and its safe twin, the detector that should fire
on the first and not on the second, and optionally the stateful outcome its property
should reach on each (the safe twin runs the *same* sequence, rebuilt from the
vulnerable candidate, against the fixed code). Everything is local: fixtures are read
from a directory on disk; nothing is downloaded.

A ``hypothesis`` case names a hypothesis source that is meant to fire on both twins.
Its emission is not scored as detector precision. Only execution can discriminate it:
the vulnerable twin must violate the property and the safe twin must hold it.

The report is a regression signal for these fixtures only. It is **not** a real-world
detection rate and must never be presented as one.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from app.discovery.bounty.properties import build_property
from app.discovery.bounty.vfcs import generate, mutate
from app.discovery.orchestration.codec import digest
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite

BENCHMARK_SCHEMA = "bugforge.local_benchmark/1"
DISCLAIMER = (
    "local fixture regression only: these compact reconstructions measure BugForge "
    "against itself; this is not a real-world detection rate"
)
MAX_CASES = 64
FUNNEL_STAGES = (
    "sequence_generated",
    "property_executable",
    "harness_built",
    "forge_executed",
    "property_judged",
    "target_applicable",
)


def _fires(text: str, file: str, detector: str, contract: str) -> tuple[bool, Any, Any]:
    model = build_research_model({file: text})
    hits = [
        c
        for c in run_suite(model).candidates
        if c.detector == detector and (not contract or c.contract == contract)
    ]
    return bool(hits), (hits[0] if hits else None), model


def run_benchmark(directory: Path, *, executor: Any = None) -> dict[str, Any]:
    """Run every case in ``directory/benchmark.json``. ``executor`` enables stateful checks."""
    spec = json.loads((directory / "benchmark.json").read_text(encoding="utf-8"))
    if spec.get("schema") != BENCHMARK_SCHEMA:
        raise ValueError("not a BugForge local benchmark")
    cases: list[dict[str, Any]] = []
    totals = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    hypotheses = {
        "cases": 0,
        "emitted_vulnerable": 0,
        "emitted_safe": 0,
        "execution_discriminated": 0,
        "execution_not_discriminated": 0,
        "execution_not_run": 0,
        "discriminated_after_feedback": 0,
    }
    funnel: dict[str, int] = {"attempted": 0, **{stage: 0 for stage in FUNNEL_STAGES}}
    # One bounded feedback round after a held primary run, as campaigns do. Variant
    # counters and case counters are kept apart: a case with three violating variants
    # is one case with a violating variant, and three violating variants.
    feedback_totals = _feedback_totals()
    stateful = {"agree": 0, "disagree": 0, "not_run": 0}
    identity_validation = {"outcome": "not_run", "executed": None, "forge_delta": None}
    for case in list(spec.get("cases", []))[:MAX_CASES]:
        detector = str(case["detector"])
        contract = str(case.get("contract", ""))
        files = {role: (directory / str(case[role])).resolve() for role in ("vulnerable", "safe")}
        if any(directory.resolve() not in path.parents for path in files.values()):
            raise ValueError("benchmark fixtures must live inside the benchmark directory")
        texts = {role: path.read_text(encoding="utf-8") for role, path in files.items()}
        vuln_hit, candidate, vuln_model = _fires(
            texts["vulnerable"], files["vulnerable"].name, detector, contract
        )
        safe_hit, _, safe_model = _fires(texts["safe"], files["safe"].name, detector, contract)
        kind = str(case.get("kind", "detector"))
        if kind == "hypothesis":
            hypotheses["cases"] += 1
            hypotheses["emitted_vulnerable"] += int(vuln_hit)
            hypotheses["emitted_safe"] += int(safe_hit)
            static = "emitted_both" if vuln_hit and safe_hit else "fail"
        else:
            totals["tp" if vuln_hit else "fn"] += 1
            totals["fp" if safe_hit else "tn"] += 1
            static = "pass" if vuln_hit and not safe_hit else "fail"
        result: dict[str, Any] = {
            "id": case["id"],
            "kind": kind,
            "detector": detector,
            "vulnerable_fires": vuln_hit,
            "safe_fires": safe_hit,
            "static": static,
            "rationale": str(case.get("rationale", "")),
            "ground_truth": str(case.get("ground_truth", "unknown")),
        }
        result["vulnerability_label"] = "not_a_confirmed_vulnerability"
        result["execution"] = "not_requested"
        if not case.get("stateful"):
            result["execution"] = "unsupported_or_not_requested"
            result["vulnerability_label"] = "unknown"
        expected = dict(case.get("stateful") or {})
        if expected and executor is not None and candidate is not None:
            outcomes: dict[str, str] = {}
            observed: dict[str, Any] = {}
            feedback: dict[str, str] = {}
            variants: list[dict[str, Any]] = []
            vulnerable_sequence = None
            for role, model, text, path in (
                ("vulnerable", vuln_model, texts["vulnerable"], files["vulnerable"]),
                ("safe", safe_model, texts["safe"], files["safe"]),
            ):
                funnel["attempted"] += 1
                twin = replace(candidate, file=path.name)
                role_sources = {path.name: text}
                built = generate(model, [twin], sources=role_sources)
                if not built.sequences:
                    outcomes[role] = "no_sequence"
                    continue
                wanted = str(case.get("template") or "")
                matched = [
                    item for item in built.sequences if not wanted or item.template == wanted
                ]
                if not matched:
                    outcomes[role] = "no_sequence"
                    continue
                sequence = matched[0]
                spec_ = build_property(sequence, model, twin)
                obs = executor.execute(sequence, model, {path.name: text}, spec=spec_)
                outcomes[role] = obs.outcome.value
                observed[role] = obs
                reached = (
                    True,
                    spec_.executable,
                    obs.harness is not None and obs.harness.buildable,
                    bool(obs.executed),
                    obs.outcome.value in {"property_violated", "property_held"},
                    getattr(obs, "applicability_disposition", "") == "target_applicable",
                )
                for stage, ok in zip(FUNNEL_STAGES, reached, strict=True):
                    funnel[stage] += int(ok)
                signal = obs.signal() if obs.outcome.value == "property_held" else None
                if signal is not None:
                    records = [
                        _variant_record(
                            role,
                            child,
                            executor.execute(
                                child, model, role_sources, spec=build_property(child, model, twin)
                            ),
                        )
                        for child in mutate([sequence], [signal])
                    ]
                    variants.extend(records)
                    feedback[role] = _feedback_outcome(records)
                    _count_variants(feedback_totals, role, records)
                if role == "vulnerable":
                    vulnerable_sequence = sequence
            result["stateful"] = outcomes
            result["stateful_expected"] = expected
            refused = bool(outcomes) and all(value == "no_sequence" for value in outcomes.values())
            result["execution"] = (
                "sequence_refused"
                if refused
                else "foundry"
                if executor.available()
                else "unavailable"
            )
            labels = {
                "property_violated": "local_property_violation_unverified",
                "property_held": "property_held",
                "mechanism_observed": "mechanism_only",
                "failure_propagated": "mechanism_not_reproduced",
                "no_sequence": "not_a_confirmed_vulnerability",
                "inconclusive": "inconclusive_not_judged",
            }
            result["vulnerability_label"] = labels.get(
                outcomes.get("vulnerable", ""), "unclassified"
            )
            vulnerable_obs = observed.get("vulnerable")
            if vulnerable_sequence is not None and identity_validation["outcome"] == "not_run":
                altered = {files["vulnerable"].name: texts["vulnerable"] + "\n"}
                before = getattr(executor, "runs", None)
                rejected = executor.execute(
                    vulnerable_sequence,
                    vuln_model,
                    altered,
                    spec=build_property(vulnerable_sequence, vuln_model),
                )
                identity_validation = {
                    "outcome": rejected.outcome.value,
                    "executed": rejected.executed,
                    "forge_delta": (None if before is None else executor.runs - before),
                }
                result["identity_rejection"] = rejected.outcome.value
            agreed = all(outcomes.get(role) == want for role, want in expected.items())
            discriminated = (
                outcomes.get("vulnerable") == "property_violated"
                and outcomes.get("safe") == "property_held"
            )
            result["execution_discriminates"] = discriminated
            final = {
                role: feedback.get(role) if feedback.get(role) == "property_violated" else value
                for role, value in outcomes.items()
            }
            after = (
                final.get("vulnerable") == "property_violated"
                and final.get("safe") == "property_held"
            )
            if feedback:
                result["feedback"] = feedback
                result["feedback_variants"] = variants
            result["execution_discriminates_after_feedback"] = after
            feedback_totals["cases_executed"] += 1
            feedback_totals["cases_distinguished_before_feedback"] += int(discriminated)
            feedback_totals["cases_distinguished_after_feedback"] += int(after)
            for role in ("vulnerable", "safe"):
                if any(
                    item["role"] == role and item["outcome"] == "property_violated"
                    for item in variants
                ):
                    feedback_totals["cases_with_violating_variant"][role] += 1
            if after != discriminated or final != outcomes:
                feedback_totals["cases_changed"] += 1
            if kind == "hypothesis":
                key = "execution_discriminated" if discriminated else "execution_not_discriminated"
                hypotheses[key] += 1
                hypotheses["discriminated_after_feedback"] += int(after)
            executed = any(getattr(item, "executed", False) for item in observed.values())
            verified = any(getattr(item, "verified", False) for item in observed.values())
            result["checks"] = {
                "static_candidate": "emitted" if vuln_hit else "absent",
                "sequence": "refused" if refused else "generated",
                "oracle": (
                    "none"
                    if refused or vulnerable_obs is None
                    else str(getattr(vulnerable_obs, "oracle_kind", ""))
                ),
                "harness": (
                    "not_built"
                    if refused or vulnerable_obs is None or vulnerable_obs.harness is None
                    else "built"
                    if vulnerable_obs.harness.buildable
                    else "failed"
                ),
                "foundry": "executed" if executed else "not_executed",
                "outcome": "matched" if agreed else "differed",
                "classification": result["vulnerability_label"],
                "persisted": "not_applicable",
                "overstated": verified,
            }
            unavailable = any(v in {"unavailable"} for v in outcomes.values())
            if unavailable:
                stateful["not_run"] += 1
            elif agreed:
                stateful["agree"] += 1
            else:
                stateful["disagree"] += 1
        elif expected:
            stateful["not_run"] += 1
            if kind == "hypothesis":
                hypotheses["execution_not_run"] += 1
        if case.get("known_limitation"):
            result["known_limitation"] = str(case["known_limitation"])
        cases.append(result)
    judged = totals["tp"] + totals["fp"]
    report = {
        "schema": BENCHMARK_SCHEMA,
        "cases": cases,
        "totals": totals,
        "fixture_precision": (totals["tp"] / judged) if judged else None,
        "fixture_recall": (
            totals["tp"] / (totals["tp"] + totals["fn"]) if (totals["tp"] + totals["fn"]) else None
        ),
        "stateful": stateful,
        "hypotheses": hypotheses,
        "execution_funnel": funnel,
        "feedback": feedback_totals,
        "identity_validation": identity_validation,
        "disclaimer": DISCLAIMER,
        "emission_is_not_vulnerability_precision": True,
        "real_world_rate": None,
        "verified": False,
    }
    report["digest"] = digest(
        {
            "cases": [
                {
                    "id": case["id"],
                    "kind": case["kind"],
                    "static": case["static"],
                    "vulnerable_fires": case["vulnerable_fires"],
                    "safe_fires": case["safe_fires"],
                    "execution": case["execution"],
                    "vulnerability_label": case["vulnerability_label"],
                    "ground_truth": case["ground_truth"],
                    "stateful": case.get("stateful"),
                    "feedback": case.get("feedback"),
                    "feedback_variants": [
                        (item["role"], item["origin"], item["outcome"])
                        for item in case.get("feedback_variants", [])
                    ],
                    "identity_rejection": case.get("identity_rejection"),
                }
                for case in cases
            ],
            "totals": totals,
            "stateful": stateful,
            "hypotheses": hypotheses,
            "execution_funnel": funnel,
            "feedback": feedback_totals,
            "identity_validation": identity_validation,
            "fixture_precision": report["fixture_precision"],
            "fixture_recall": report["fixture_recall"],
            "real_world_rate": None,
            "verified": False,
        }
    )
    return report


_JUDGED = frozenset({"property_violated", "property_held"})


def _feedback_totals() -> dict[str, Any]:
    roles = {
        role: {
            "variants_generated": 0,
            "variants_executed": 0,
            "variants_violated": 0,
            "variants_held": 0,
            "variants_compiled_inconclusive": 0,
            "variants_not_executed": 0,
        }
        for role in ("vulnerable", "safe")
    }
    return {
        "variants_generated": 0,
        "variants_executed": 0,
        "variants_judged": 0,
        "variants_compiled_inconclusive": 0,
        "variants_not_executed": 0,
        "by_role": roles,
        "cases_executed": 0,
        "cases_with_violating_variant": {"vulnerable": 0, "safe": 0},
        "cases_distinguished_before_feedback": 0,
        "cases_distinguished_after_feedback": 0,
        "cases_changed": 0,
        "note": (
            "variant counts and case counts use different denominators; a variant that did "
            "not execute or was not judged is not counted as held or as a negative"
        ),
    }


def _variant_record(role: str, child: Any, obs: Any) -> dict[str, Any]:
    outcome = obs.outcome.value
    result = getattr(obs, "result", None)
    ran = result is not None and getattr(result, "test_status", "not_run") != "not_run"
    if outcome in _JUDGED:
        status = "judged"
    elif ran:
        status = "compiled_inconclusive"
    else:
        status = "not_executed"
    return {
        "role": role,
        "sequence_id": child.sequence_id,
        "origin": child.origin,
        "outcome": outcome,
        "status": status,
        "reason_code": getattr(obs, "reason_code", "") or outcome,
    }


def _feedback_outcome(records: list[dict[str, Any]]) -> str:
    outcomes = [item["outcome"] for item in records]
    if "property_violated" in outcomes:
        return "property_violated"
    if "property_held" in outcomes:
        return "property_held"
    return outcomes[0] if outcomes else "no_variant"


def _count_variants(totals: dict[str, Any], role: str, records: list[dict[str, Any]]) -> None:
    per = totals["by_role"][role]
    for item in records:
        totals["variants_generated"] += 1
        per["variants_generated"] += 1
        if item["status"] == "not_executed":
            totals["variants_not_executed"] += 1
            per["variants_not_executed"] += 1
            continue
        totals["variants_executed"] += 1
        per["variants_executed"] += 1
        if item["status"] == "compiled_inconclusive":
            totals["variants_compiled_inconclusive"] += 1
            per["variants_compiled_inconclusive"] += 1
            continue
        totals["variants_judged"] += 1
        key = "variants_violated" if item["outcome"] == "property_violated" else "variants_held"
        per[key] += 1


def pipeline_coverage_matrix(directory: Path | None = None) -> dict[str, Any]:
    """Registry-derived view of which detectors have fixtures and executable oracles.

    Untested cells stay ``untested``. This does not run Foundry and does not turn
    a fixture into a passing execution result.
    """
    from app.discovery.bounty.properties import _ORACLE_BUILDERS
    from app.discovery.bounty.vfcs import _BUILDERS

    cases: list[dict[str, Any]] = []
    if directory is not None and (directory / "benchmark.json").is_file():
        spec = json.loads((directory / "benchmark.json").read_text(encoding="utf-8"))
        cases = list(spec.get("cases", []))
    by_detector = {str(case.get("detector")): case for case in cases}
    rows = []
    for detector in sorted(_BUILDERS):
        case = by_detector.get(detector)
        stateful = bool(case and case.get("stateful"))
        rows.append(
            {
                "detector": detector,
                "registered": True,
                "sequence_builder": True,
                "positive_fixture": "present" if case else "untested",
                "safe_control": "present" if case else "untested",
                "oracle_expected": "specified" if stateful else "untested",
                "foundry_execution": "untested",
                "persistence": "untested",
                "qualification": "untested",
            }
        )
    return {
        "rows": rows,
        "oracle_templates": sorted(_ORACLE_BUILDERS),
        "builders_without_fixture": [
            row["detector"] for row in rows if row["positive_fixture"] == "untested"
        ],
        "note": (
            "foundry_execution, persistence, and qualification stay untested in this "
            "view; a present fixture is not an execution result and not a vulnerability"
        ),
        "verified": False,
    }
