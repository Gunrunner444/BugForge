"""Local regression benchmark over compact incident-class fixtures (Phase 52, Slice D).

Each case is a vulnerable fixture and its safe twin, the detector that should fire
on the first and not on the second, and optionally the stateful outcome its property
should reach on each (the safe twin runs the *same* sequence, rebuilt from the
vulnerable candidate, against the fixed code). Everything is local: fixtures are read
from a directory on disk; nothing is downloaded.

The report is a regression signal for these fixtures only. It is **not** a real-world
detection rate and must never be presented as one.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from app.discovery.bounty.properties import build_property
from app.discovery.bounty.vfcs import generate
from app.discovery.orchestration.codec import digest
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite

BENCHMARK_SCHEMA = "bugforge.local_benchmark/1"
DISCLAIMER = (
    "local fixture regression only: these compact reconstructions measure BugForge "
    "against itself; this is not a real-world detection rate"
)
MAX_CASES = 64


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
    stateful = {"agree": 0, "disagree": 0, "not_run": 0}
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
        totals["tp" if vuln_hit else "fn"] += 1
        totals["fp" if safe_hit else "tn"] += 1
        result: dict[str, Any] = {
            "id": case["id"],
            "detector": detector,
            "vulnerable_fires": vuln_hit,
            "safe_fires": safe_hit,
            "static": "pass" if vuln_hit and not safe_hit else "fail",
        }
        expected = dict(case.get("stateful") or {})
        if expected and executor is not None and candidate is not None:
            outcomes: dict[str, str] = {}
            for role, model, text, path in (
                ("vulnerable", vuln_model, texts["vulnerable"], files["vulnerable"]),
                ("safe", safe_model, texts["safe"], files["safe"]),
            ):
                twin = replace(candidate, file=path.name)
                built = generate(model, [twin])
                if not built.sequences:
                    outcomes[role] = "no_sequence"
                    continue
                sequence = built.sequences[0]
                spec_ = build_property(sequence, model, twin)
                obs = executor.execute(sequence, model, {path.name: text}, spec=spec_)
                outcomes[role] = obs.outcome.value
            result["stateful"] = outcomes
            result["stateful_expected"] = expected
            agreed = all(outcomes.get(role) == want for role, want in expected.items())
            unavailable = any(v in {"unavailable"} for v in outcomes.values())
            if unavailable:
                stateful["not_run"] += 1
            elif agreed:
                stateful["agree"] += 1
            else:
                stateful["disagree"] += 1
        elif expected:
            stateful["not_run"] += 1
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
        "disclaimer": DISCLAIMER,
        "real_world_rate": None,
        "verified": False,
    }
    report["digest"] = digest({"cases": cases, "totals": totals})
    return report
