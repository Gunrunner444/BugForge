"""Run the Foundry plan once and judge it in Python and in the EVM.

The in-EVM judge is the generated ``_bfJudged`` / ``_bfViolated`` pair. The Python
judge is ``evaluate`` on the observations that same execution stored. Neither
verdict is copied from the other.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from app.discovery.bounty.engine_adapters import (
    ENGINE_CONTRACT,
    FLAG_RAN,
    FLAG_UNJUDGED,
    FLAG_VIOLATED,
    FLAGS,
    engine_harness_source,
    verdict_from_flags,
)
from app.discovery.bounty.properties import evaluate
from app.discovery.bounty.stateful import (
    HARNESS_ADDRESS,
    Outcome,
    StatefulObservation,
    decode_events,
    foundry_config,
    harness_test,
    observation_from_events,
    parse_forge_report,
    scaffold,
    tool_status,
)
from app.discovery.bounty.vfcs import Vfcs
from app.discovery.process import tool_path

_FLAG_KIND = {90: FLAG_RAN, 91: FLAG_UNJUDGED, 92: FLAG_VIOLATED}


def _instrument(source: str) -> str:
    """Host the engine harness as the Foundry test without changing the judge."""
    source = source.replace(f"contract {ENGINE_CONTRACT}", "contract VfcsHarness", 1)
    source = source.replace('import "./src/', 'import "src/')
    source = source.replace(
        "bool internal bfRan;",
        "event BugForgeObservation(uint256 kind, uint256 index, uint256 value);\n"
        "    bool internal bfRan;",
        1,
    )
    source = source.replace(
        "bfSeen[kind][index] = true;",
        "bfSeen[kind][index] = true;\n        emit BugForgeObservation(kind, index, value);",
        1,
    )
    runner = """
    function test_vfcs_execute() public {
        bf_run();
        emit BugForgeObservation(90, 0, echidna_bf_flag_ran() ? 1 : 0);
        emit BugForgeObservation(91, 0, echidna_bf_flag_unjudged() ? 1 : 0);
        emit BugForgeObservation(92, 0, echidna_bf_flag_violated() ? 1 : 0);
    }

"""
    return source.replace(
        "function bf_run() public {", runner + "    function bf_run() public {", 1
    )


def compare_judges(
    observation: StatefulObservation,
    sequence: Vfcs,
    sources: dict[str, str],
) -> dict[str, Any]:
    """Execute the engine harness of this plan and compare it with Python.

    ``observation`` is the production Foundry run. The engine run is the same
    plan, and the Python verdict below is computed from that engine run's events.
    """
    harness = observation.harness
    if harness is None or not harness.buildable:
        return {
            "supported": False,
            "reason": "the production harness was not built",
            "production": observation.verdict,
        }
    engine = engine_harness_source(harness, sequence)
    if not engine:
        return {
            "supported": False,
            "reason": "the in-EVM judge cannot express this oracle",
            "production": observation.verdict,
            "production_outcome": observation.outcome.value,
        }
    solc = tool_path("solc") or ""
    forge = tool_path("forge") or shutil.which("forge") or ""
    with tempfile.TemporaryDirectory(prefix="bf-judge-") as tmp:
        root = Path(tmp)
        scaffold(root, sources, _instrument(engine), foundry_config("default", solc))
        proc = subprocess.run(
            [forge, "test", "--offline", "--json", "-vv", "--match-path", "test/VfcsHarness.t.sol"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            env={
                "PATH": __import__("os").environ.get("PATH", ""),
                "HOME": str(root),
                "FOUNDRY_OFFLINE": "true",
                "FOUNDRY_FFI": "false",
            },
        )
    report = parse_forge_report(proc.stdout)
    test = harness_test(report) if report is not None else None
    if test is None or str(test.get("status")) != "Success":
        tail = (proc.stderr or proc.stdout)[-1500:]
        return {
            "supported": True,
            "compiled": False,
            "reason": f"the differential harness did not pass: {tail}",
            "production": observation.verdict,
        }
    events = decode_events(test)
    flags = {
        _FLAG_KIND[kind]: ("failed" if value == 0 else "passed")
        for kind, _index, value in events
        if kind in _FLAG_KIND
    }
    measured = tuple(item for item in events if item[0] not in _FLAG_KIND)
    evm_outcome, evm_verdict, evm_reason = verdict_from_flags(flags)
    oracle_observation, _deployed, _done = observation_from_events(measured, len(sequence.calls))
    python = evaluate(sequence, harness.oracle, oracle_observation)
    return {
        "supported": True,
        "compiled": True,
        "emitter": HARNESS_ADDRESS,
        "production_outcome": observation.outcome.value,
        "production_verdict": observation.verdict,
        "python_verdict": python.verdict.value,
        "python_reason": python.reason,
        "python_evaluated": python.evaluated,
        "evm_outcome": evm_outcome.value,
        "evm_verdict": evm_verdict,
        "evm_reason": evm_reason,
        "flags": flags,
        "flag_names": FLAGS,
        "tools": tool_status().as_dict(),
    }


def verdict_class(value: str) -> str:
    """Collapse a verdict to held, violated, or not-evaluated."""
    if value in {Outcome.PROPERTY_HELD.value, "property_held"}:
        return "held"
    if value in {Outcome.PROPERTY_VIOLATED.value, "property_violated"}:
        return "violated"
    return "not_evaluated"
