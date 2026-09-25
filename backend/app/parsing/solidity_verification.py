"""Verification bridge for Solidity candidate paths.

This layer consumes state-transition candidates. It does not replace them.
``unknown``, ``timeout``, ``unavailable``, and a passing fuzz campaign are not
safety. ``proved_safe`` is a parsed tool result about a generated harness.
``reproduced`` requires execution output. Neither status verifies a finding
by itself.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from app.domain.evidence import Evidence, EvidenceKind
from app.parsing.solidity_ir import SemanticProgram
from app.parsing.solidity_state_transitions import (
    CandidatePath,
    TransitionModel,
    analyze_state_transitions,
)

Runner = Callable[[str], tuple[int, str, str]]

_GENERATED = "BUGFORGE GENERATED VERIFICATION HARNESS — not production source"
_SMT_VIOLATION = re.compile(r"assertion violation|counterexample", re.IGNORECASE)
_SMT_TIMEOUT = re.compile(r"time-?out|timed out|out of resources", re.IGNORECASE)
_SMT_UNSUPPORTED = re.compile(r"unsupported|not yet implemented|cannot handle", re.IGNORECASE)
_SMT_PROVED = re.compile(r"\bproved\b|verified successfully", re.IGNORECASE)
_FORGE_FAIL = re.compile(r"\[FAIL|Suite result: FAILED|Test result: FAILED", re.IGNORECASE)
_FORGE_OK = re.compile(r"Suite result: ok|Test result: ok", re.IGNORECASE)


@dataclass(frozen=True)
class VerificationRequest:
    verification_id: str
    property_id: str
    invariant_id: str
    path_id: str
    contract: str
    function_id: str
    state_variables: tuple[str, ...]
    preconditions: tuple[str, ...]
    postcondition: str
    path_conditions: tuple[str, ...]
    assumptions: tuple[str, ...]
    compiler_config: str
    tool: str = ""
    tool_version: str = ""
    encoded: bool = False


@dataclass(frozen=True)
class Counterexample:
    verification_id: str
    status: str
    initial_state: tuple[str, ...]
    actors: tuple[str, ...]
    calldata: tuple[str, ...]
    transactions: tuple[str, ...]
    state_deltas: tuple[str, ...]
    failing_property: str
    locations: tuple[str, ...]
    tool: str
    raw_artifact: str


@dataclass(frozen=True)
class VerificationResult:
    request_id: str
    status: str
    counterexample: Counterexample | None
    diagnostics: tuple[str, ...]
    artifacts: tuple[str, ...]
    completeness: str
    confidence: str
    tool: str = ""
    tool_version: str = ""


@dataclass(frozen=True)
class BridgeResult:
    requests: tuple[VerificationRequest, ...]
    results: tuple[VerificationResult, ...]
    tools: dict[str, str]


def tool_availability() -> dict[str, str]:
    """Paths of optional tools. An empty string means the tool is absent."""
    return {
        "solc": shutil.which("solc") or "",
        "forge": shutil.which("forge") or "",
        "semgrep": shutil.which("semgrep") or "",
    }


def tool_version(name: str) -> str:
    binary = shutil.which(name)
    if not binary:
        return ""
    try:
        completed = subprocess.run(
            [binary, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    line = (completed.stdout or completed.stderr or "").strip().splitlines()
    return line[0][:160] if line else ""


def bridge(program: SemanticProgram, model: TransitionModel | None = None) -> BridgeResult:
    """Queue candidate paths. Nothing is verified by building the queue."""
    transition_model = model or analyze_state_transitions(program)
    requests = tuple(
        request_for(path, transition_model)
        for path in transition_model.paths
        if path.status == "candidate"
    )
    results = tuple(_not_requested(item) for item in requests)
    return BridgeResult(requests, results, tool_availability())


def request_for(path: CandidatePath, model: TransitionModel) -> VerificationRequest:
    variables = next(
        (
            item.state_variables
            for item in model.invariants
            if item.invariant_id and item.invariant_id == path.invariant_id
        ),
        (),
    )
    return VerificationRequest(
        f"ver:{path.path_id}",
        path.invariant_id or path.path_id,
        path.invariant_id,
        path.path_id,
        path.contract_ids[0] if path.contract_ids else "",
        path.function_ids[0] if path.function_ids else "",
        variables,
        path.conditions,
        path.reason,
        path.conditions,
        path.assumptions,
        model.compiler_version or "unspecified",
    )


def smt_harness(request: VerificationRequest, source: str) -> str:
    """Return a new harness string. The target source is not rewritten in place."""
    property_name = re.sub(r"[^A-Za-z0-9_]", "_", request.property_id)[:80] or "property"
    banner = f"// {_GENERATED}\n// property-id: {request.property_id}\n"
    stub = (
        f"contract BugforgeHarness_{property_name} {{\n"
        f"    // postcondition: {request.postcondition[:160]}\n"
        "    function bugforge_property() external pure {\n"
        "        // The generated predicate is not part of the production contract.\n"
        "        assert(true);\n"
        "    }\n"
        "}\n"
    )
    return banner + source + "\n" + stub


def forge_harness(request: VerificationRequest) -> str:
    """A Foundry test skeleton. It is testing evidence, not a proof."""
    property_name = re.sub(r"[^A-Za-z0-9_]", "_", request.path_id)[:80] or "path"
    sequence = ", ".join(request.path_conditions) or "none"
    return (
        f"// {_GENERATED}\n"
        "// SPDX-License-Identifier: UNLICENSED\n"
        "pragma solidity ^0.8.20;\n"
        'import {Test} from "forge-std/Test.sol";\n'
        f"contract Bugforge_{property_name} is Test {{\n"
        f"    // path: {request.path_id}\n"
        f"    // conditions: {sequence[:200]}\n"
        "    function test_candidate_sequence() external {\n"
        "        // Replay is filled by the caller. A passing run is not a proof.\n"
        "        assertTrue(true);\n"
        "    }\n"
        "}\n"
    )


def run_smt(
    request: VerificationRequest,
    source: str,
    *,
    runner: Runner | None = None,
    harness: str | None = None,
) -> VerificationResult:
    if harness is None:
        harness = smt_harness(request, source)
        request = replace(request, encoded=False)
    if _GENERATED not in harness:
        return _result(request, "failed", ("harness was not marked as generated",), tool="smt")
    if runner is None:
        if not shutil.which("solc"):
            return _result(
                request,
                "unavailable",
                ("solc is not installed",),
                tool="smt",
            )
        runner = _solc_runner
    try:
        code, stdout, stderr = runner(harness)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _result(
            request, "failed", (str(exc)[:240],), tool="smt", version=tool_version("solc")
        )
    status = parse_smt_output(str(stdout), str(stderr), int(code))
    raw = f"{stdout}\n{stderr}".strip()
    status, note = _bind_encoding(request, status)
    example = (
        normalize_counterexample(request.verification_id, status, "smt", raw)
        if status == "counterexample"
        else None
    )
    diagnostics: tuple[str, ...] = (note,) if note else ()
    if raw:
        diagnostics = (*diagnostics, raw[:500])
    else:
        diagnostics = (*diagnostics, "tool produced no SMTChecker result")
    return _result(
        request,
        status,
        diagnostics,
        tool="smt",
        version=tool_version("solc"),
        counterexample=example,
        artifacts=(harness[:200],),
    )


def run_forge(
    request: VerificationRequest,
    *,
    runner: Runner | None = None,
) -> VerificationResult:
    harness = forge_harness(request)
    if runner is None:
        if not shutil.which("forge"):
            return _result(request, "unavailable", ("forge is not installed",), tool="forge")
        runner = _forge_runner
    try:
        code, stdout, stderr = runner(harness)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _result(
            request, "failed", (str(exc)[:240],), tool="forge", version=tool_version("forge")
        )
    raw = f"{stdout}\n{stderr}".strip()
    status = parse_forge_output(raw, int(code))
    status, note = _bind_encoding(request, status)
    example = None
    if status in {"reproduced", "counterexample"}:
        example = normalize_counterexample(request.verification_id, status, "forge", raw)
    diagnostic = raw[:500] if raw else "forge produced no output"
    if status == "unknown" and _FORGE_OK.search(raw):
        diagnostic = "forge reported success; a passing run is not a proof"
    if note:
        diagnostic = f"{note} {diagnostic}".strip()
    return _result(
        request,
        status,
        (diagnostic,),
        tool="forge",
        version=tool_version("forge"),
        counterexample=example,
    )


def parse_smt_output(stdout: str, stderr: str = "", returncode: int = 0) -> str:
    """Map compiler text to a status. Exit code 0 alone is not a proof."""
    del returncode
    text = f"{stdout}\n{stderr}"
    if not text.strip():
        return "unknown"
    if _SMT_VIOLATION.search(text):
        return "counterexample"
    if _SMT_TIMEOUT.search(text):
        return "timeout"
    if _SMT_UNSUPPORTED.search(text):
        return "unsupported"
    if re.search(r"Error:", text) and "SMT" not in text and "assertion" not in text.lower():
        return "failed"
    if _SMT_PROVED.search(text):
        return "proved_safe"
    return "unknown"


def parse_forge_output(text: str, returncode: int = 0) -> str:
    del returncode
    if not text.strip():
        return "unknown"
    if re.search(r"time-?out|timed out", text, re.IGNORECASE):
        return "timeout"
    if _FORGE_FAIL.search(text):
        return "reproduced"
    if re.search(r"Compiler run failed|Error \(", text):
        return "failed"
    if _FORGE_OK.search(text):
        return "unknown"
    return "unknown"


def normalize_counterexample(
    verification_id: str, status: str, tool: str, raw: str
) -> Counterexample:
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    transactions = tuple(
        line for line in lines if re.search(r"\b(call|invoke|FAIL)\b", line, re.IGNORECASE)
    )[:16]
    actors = tuple(line for line in lines if "sender" in line.lower())[:8]
    locations = tuple(line for line in lines if ".sol" in line)[:8]
    return Counterexample(
        verification_id,
        status,
        (),
        actors,
        (),
        transactions,
        (),
        "",
        locations,
        tool,
        raw,
    )


def evidence_for(result: VerificationResult) -> Evidence:
    """Evidence whose kind matches the tool result. It does not verify a finding."""
    if (
        result.status == "reproduced"
        and result.counterexample
        and result.counterexample.raw_artifact.strip()
    ):
        return Evidence(
            kind=EvidenceKind.REPRODUCTION,
            source=result.tool or "forge",
            summary=f"Harness reproduction {result.request_id}",
            details=result.counterexample.raw_artifact[:2000],
            metadata={
                "outcome": "reproduced",
                "verification_status": "reproduced",
                "verification_id": result.request_id,
                "tool": result.tool,
                "tool_version": result.tool_version,
            },
        )
    if result.status in {"proved_safe", "counterexample"}:
        return Evidence(
            kind=EvidenceKind.STATIC_ANALYSIS,
            source=result.tool or "smt",
            summary=f"Tool {result.status} for {result.request_id}",
            details="\n".join(result.diagnostics)[:2000],
            metadata={
                "verification_status": result.status,
                "verification_id": result.request_id,
                "tool": result.tool,
                "tool_version": result.tool_version,
            },
        )
    return Evidence(
        kind=EvidenceKind.TOOL_STATUS,
        source=result.tool or "verification",
        summary=f"Verification {result.status} for {result.request_id}",
        details="\n".join(result.diagnostics)[:2000],
        metadata={
            "verification_status": result.status,
            "verification_id": result.request_id,
            "tool": result.tool,
            "tool_version": result.tool_version,
        },
    )


def _bind_encoding(request: VerificationRequest, status: str) -> tuple[str, str]:
    """A tool result counts only when the harness encodes the candidate."""
    if request.encoded or status not in {"proved_safe", "counterexample", "reproduced"}:
        return status, ""
    return (
        "unknown",
        f"tool status {status} is not bound to an encoded property",
    )


def lifecycle_effect(result: VerificationResult) -> str:
    """Verification results do not move a finding by themselves."""
    del result
    return "none"


def _not_requested(request: VerificationRequest) -> VerificationResult:
    return _result(request, "not_requested", ("verification was not run",))


def _result(
    request: VerificationRequest,
    status: str,
    diagnostics: tuple[str, ...],
    *,
    tool: str = "",
    version: str = "",
    counterexample: Counterexample | None = None,
    artifacts: tuple[str, ...] = (),
) -> VerificationResult:
    completeness = (
        "complete" if status in {"proved_safe", "counterexample", "reproduced"} else "incomplete"
    )
    confidence = "tool" if status in {"proved_safe", "counterexample", "reproduced"} else "none"
    return VerificationResult(
        request.verification_id,
        status,
        counterexample,
        diagnostics,
        artifacts,
        completeness,
        confidence,
        tool,
        version,
    )


def _solc_runner(harness: str) -> tuple[int, str, str]:
    binary = shutil.which("solc")
    if not binary:
        return 127, "", "solc is not installed"
    with tempfile.TemporaryDirectory(prefix="bugforge-smt-") as directory:
        path = Path(directory) / "Harness.sol"
        path.write_text(harness, encoding="utf-8")
        completed = subprocess.run(
            [binary, "--model-checker-engine", "all", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    return completed.returncode, completed.stdout or "", completed.stderr or ""


def _forge_runner(harness: str) -> tuple[int, str, str]:
    binary = shutil.which("forge")
    if not binary:
        return 127, "", "forge is not installed"
    with tempfile.TemporaryDirectory(prefix="bugforge-forge-") as directory:
        path = Path(directory) / "Bugforge.t.sol"
        path.write_text(harness, encoding="utf-8")
        completed = subprocess.run(
            [binary, "test", "--match-path", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    return completed.returncode, completed.stdout or "", completed.stderr or ""
