"""Optional external discovery tools. Missing executables do not invent results."""

from __future__ import annotations

import json
from pathlib import Path

from app.discovery.capabilities import EngineAvailability, EngineCapability, ResultStatus
from app.discovery.engine import AnalysisRequest, DiscoveryEngine
from app.discovery.process import run_command, tool_path, tool_version
from app.discovery.results import DynamicFinding, DynamicResult, unavailable_result


class ExternalDiscoveryEngine(DiscoveryEngine):
    binary: str = ""
    license_note: str = ""

    def availability(self) -> EngineAvailability:
        if tool_path(self.binary):
            return EngineAvailability.AVAILABLE
        return EngineAvailability.UNAVAILABLE

    def version(self) -> str:
        return tool_version(self.binary)

    def _unavailable(self, request: AnalysisRequest) -> DynamicResult:
        return unavailable_result(
            self.engine_id,
            request.language,
            request.target,
            reason=f"{self.display_name} executable {self.binary!r} is not installed",
        )


class SlitherEngine(ExternalDiscoveryEngine):
    binary = "slither"
    license_note = "AGPLv3 external executable; source is not vendored"

    @property
    def engine_id(self) -> str:
        return "slither"

    @property
    def display_name(self) -> str:
        return "Slither"

    @property
    def supported_languages(self) -> frozenset[str]:
        return frozenset({"solidity"})

    def capabilities(self) -> frozenset[EngineCapability]:
        return frozenset({EngineCapability.STATIC_ANALYSIS, EngineCapability.RESULTS_INGESTION})

    def _analyze_target(self, request: AnalysisRequest) -> DynamicResult:
        if self.availability() is not EngineAvailability.AVAILABLE:
            return self._unavailable(request)
        code, stdout, stderr, timed_out = run_command(
            ["slither", ".", "--json", "-"],
            cwd=request.repo_root,
            timeout=60,
        )
        findings = normalize_slither(stdout)
        return DynamicResult(
            engine=self.engine_id,
            engine_version=self.version(),
            language=request.language,
            target=request.target or str(request.repo_root),
            status=ResultStatus.FAILED if timed_out else ResultStatus.INGESTED,
            executed=True,
            exit_code=code,
            stdout=stdout[:4000],
            stderr=stderr[:2000],
            findings=tuple(findings),
            provenance="slither",
            metadata={"license": self.license_note, "verified": "false"},
        )

    def _collect_results(self, request: AnalysisRequest) -> DynamicResult:
        raw = request.extra.get("slither_json", "")
        if not raw:
            return self._analyze_target(request)
        findings = normalize_slither(raw)
        return DynamicResult(
            engine=self.engine_id,
            language=request.language,
            target=request.target,
            status=ResultStatus.INGESTED,
            executed=False,
            findings=tuple(findings),
            provenance="slither_json",
            oracle_explanation="Ingested caller-supplied Slither JSON. The tool was not executed.",
        )


class FoundryEngine(ExternalDiscoveryEngine):
    binary = "forge"
    license_note = "MIT/Apache external Foundry executable"

    @property
    def engine_id(self) -> str:
        return "foundry"

    @property
    def display_name(self) -> str:
        return "Foundry"

    @property
    def supported_languages(self) -> frozenset[str]:
        return frozenset({"solidity"})

    def capabilities(self) -> frozenset[EngineCapability]:
        caps = {
            EngineCapability.BUILD,
            EngineCapability.TEST_EXECUTION,
            EngineCapability.FUZZING,
            EngineCapability.INVARIANT_TESTING,
            EngineCapability.RESULTS_INGESTION,
        }
        if tool_path("anvil"):
            caps.add(EngineCapability.PLANNING_ONLY)
        return frozenset(caps)

    def _start_campaign(self, request: AnalysisRequest) -> DynamicResult:
        if self.availability() is not EngineAvailability.AVAILABLE:
            return self._unavailable(request)
        if _rejects_fork(request):
            return DynamicResult(
                engine=self.engine_id,
                language=request.language,
                target=request.target,
                status=ResultStatus.FAILED,
                executed=False,
                provenance="scope",
                oracle_explanation="Live or forked network execution is not started from this adapter.",
            )
        argv = ["forge", "test"]
        if request.match_test:
            argv.extend(["--match-test", request.match_test])
        code, stdout, stderr, timed_out = run_command(argv, cwd=request.repo_root, timeout=90)
        failed = "FAIL" in stdout or (code not in {0, None} and not timed_out)
        return DynamicResult(
            engine=self.engine_id,
            engine_version=self.version(),
            language=request.language,
            target=request.target,
            status=ResultStatus.FAILED if timed_out else ResultStatus.EXECUTED,
            executed=True,
            exit_code=code,
            stdout=stdout[:4000],
            stderr=stderr[:2000],
            assertion="forge reported a failing test" if failed and code not in {0, None} else "",
            reproduction_command=" ".join(argv),
            provenance="foundry",
            metadata={"fork": "false", "verified": "false"},
        )


class EchidnaEngine(ExternalDiscoveryEngine):
    binary = "echidna"
    license_note = "AGPL external executable; source is not vendored"

    @property
    def engine_id(self) -> str:
        return "echidna"

    @property
    def display_name(self) -> str:
        return "Echidna"

    @property
    def supported_languages(self) -> frozenset[str]:
        return frozenset({"solidity"})

    def capabilities(self) -> frozenset[EngineCapability]:
        return frozenset(
            {
                EngineCapability.PROPERTY_TESTING,
                EngineCapability.FUZZING,
                EngineCapability.RESULTS_INGESTION,
            }
        )

    def _start_campaign(self, request: AnalysisRequest) -> DynamicResult:
        if self.availability() is not EngineAvailability.AVAILABLE:
            return self._unavailable(request)
        target = request.source_file or request.target
        if not target:
            return DynamicResult(
                engine=self.engine_id,
                language=request.language,
                target="",
                status=ResultStatus.NOT_IMPLEMENTED,
                executed=False,
                oracle_explanation="Echidna needs a contract file or config.",
            )
        code, stdout, stderr, timed_out = run_command(
            ["echidna", target, "--format", "text"],
            cwd=request.repo_root,
            timeout=60,
        )
        falsified = "falsified" in (stdout + stderr).lower()
        return DynamicResult(
            engine=self.engine_id,
            engine_version=self.version(),
            language=request.language,
            target=target,
            status=ResultStatus.FAILED if timed_out else ResultStatus.EXECUTED,
            executed=True,
            exit_code=code,
            stdout=stdout[:4000],
            stderr=stderr[:2000],
            assertion="property falsified" if falsified else "",
            provenance="echidna",
            metadata={"verified": "false"},
        )


class MedusaEngine(ExternalDiscoveryEngine):
    binary = "medusa"
    license_note = "AGPL external executable; source is not vendored"

    @property
    def engine_id(self) -> str:
        return "medusa"

    @property
    def display_name(self) -> str:
        return "Medusa"

    @property
    def supported_languages(self) -> frozenset[str]:
        return frozenset({"solidity"})

    def capabilities(self) -> frozenset[EngineCapability]:
        return frozenset(
            {
                EngineCapability.FUZZING,
                EngineCapability.COVERAGE_FEEDBACK,
                EngineCapability.PROPERTY_TESTING,
                EngineCapability.RESULTS_INGESTION,
            }
        )

    def _start_campaign(self, request: AnalysisRequest) -> DynamicResult:
        if self.availability() is not EngineAvailability.AVAILABLE:
            return self._unavailable(request)
        code, stdout, stderr, timed_out = run_command(
            ["medusa", "fuzz"], cwd=request.repo_root, timeout=60
        )
        return DynamicResult(
            engine=self.engine_id,
            engine_version=self.version(),
            language=request.language,
            target=request.target,
            status=ResultStatus.FAILED if timed_out else ResultStatus.EXECUTED,
            executed=True,
            exit_code=code,
            stdout=stdout[:4000],
            stderr=stderr[:2000],
            assertion="assertion failed" if "failed" in stdout.lower() else "",
            provenance="medusa",
            metadata={"verified": "false"},
        )


class HalmosEngine(ExternalDiscoveryEngine):
    binary = "halmos"
    license_note = "External symbolic testing executable"

    @property
    def engine_id(self) -> str:
        return "halmos"

    @property
    def display_name(self) -> str:
        return "Halmos"

    @property
    def supported_languages(self) -> frozenset[str]:
        return frozenset({"solidity"})

    def capabilities(self) -> frozenset[EngineCapability]:
        return frozenset({EngineCapability.SYMBOLIC_EXECUTION, EngineCapability.RESULTS_INGESTION})

    def _start_campaign(self, request: AnalysisRequest) -> DynamicResult:
        if not request.difficult:
            return DynamicResult(
                engine=self.engine_id,
                language=request.language,
                target=request.target,
                status=ResultStatus.PLANNED,
                executed=False,
                oracle_explanation="Halmos runs only for a target marked difficult to reach.",
            )
        if self.availability() is not EngineAvailability.AVAILABLE:
            return self._unavailable(request)
        argv = ["halmos"]
        if request.match_test:
            argv.extend(["--match-test", request.match_test])
        code, stdout, stderr, timed_out = run_command(argv, cwd=request.repo_root, timeout=90)
        counterexample = "Counterexample" in stdout
        return DynamicResult(
            engine=self.engine_id,
            engine_version=self.version(),
            language=request.language,
            target=request.target,
            function=request.function,
            source_file=request.source_file,
            status=ResultStatus.FAILED if timed_out else ResultStatus.EXECUTED,
            executed=True,
            exit_code=code,
            stdout=stdout[:4000],
            stderr=stderr[:2000],
            minimized_input=stdout[:500] if counterexample else "",
            provenance="halmos",
            metadata={"seed_source": "symbolic" if counterexample else "", "verified": "false"},
        )


class WakeEngine(ExternalDiscoveryEngine):
    binary = "wake"
    license_note = "ISC external executable; BugForge does not depend on Wake"

    @property
    def engine_id(self) -> str:
        return "wake"

    @property
    def display_name(self) -> str:
        return "Wake"

    @property
    def supported_languages(self) -> frozenset[str]:
        return frozenset({"solidity"})

    def capabilities(self) -> frozenset[EngineCapability]:
        return frozenset({EngineCapability.STATIC_ANALYSIS, EngineCapability.RESULTS_INGESTION})

    def _analyze_target(self, request: AnalysisRequest) -> DynamicResult:
        if self.availability() is not EngineAvailability.AVAILABLE:
            return self._unavailable(request)
        code, stdout, stderr, timed_out = run_command(
            ["wake", "detect"], cwd=request.repo_root, timeout=60
        )
        return DynamicResult(
            engine=self.engine_id,
            engine_version=self.version(),
            language=request.language,
            target=request.target,
            status=ResultStatus.FAILED if timed_out else ResultStatus.EXECUTED,
            executed=True,
            exit_code=code,
            stdout=stdout[:4000],
            stderr=stderr[:2000],
            provenance="wake",
            metadata={"license": self.license_note, "verified": "false"},
        )


def normalize_slither(payload: str) -> list[DynamicFinding]:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return []
    detectors = data.get("results", {}).get("detectors", []) if isinstance(data, dict) else []
    findings: list[DynamicFinding] = []
    if not isinstance(detectors, list):
        return []
    for item in detectors:
        if not isinstance(item, dict):
            continue
        elements = item.get("elements") if isinstance(item.get("elements"), list) else []
        first = elements[0] if elements and isinstance(elements[0], dict) else {}
        raw_mapping = first.get("source_mapping")
        mapping = raw_mapping if isinstance(raw_mapping, dict) else {}
        raw_lines = mapping.get("lines")
        lines = raw_lines if isinstance(raw_lines, list) else []
        findings.append(
            DynamicFinding(
                detector_id=str(item.get("check") or "slither"),
                title=str(item.get("check") or "slither"),
                severity=str(item.get("impact") or ""),
                confidence=str(item.get("confidence") or ""),
                function=str(first.get("name") or ""),
                file_path=str(mapping.get("filename") or ""),
                line=int(lines[0]) if lines and isinstance(lines[0], int) else 0,
                description=str(item.get("description") or "")[:500],
                status="potential",
            )
        )
    return findings


def project_uses_foundry(root: Path) -> bool:
    return (root / "foundry.toml").is_file()


def _rejects_fork(request: AnalysisRequest) -> bool:
    blob = " ".join(request.extra.values()).lower()
    return "fork-url" in blob or "fork_url" in blob or request.extra.get("fork") == "true"
