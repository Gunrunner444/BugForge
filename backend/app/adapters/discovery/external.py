"""Optional external discovery tools. Missing executables do not invent results."""

from __future__ import annotations

import json
import re
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
            status=_process_status(code, stdout, stderr, timed_out, ingested=bool(findings)),
            executed=code != 127,
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
        return frozenset(
            {
                EngineCapability.BUILD,
                EngineCapability.TEST_EXECUTION,
                EngineCapability.FUZZING,
                EngineCapability.INVARIANT_TESTING,
                EngineCapability.COVERAGE_FEEDBACK,
                EngineCapability.RESULTS_INGESTION,
            }
        )

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
        mode = request.extra.get("mode", "test")
        config = read_foundry_config(request.repo_root)
        argv = _foundry_argv(mode, request)
        code, stdout, stderr, timed_out = run_command(argv, cwd=request.repo_root, timeout=120)
        parsed = parse_foundry_output(stdout)
        coverage = _as_map(parsed["coverage"])
        assertion = _as_str(parsed["assertion"])
        status = _process_status(
            code, stdout, stderr, timed_out, ingested=bool(assertion or coverage)
        )
        if assertion and status in {ResultStatus.EXECUTED, ResultStatus.INGESTED}:
            status = ResultStatus.INTERESTING
        return DynamicResult(
            engine=self.engine_id,
            engine_version=self.version(),
            language=request.language,
            target=request.target,
            function=request.function,
            contract=request.contract,
            source_file=request.source_file,
            status=status,
            executed=code != 127,
            exit_code=code,
            stdout=stdout[:4000],
            stderr=stderr[:2000],
            assertion=assertion,
            coverage=coverage,
            reproduction_command=" ".join(argv),
            provenance="foundry",
            oracle_kind="assertion" if assertion else "",
            oracle_explanation=assertion,
            metadata={
                "fork": "false",
                "verified": "false",
                "mode": mode,
                "license": self.license_note,
                **{f"foundry_{key}": value for key, value in config.items()},
            },
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
                oracle_explanation="Echidna needs a contract file.",
            )
        argv = ["echidna", target, "--format", "text"]
        if request.contract:
            argv[2:2] = ["--contract", request.contract]
        for name in ("echidna.yaml", "echidna.config.yaml"):
            if (request.repo_root / name).is_file():
                argv.extend(["--config", name])
                break
        code, stdout, stderr, timed_out = run_command(argv, cwd=request.repo_root, timeout=90)
        parsed = parse_echidna_output(stdout + "\n" + stderr)
        assertion = _as_str(parsed["assertion"])
        sequence = _as_str(parsed["sequence"])
        coverage = _as_map(parsed["coverage"])
        status = _process_status(code, stdout, stderr, timed_out, ingested=bool(assertion))
        if assertion and status in {ResultStatus.EXECUTED, ResultStatus.INGESTED}:
            status = ResultStatus.INTERESTING
        return DynamicResult(
            engine=self.engine_id,
            engine_version=self.version(),
            language=request.language,
            target=target,
            contract=_as_str(parsed["contract"]) or request.contract,
            function=_as_str(parsed["property"]),
            status=status,
            executed=code != 127,
            exit_code=code,
            stdout=stdout[:4000],
            stderr=stderr[:2000],
            assertion=assertion,
            minimized_input=sequence,
            coverage=coverage,
            reproduction_command=" ".join(argv),
            provenance="echidna",
            oracle_kind="property" if assertion else "",
            oracle_explanation=assertion,
            metadata={"verified": "false", "license": self.license_note},
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
                EngineCapability.PROPERTY_TESTING,
                EngineCapability.COVERAGE_FEEDBACK,
                EngineCapability.RESULTS_INGESTION,
            }
        )

    def _start_campaign(self, request: AnalysisRequest) -> DynamicResult:
        if self.availability() is not EngineAvailability.AVAILABLE:
            return self._unavailable(request)
        argv = ["medusa", "fuzz"]
        if (request.repo_root / "medusa.json").is_file():
            argv.extend(["--config", "medusa.json"])
        code, stdout, stderr, timed_out = run_command(argv, cwd=request.repo_root, timeout=90)
        parsed = parse_medusa_output(stdout + "\n" + stderr)
        assertion = _as_str(parsed["assertion"])
        coverage = _as_map(parsed["coverage"])
        status = _process_status(code, stdout, stderr, timed_out, ingested=bool(assertion))
        if coverage:
            status = ResultStatus.INTERESTING if assertion else ResultStatus.EXECUTED
        return DynamicResult(
            engine=self.engine_id,
            engine_version=self.version(),
            language=request.language,
            target=request.target,
            contract=request.contract,
            function=_as_str(parsed["property"]) or request.function,
            status=status,
            executed=code != 127,
            exit_code=code,
            stdout=stdout[:4000],
            stderr=stderr[:2000],
            assertion=assertion,
            coverage=coverage,
            minimized_input=_as_str(parsed["sequence"]),
            reproduction_command=" ".join(argv),
            provenance="medusa",
            oracle_kind="property" if assertion else "",
            oracle_explanation=assertion,
            metadata={"verified": "false", "license": self.license_note},
        )


class HalmosEngine(ExternalDiscoveryEngine):
    binary = "halmos"
    license_note = "AGPL external symbolic-testing executable; source is not vendored"

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

    def start_campaign(self, request: AnalysisRequest) -> DynamicResult:
        if not request.difficult:
            return DynamicResult(
                engine=self.engine_id,
                language=request.language,
                target=request.target,
                status=ResultStatus.PLANNED,
                executed=False,
                oracle_explanation="Halmos runs only for a target marked difficult to reach.",
            )
        return super().start_campaign(request)

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
        if request.contract:
            argv.extend(["--contract", request.contract])
        if request.function:
            argv.extend(["--function", request.function])
        elif request.match_test:
            argv.extend(["--match-test", request.match_test])
        code, stdout, stderr, timed_out = run_command(argv, cwd=request.repo_root, timeout=120)
        parsed = parse_halmos_output(stdout)
        status = _process_status(code, stdout, stderr, timed_out, ingested=bool(parsed["counterexample"]))
        if parsed["counterexample"] and status in {ResultStatus.EXECUTED, ResultStatus.INGESTED}:
            status = ResultStatus.INTERESTING
        return DynamicResult(
            engine=self.engine_id,
            engine_version=self.version(),
            language=request.language,
            target=request.target,
            function=parsed["test"] or request.function,
            contract=request.contract,
            source_file=request.source_file,
            status=status,
            executed=code != 127,
            exit_code=code,
            stdout=stdout[:4000],
            stderr=stderr[:2000],
            minimized_input=parsed["counterexample"],
            assertion=parsed["counterexample"],
            reproduction_command=" ".join(argv),
            provenance="halmos",
            oracle_kind="assertion" if parsed["counterexample"] else "",
            oracle_explanation=parsed["counterexample"],
            metadata={
                "seed_source": "symbolic" if parsed["counterexample"] else "",
                "verified": "false",
                "license": self.license_note,
            },
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
        return frozenset(
            {
                EngineCapability.STATIC_ANALYSIS,
                EngineCapability.FUZZING,
                EngineCapability.RESULTS_INGESTION,
            }
        )

    def _analyze_target(self, request: AnalysisRequest) -> DynamicResult:
        return self._run(request, ["wake", "detect"], fuzz=False)

    def _start_campaign(self, request: AnalysisRequest) -> DynamicResult:
        return self._run(request, ["wake", "fuzz"], fuzz=True)

    def _run(self, request: AnalysisRequest, argv: list[str], *, fuzz: bool) -> DynamicResult:
        if self.availability() is not EngineAvailability.AVAILABLE:
            return self._unavailable(request)
        code, stdout, stderr, timed_out = run_command(argv, cwd=request.repo_root, timeout=90)
        findings = () if fuzz else tuple(parse_wake_detect(stdout))
        status = _process_status(code, stdout, stderr, timed_out, ingested=bool(findings))
        return DynamicResult(
            engine=self.engine_id,
            engine_version=self.version(),
            language=request.language,
            target=request.target,
            status=status,
            executed=code != 127,
            exit_code=code,
            stdout=stdout[:4000],
            stderr=stderr[:2000],
            findings=findings,
            provenance="wake",
            metadata={"license": self.license_note, "verified": "false", "mode": argv[-1]},
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
                contract=_slither_contract(first),
                file_path=str(mapping.get("filename_relative") or mapping.get("filename") or ""),
                line=int(lines[0]) if lines and isinstance(lines[0], int) else 0,
                description=str(item.get("description") or "")[:500],
                status="potential",
            )
        )
    return findings


def _slither_contract(element: dict[str, object]) -> str:
    specific = element.get("type_specific_fields")
    if not isinstance(specific, dict):
        return ""
    parent = specific.get("parent")
    if not isinstance(parent, dict):
        return ""
    return str(parent.get("name") or "")


def project_uses_foundry(root: Path) -> bool:
    return (root / "foundry.toml").is_file()


def read_foundry_config(root: Path) -> dict[str, str]:
    path = root / "foundry.toml"
    found: dict[str, str] = {}
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace")
        for key in ("src", "test", "script", "libs", "solc_version", "solc"):
            match = re.search(rf"^{key}\s*=\s*['\"]([^'\"]+)['\"]", text, re.MULTILINE)
            if match:
                found[key] = match.group(1)
    for dirname in ("src", "test", "script", "lib"):
        if (root / dirname).is_dir():
            found.setdefault(dirname, dirname)
    return found


def parse_foundry_output(stdout: str) -> dict[str, object]:
    fails = re.findall(r"\[FAIL[^\]]*\]\s*([^\n]+)", stdout)
    assertion = fails[0].strip() if fails else ""
    coverage: dict[str, str] = {}
    for match in re.finditer(r"(\d+(?:\.\d+)?)%", stdout):
        coverage["percent"] = match.group(1)
        break
    if "Suite result" in stdout or fails or re.search(r"\bpassed\b", stdout):
        coverage.setdefault("new", "true" if not fails else "false")
    return {"assertion": assertion, "coverage": coverage}


def parse_echidna_output(text: str) -> dict[str, object]:
    assertion = ""
    property_name = ""
    for line in text.splitlines():
        if "falsified" in line.lower() or re.search(r"\bfailed!?\b", line.lower()):
            assertion = line.strip()[:240]
            property_name = line.split(":", 1)[0].strip()
            break
    sequence = ""
    if "Call sequence" in text or "call sequence" in text.lower():
        chunk = re.split(r"call sequence", text, flags=re.IGNORECASE, maxsplit=1)[-1]
        sequence = "\n".join(line.strip() for line in chunk.splitlines()[1:8] if line.strip())
    coverage: dict[str, str] = {}
    corpus = re.search(r"corpus[^\d]*(\d+)", text, re.IGNORECASE)
    if corpus:
        coverage["corpus"] = corpus.group(1)
    return {
        "assertion": assertion,
        "property": property_name,
        "sequence": sequence[:500],
        "coverage": coverage,
        "contract": "",
    }


def parse_medusa_output(text: str) -> dict[str, object]:
    assertion = ""
    property_name = ""
    for line in text.splitlines():
        if re.search(r"assertion failed|property failed|\[FAIL", line, re.IGNORECASE):
            assertion = line.strip()[:240]
            property_name = line.strip()[:80]
            break
    coverage: dict[str, str] = {}
    percent = re.search(r"coverage[^\d]*(\d+(?:\.\d+)?)%", text, re.IGNORECASE)
    if percent:
        coverage["percent"] = percent.group(1)
        coverage["new"] = "true"
    corpus = re.search(r"corpus[^\d]*(\d+)", text, re.IGNORECASE)
    if corpus:
        coverage["corpus"] = corpus.group(1)
    sequence = ""
    if "CallSequence" in text or "call sequence" in text.lower():
        sequence = text[text.lower().find("call sequence") : text.lower().find("call sequence") + 300]
    return {
        "assertion": assertion,
        "property": property_name,
        "coverage": coverage,
        "sequence": sequence[:500],
    }


def parse_halmos_output(stdout: str) -> dict[str, str]:
    counterexample = ""
    if "Counterexample" in stdout:
        start = stdout.find("Counterexample")
        counterexample = stdout[start : start + 500].strip()
    test = ""
    match = re.search(r"\[(?:FAIL|PASS)[^\]]*\]\s*([^\n(]+)", stdout)
    if match:
        test = match.group(1).strip()
    return {"counterexample": counterexample, "test": test}


def parse_wake_detect(stdout: str) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    for line in stdout.splitlines():
        match = re.search(r"([A-Za-z0-9_.-]+):(\d+):\s*(.+)", line)
        if match is None:
            continue
        findings.append(
            DynamicFinding(
                detector_id="wake",
                title=match.group(3)[:120],
                file_path=match.group(1),
                line=int(match.group(2)),
                description=line.strip()[:500],
                status="potential",
            )
        )
    return findings


def _foundry_argv(mode: str, request: AnalysisRequest) -> list[str]:
    if mode == "build":
        return ["forge", "build"]
    if mode == "coverage":
        return ["forge", "coverage", "--report", "summary"]
    argv = ["forge", "test"]
    match = request.match_test or (request.function if mode in {"fuzz", "invariant", "test"} else "")
    if mode == "invariant" and not match:
        match = "invariant"
    if match:
        argv.extend(["--match-test", match, "-vv"])
    if mode == "fuzz":
        runs = request.extra.get("fuzz_runs", "64")
        if runs.isdigit():
            argv.extend(["--fuzz-runs", runs])
    return argv


def _process_status(
    code: int,
    stdout: str,
    stderr: str,
    timed_out: bool,
    *,
    ingested: bool,
) -> ResultStatus:
    if timed_out:
        return ResultStatus.TIMEOUT
    if code == 127:
        return ResultStatus.UNAVAILABLE
    tool_error = "compiler run failed" in stderr.lower() or "traceback (most recent call last)" in (
        stderr + stdout
    ).lower()
    if tool_error and not ingested:
        return ResultStatus.TOOL_FAILURE
    if ingested:
        return ResultStatus.INGESTED
    if code not in {0, None} and not ingested:
        return ResultStatus.TOOL_FAILURE
    return ResultStatus.EXECUTED


def _as_str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _as_map(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _rejects_fork(request: AnalysisRequest) -> bool:
    blob = " ".join(request.extra.values()).lower()
    return "fork-url" in blob or "fork_url" in blob or request.extra.get("fork") == "true"
