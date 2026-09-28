"""Optional ItyFuzz exploration. The executable is not vendored and is not an authority."""

from __future__ import annotations

import json
from pathlib import Path

from app.adapters.discovery.external import ExternalDiscoveryEngine
from app.discovery.capabilities import EngineAvailability, EngineCapability, ResultStatus
from app.discovery.engine import AnalysisRequest
from app.discovery.process import ProcessResult, run_command, tool_path, tool_version
from app.discovery.results import DynamicFinding, DynamicResult, unavailable_result

_LICENSE = "fuzzland/ityfuzz; source is not vendored and is not relicensed by BugForge"
_NETWORK = (
    "fork",
    "rpc",
    "onchain",
    "etherscan",
    "http://",
    "https://",
    "eth_rpc",
    "alchemy",
    "infura",
)
_MAX_TIMEOUT = 60.0


class ItyFuzzEngine(ExternalDiscoveryEngine):
    binary = "ityfuzz"
    license_note = _LICENSE

    @property
    def engine_id(self) -> str:
        return "ityfuzz"

    @property
    def display_name(self) -> str:
        return "ItyFuzz"

    @property
    def supported_languages(self) -> frozenset[str]:
        return frozenset({"solidity"})

    def capabilities(self) -> frozenset[EngineCapability]:
        return frozenset(
            {
                EngineCapability.FUZZING,
                EngineCapability.COVERAGE_FEEDBACK,
                EngineCapability.RESULTS_INGESTION,
            }
        )

    def availability(self) -> EngineAvailability:
        if tool_path(self.binary):
            return EngineAvailability.AVAILABLE
        return EngineAvailability.UNAVAILABLE

    def version(self) -> str:
        found = tool_version(self.binary)
        if found:
            return found
        return tool_version(self.binary, ("-V",))

    def _start_campaign(self, request: AnalysisRequest) -> DynamicResult:
        if self.availability() is not EngineAvailability.AVAILABLE:
            return self._unavailable(request)
        if _rejects_network(request):
            return DynamicResult(
                engine=self.engine_id,
                language=request.language,
                target=request.target,
                status=ResultStatus.FAILED,
                executed=False,
                provenance="scope",
                oracle_explanation="public RPC and fork campaigns are rejected in the default sandbox",
                metadata={
                    "verified": "false",
                    "environment": "sandbox",
                    "license": self.license_note,
                },
            )
        artifacts = _artifact_dir(request)
        if artifacts is None:
            return DynamicResult(
                engine=self.engine_id,
                language=request.language,
                target=request.target,
                status=ResultStatus.UNSUPPORTED,
                executed=False,
                provenance="capability",
                oracle_explanation=(
                    "a local ItyFuzz campaign needs compiled .abi and .bin files; "
                    "BugForge does not fetch them"
                ),
                metadata={
                    "verified": "false",
                    "environment": "sandbox",
                    "license": self.license_note,
                },
            )
        timeout = _timeout(request)
        proc = run_command(
            ["ityfuzz", "evm", "-t", f"{artifacts.as_posix()}/*"],
            cwd=request.repo_root,
            timeout=timeout,
            env=_local_env(),
        )
        return _from_process(self, request, proc)

    def _collect_results(self, request: AnalysisRequest) -> DynamicResult:
        raw = request.extra.get("ityfuzz_output", "")
        if not raw:
            return self._start_campaign(request)
        status, findings, minimized, limitation = parse_ityfuzz_output(raw)
        return DynamicResult(
            engine=self.engine_id,
            language=request.language,
            target=request.target,
            status=status,
            executed=False,
            minimized_input=minimized,
            findings=findings,
            provenance="ityfuzz_output",
            oracle_explanation=limitation
            or "ingested caller-supplied ItyFuzz output; the tool was not executed",
            metadata={
                "verified": "false",
                "authority": "candidate" if findings else "unknown",
                "structured": "false" if limitation else "true",
                "license": self.license_note,
            },
        )


def parse_ityfuzz_output(
    text: str,
) -> tuple[ResultStatus, tuple[DynamicFinding, ...], str, str]:
    """Structured JSON only. Malformed text never becomes a finding."""
    stripped = text.strip()
    if not stripped:
        return ResultStatus.EXECUTED, (), "", "structured output was unavailable"
    payload = _json_object(stripped)
    if payload is None:
        return (
            ResultStatus.FAILED,
            (),
            "",
            "malformed ItyFuzz output; no finding was fabricated",
        )
    vulns = payload.get("vulnerabilities", payload.get("bugs", []))
    transactions = payload.get("transactions", payload.get("minimized_sequence", []))
    if not isinstance(vulns, list) or not isinstance(transactions, list):
        return ResultStatus.FAILED, (), "", "malformed ItyFuzz output; no finding was fabricated"
    findings: list[DynamicFinding] = []
    for item in vulns:
        if not isinstance(item, dict):
            return (
                ResultStatus.FAILED,
                (),
                "",
                "malformed ItyFuzz output; no finding was fabricated",
            )
        findings.append(
            DynamicFinding(
                detector_id=str(item.get("id", "ityfuzz")),
                title=str(item.get("title", "ityfuzz candidate"))[:180],
                contract=str(item.get("contract", "")),
                function=str(item.get("function", "")),
                description=str(item.get("description", ""))[:500],
                status="potential",
            )
        )
    minimized = (
        json.dumps(transactions, sort_keys=True, separators=(",", ":")) if transactions else ""
    )
    if findings:
        return ResultStatus.INTERESTING, tuple(findings), minimized, ""
    return ResultStatus.EXECUTED, (), minimized, ""


def exploration_authority(status: ResultStatus) -> str:
    """ItyFuzz never promotes a result to reproduced."""
    if status is ResultStatus.INTERESTING:
        return "interesting"
    if status is ResultStatus.EXECUTED:
        return "executed"
    if status is ResultStatus.UNAVAILABLE:
        return "unavailable"
    if status is ResultStatus.UNSUPPORTED:
        return "unsupported"
    if status is ResultStatus.TIMEOUT:
        return "timeout"
    if status is ResultStatus.FAILED:
        return "failed"
    return "unknown"


def _from_process(
    engine: ItyFuzzEngine, request: AnalysisRequest, proc: ProcessResult
) -> DynamicResult:
    if proc.timed_out:
        return DynamicResult(
            engine=engine.engine_id,
            engine_version=engine.version(),
            language=request.language,
            target=request.target,
            status=ResultStatus.TIMEOUT,
            executed=False,
            stderr=proc.stderr[:2000],
            stdout=proc.stdout[:4000],
            provenance="ityfuzz",
            metadata={
                "verified": "false",
                "environment": "sandbox",
                "license": engine.license_note,
            },
        )
    if not proc.available:
        return unavailable_result(
            engine.engine_id,
            request.language,
            request.target,
            reason="ityfuzz is not installed",
        )
    if not proc.started:
        return DynamicResult(
            engine=engine.engine_id,
            language=request.language,
            target=request.target,
            status=ResultStatus.FAILED,
            executed=False,
            stderr=proc.stderr[:2000],
            provenance="ityfuzz",
            metadata={"verified": "false", "environment": "sandbox"},
        )
    status, findings, minimized, limitation = parse_ityfuzz_output(proc.stdout or proc.stderr)
    if status is ResultStatus.FAILED and not (proc.stdout or proc.stderr).strip():
        status = ResultStatus.EXECUTED
        limitation = "structured output was unavailable"
    return DynamicResult(
        engine=engine.engine_id,
        engine_version=engine.version(),
        language=request.language,
        target=request.target,
        source_file=request.source_file,
        contract=request.contract,
        function=request.function,
        status=status,
        executed=proc.started and not proc.timed_out,
        exit_code=proc.return_code,
        stdout=(proc.stdout or "")[:4000],
        stderr=(proc.stderr or "")[:2000],
        minimized_input=minimized,
        findings=findings,
        provenance="ityfuzz",
        oracle_explanation=limitation,
        metadata={
            "verified": "false",
            "authority": exploration_authority(status),
            "environment": "sandbox",
            "structured": "false" if limitation else "true",
            "license": engine.license_note,
            "tool_version": engine.version(),
        },
    )


def _json_object(text: str) -> dict[str, object] | None:
    start = text.find("{")
    if start < 0:
        return None
    try:
        payload = json.loads(text[start:])
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _artifact_dir(request: AnalysisRequest) -> Path | None:
    raw = request.extra.get("artifact_dir", "")
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = request.repo_root / path
    try:
        path.resolve().relative_to(request.repo_root.resolve())
    except ValueError:
        return None
    if not path.is_dir():
        return None
    names = {item.name for item in path.iterdir() if item.is_file()}
    if not any(name.endswith(".abi") for name in names) or not any(
        name.endswith(".bin") for name in names
    ):
        return None
    return path


def _rejects_network(request: AnalysisRequest) -> bool:
    blob = " ".join(request.extra.values()).lower()
    return any(marker in blob for marker in _NETWORK)


def _timeout(request: AnalysisRequest) -> float:
    raw = request.extra.get("timeout", "")
    try:
        requested = float(raw) if raw else 30.0
    except ValueError:
        requested = 30.0
    return max(1.0, min(requested, _MAX_TIMEOUT))


def _local_env() -> dict[str, str]:
    from app.discovery.process import _env

    env = _env()
    markers = (
        "RPC",
        "ETHERSCAN",
        "INFURA",
        "ALCHEMY",
        "MNEMONIC",
        "PRIVATE",
        "SECRET",
        "API_KEY",
        "APIKEY",
    )
    for key in list(env):
        upper = key.upper()
        if any(marker in upper for marker in markers):
            env.pop(key, None)
    return env
