"""Sandboxed runtime, fork, and differential validation.

A missing image is unavailable. Host execution is not a fallback. The network
stays disabled unless an operator has enabled a pinned fork. Results stay
candidates or unknown and cannot mark a finding verified.
"""

from __future__ import annotations

import tempfile

from app.discovery.capabilities import EngineAvailability, EngineCapability, ResultStatus
from app.discovery.engine import AnalysisRequest, DiscoveryEngine
from app.discovery.results import DynamicResult
from app.execution.base import ExecutionConfig, ExecutionResult
from app.parsing.solidity_runtime import (
    SCHEMA,
    ForkIdentity,
    RuntimeObservation,
    clamp_runtime_executions,
    compare_executions,
    fork_identity,
    local_command,
    network_allowed,
    parse_runtime_document,
)

_VERSION = "phase48"
_INTERFACE = SCHEMA
_SECRET_KEYS = frozenset({"private_key", "mnemonic", "wallet", "secret"})
_PUBLIC = ("http://", "https://", "alchemy", "infura", "fork_url")
_MAX_PAIR = 2


class RuntimeEngine(DiscoveryEngine):
    @property
    def engine_id(self) -> str:
        return "bugforge-runtime"

    @property
    def display_name(self) -> str:
        return "BugForge runtime validation"

    @property
    def supported_languages(self) -> frozenset[str]:
        return frozenset({"solidity"})

    def capabilities(self) -> frozenset[EngineCapability]:
        return frozenset(
            {
                EngineCapability.RUNTIME_VALIDATION,
                EngineCapability.FORK_VALIDATION,
                EngineCapability.DIFFERENTIAL_VALIDATION,
                EngineCapability.RESULTS_INGESTION,
            }
        )

    def availability(self) -> EngineAvailability:
        if _runtime_image() and _docker_present() and _local_image():
            return EngineAvailability.AVAILABLE
        return EngineAvailability.UNAVAILABLE

    def version(self) -> str:
        if not _runtime_image():
            return ""
        return _INTERFACE

    def start_campaign(self, request: AnalysisRequest) -> DynamicResult:
        mode = request.extra.get("mode", "local") or "local"
        if mode == "fork":
            blocked = _fork_gate(self, request)
            if blocked is not None:
                return blocked
        if self.availability() is not EngineAvailability.AVAILABLE:
            return _status(
                self,
                request,
                ResultStatus.UNAVAILABLE,
                "runtime validation requires Docker and a local "
                "security_agent_runtime_image; host execution is not started "
                "and no image is pulled",
                capability=_capability(mode),
                observation="unavailable",
            )
        return super().start_campaign(request)

    def analyze_target(self, request: AnalysisRequest) -> DynamicResult:
        return self.start_campaign(request)

    def _start_campaign(self, request: AnalysisRequest) -> DynamicResult:
        return _validate(self, request)

    def _analyze_target(self, request: AnalysisRequest) -> DynamicResult:
        return _validate(self, request)


def _validate(engine: RuntimeEngine, request: AnalysisRequest) -> DynamicResult:
    mode = request.extra.get("mode", "local") or "local"
    if mode not in {"local", "fork", "differential", "replay"}:
        return _status(
            engine,
            request,
            ResultStatus.UNSUPPORTED,
            "the runtime mode is not supported",
            capability="runtime_validation",
            observation="unsupported",
        )
    if _secret_requested(request):
        return _status(
            engine,
            request,
            ResultStatus.FAILED,
            "private-key and wallet material are not accepted",
            capability=_capability(mode),
            observation="unknown",
        )
    if mode != "fork" and _public_network_requested(request):
        return _status(
            engine,
            request,
            ResultStatus.FAILED,
            "public RPC and fork URLs are not used",
            capability=_capability(mode),
            observation="unknown",
        )
    identity = _fork(request) if mode == "fork" else None
    if mode == "fork":
        blocked = _fork_gate(engine, request)
        if blocked is not None:
            return blocked
    if engine.availability() is not EngineAvailability.AVAILABLE:
        return _status(
            engine,
            request,
            ResultStatus.UNAVAILABLE,
            "runtime validation requires Docker and a local security_agent_runtime_image; "
            "host execution is not started and no image is pulled",
            capability=_capability(mode),
            observation="unavailable",
        )
    runs = _run_count(request, mode)
    allow_network = network_allowed(
        mode=mode,
        fork_enabled=_fork_enabled(),
        deterministic=bool(identity and identity.deterministic),
        requested_network=request.extra.get("network", ""),
    )
    observations: list[RuntimeObservation] = []
    for index in range(runs):
        observed = _execute_once(request, mode, allow_network, index, identity)
        if isinstance(observed, DynamicResult):
            return observed
        observations.append(observed)
    report = None
    if mode in {"differential", "replay"}:
        if len(observations) < 2:
            return _status(
                engine,
                request,
                ResultStatus.UNSUPPORTED,
                "a comparison needs two executions inside the existing cap",
                capability=_capability(mode),
                observation="incomplete",
            )
        reset = request.extra.get("state_reset", "") == "true"
        report = compare_executions(observations[0], observations[1], reset=reset)
    return _ingested(engine, request, mode, observations, report, identity)


def _execute_once(
    request: AnalysisRequest,
    mode: str,
    allow_network: bool,
    index: int,
    identity: ForkIdentity | None,
) -> RuntimeObservation | DynamicResult:
    command = _command(mode, identity)
    with tempfile.TemporaryDirectory(prefix="bugforge-runtime-") as directory:
        config = ExecutionConfig(
            command=command,
            working_directory=str(request.repo_root),
            timeout_seconds=60,
            memory_limit_mb=512,
            cpu_limit=1.0,
            environment={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
            allow_network=allow_network,
            output_dir=directory,
            read_only_volumes={str(request.repo_root): "/bugforge-src"},
        )
        if config.allow_network != allow_network:
            return _bare(request, "network disabled")
        result = _execute(config)
        if result.timed_out:
            return _bare(request, "the runtime timed out", ResultStatus.TIMEOUT)
        document = result.artifact_contents.get("runtime.json", "")
        parsed = parse_runtime_document(document) if document else None
        if parsed is None:
            return _bare(
                request,
                "the runtime output did not match bugforge-runtime-v1",
                ResultStatus.UNSUPPORTED,
            )
        chosen = parsed[min(index, len(parsed) - 1)]
        return chosen


def _ingested(
    engine: RuntimeEngine,
    request: AnalysisRequest,
    mode: str,
    observations: list[RuntimeObservation],
    report: object,
    identity: ForkIdentity | None,
) -> DynamicResult:
    first = observations[0]
    classification = getattr(report, "classification", "")
    report_status = getattr(report, "status", "")
    status = report_status or ("candidate" if first.status == "observed" else "unknown")
    explanation = "runtime evidence is not verification"
    if classification:
        explanation = f"{classification}; {explanation}"
    fork_pinned = bool(
        identity
        and identity.deterministic
        and first.block_number == identity.block_number
        and first.chain_id == identity.chain_id
        and first.state_snapshot == identity.state_snapshot
    )
    local_pinned = (
        mode == "local"
        and first.chain_id == "31337"
        and first.block_number == "1"
        and bool(first.state_snapshot)
    )
    metadata = _meta(
        request,
        capability=_capability(mode),
        observation=status,
        deterministic="true" if fork_pinned or local_pinned else "false",
        observed=True,
    )
    metadata["executions"] = str(len(observations))
    metadata["vulnerability"] = "unknown"
    metadata["tool"] = first.tool
    metadata["tool_version"] = first.tool_version
    metadata["sequence_id"] = first.sequence_id
    metadata["state_snapshot"] = first.state_snapshot
    if report is not None and classification:
        metadata["classification"] = str(classification)
        metadata["compared"] = (
            f"{getattr(report, 'left_execution', '')}|{getattr(report, 'right_execution', '')}"
        )
    return DynamicResult(
        engine=engine.engine_id,
        engine_version=engine.version() or _INTERFACE,
        language=request.language,
        target=request.target,
        campaign_id=request.campaign_id,
        source_file=request.source_file,
        contract=first.contract,
        function=first.function_identity,
        status=ResultStatus.INGESTED,
        executed=True,
        provenance="sandbox",
        oracle_explanation=explanation,
        oracle_kind="differential" if report is not None else "runtime",
        metadata=metadata,
        runtime_evidence=report or first,
    )


def _status(
    engine: RuntimeEngine,
    request: AnalysisRequest,
    status: ResultStatus,
    explanation: str,
    *,
    capability: str,
    observation: str,
    deterministic: str = "",
) -> DynamicResult:
    return DynamicResult(
        engine=engine.engine_id,
        engine_version=engine.version(),
        language=request.language,
        target=request.target,
        status=status,
        executed=False,
        provenance="sandbox",
        oracle_explanation=explanation,
        oracle_kind="" if status is not ResultStatus.INGESTED else "runtime",
        metadata=_meta(
            request,
            capability=capability,
            observation=observation,
            deterministic=deterministic,
        ),
    )


def _bare(
    request: AnalysisRequest,
    explanation: str,
    status: ResultStatus = ResultStatus.FAILED,
) -> DynamicResult:
    return DynamicResult(
        engine="bugforge-runtime",
        language=request.language,
        target=request.target,
        status=status,
        executed=False,
        provenance="sandbox",
        oracle_explanation=explanation,
        oracle_kind="",
        metadata={
            "verified": "false",
            "vulnerability": "unknown",
            "llm_invoked": "false",
            "network": "none",
            "observation_status": "unknown" if status is ResultStatus.FAILED else "incomplete",
        },
    )


def _meta(
    request: AnalysisRequest,
    *,
    capability: str,
    observation: str,
    deterministic: str,
    observed: bool = False,
) -> dict[str, str]:
    if not observed:
        evidence_class = ""
    elif capability == "differential_validation":
        evidence_class = "differential"
    else:
        evidence_class = "runtime"
    return {
        "verified": "false",
        "vulnerability": "unknown",
        "capability": capability,
        "evidence_class": evidence_class,
        "observation_status": observation,
        "deterministic": deterministic,
        "network": "none",
        "environment": "docker-sandbox",
        "project": request.extra.get("project_id", ""),
        "source_snapshot": request.extra.get("source_snapshot", ""),
        "compiler_configuration": request.extra.get("compiler_configuration", ""),
        "llm_invoked": "false",
    }


def _fork_gate(engine: RuntimeEngine, request: AnalysisRequest) -> DynamicResult | None:
    identity = _fork(request)
    if not identity.configured:
        return _status(
            engine,
            request,
            ResultStatus.UNAVAILABLE,
            "fork mode requires explicit operator configuration",
            capability="fork_validation",
            observation="unavailable",
        )
    if not identity.deterministic:
        return _status(
            engine,
            request,
            ResultStatus.UNSUPPORTED,
            "an unpinned fork is not deterministic validation",
            capability="fork_validation",
            observation="unknown",
            deterministic="false",
        )
    return None


def _capability(mode: str) -> str:
    if mode == "fork":
        return "fork_validation"
    if mode in {"differential", "replay"}:
        return "differential_validation"
    return "runtime_validation"


def _run_count(request: AnalysisRequest, mode: str) -> int:
    requested = request.extra.get("executions", "2" if mode in {"differential", "replay"} else "1")
    try:
        count = int(requested)
    except ValueError:
        count = 1
    capped = clamp_runtime_executions(count)
    if mode in {"differential", "replay"}:
        return min(capped, _MAX_PAIR)
    return capped


def _fork(request: AnalysisRequest) -> ForkIdentity:
    enabled = _fork_enabled() and bool(_fork_source())
    return fork_identity(
        configured=enabled,
        fork_source=_fork_source() if enabled else "",
        chain_id=request.extra.get("chain_id", ""),
        block_number=request.extra.get("fork_block", ""),
        state_snapshot=request.extra.get("state_snapshot", ""),
        compiler_configuration=request.extra.get("compiler_configuration", ""),
        project=request.extra.get("project_id", ""),
        target=request.target,
        deployments=tuple(item for item in request.extra.get("deployments", "").split(",") if item),
    )


def _secret_requested(request: AnalysisRequest) -> bool:
    return any(key.lower() in _SECRET_KEYS for key in request.extra)


def _public_network_requested(request: AnalysisRequest) -> bool:
    blob = " ".join(f"{key}={value}" for key, value in request.extra.items()).lower()
    return any(mark in blob for mark in _PUBLIC)


def _command(mode: str, identity: ForkIdentity | None) -> list[str]:
    if mode != "fork" or identity is None:
        return local_command()
    return [
        "bugforge-runtime",
        "--mode",
        "fork",
        "--chain-id",
        identity.chain_id,
        "--block",
        identity.block_number,
        "--state",
        identity.state_snapshot,
        "--fork-source",
        identity.fork_source,
        "--output",
        "/bugforge-output/runtime.json",
    ]


def _execute(config: ExecutionConfig) -> ExecutionResult:
    """Run inside Docker. This function is the only execution path."""
    import asyncio

    from app.execution.docker_executor import DockerTestExecutor

    if config.allow_network and not _fork_enabled():
        return ExecutionResult(
            exit_code=-1,
            stdout="",
            stderr="network disabled",
            duration_seconds=0.0,
            error_message="network disabled",
        )
    image = _runtime_image()
    return asyncio.run(DockerTestExecutor(image).execute(config))


def _runtime_image() -> str:
    from app.core.config import get_settings

    return get_settings().security_agent_runtime_image.strip()


def _fork_enabled() -> bool:
    from app.core.config import get_settings

    return bool(get_settings().security_agent_fork_enabled)


def _fork_source() -> str:
    from app.core.config import get_settings

    return get_settings().security_agent_fork_source.strip()


def _docker_present() -> bool:
    import shutil

    return shutil.which("docker") is not None


def _local_image() -> bool:
    from app.execution.docker_executor import local_image_present

    return local_image_present(_runtime_image())
