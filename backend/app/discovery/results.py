"""Normalized dynamic-engine results. Tool text is untrusted evidence, not instructions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.discovery.capabilities import ResultStatus
from app.domain.evidence import Evidence, EvidenceKind
from app.security_testing.secrets import redact_text


@dataclass(frozen=True)
class DynamicFinding:
    """One tool observation. Status stays potential until BugForge corroborates it."""

    detector_id: str
    title: str
    severity: str = ""
    confidence: str = ""
    contract: str = ""
    function: str = ""
    file_path: str = ""
    line: int = 0
    description: str = ""
    status: str = "potential"


@dataclass
class DynamicResult:
    engine: str
    language: str
    target: str
    status: ResultStatus = ResultStatus.PLANNED
    executed: bool = False
    engine_version: str = ""
    campaign_id: str = ""
    seed_id: str = ""
    coverage: dict[str, str] = field(default_factory=dict)
    exit_code: int | None = None
    crash: str = ""
    assertion: str = ""
    sanitizer: str = ""
    stdout: str = ""
    stderr: str = ""
    minimized_input: str = ""
    reproduction_command: str = ""
    source_file: str = ""
    function: str = ""
    contract: str = ""
    provenance: str = ""
    timestamp: str = ""
    oracle_explanation: str = ""
    oracle_kind: str = ""
    findings: tuple[DynamicFinding, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.stdout = redact_text(self.stdout)
        self.stderr = redact_text(self.stderr)
        self.crash = redact_text(self.crash)
        self.minimized_input = redact_text(self.minimized_input)
        if not self.timestamp:
            self.timestamp = datetime.now(UTC).isoformat()

    def to_evidence(self) -> Evidence:
        kind = EvidenceKind.TOOL_STATUS
        if self.executed and self.status is ResultStatus.INGESTED:
            kind = EvidenceKind.SCANNER if self.findings else EvidenceKind.FUZZING
        elif self.executed:
            kind = EvidenceKind.FUZZING if self.coverage or self.crash else EvidenceKind.LOG
        summary = f"{self.engine} {self.status.value} executed={self.executed}"
        if self.oracle_explanation:
            summary = f"{summary}: {self.oracle_explanation}"
        return Evidence(
            kind=kind,
            source=self.engine,
            summary=summary[:500],
            details=redact_text(self.stdout or self.stderr)[:2000],
            artifact_path=self.source_file or None,
            metadata={
                "engine": self.engine,
                "engine_version": self.engine_version,
                "language": self.language,
                "target": self.target,
                "campaign_id": self.campaign_id,
                "seed_id": self.seed_id,
                "status": self.status.value,
                "executed": str(self.executed).lower(),
                "verified": "false",
                "contract": self.contract,
                "function": self.function,
                "provenance": self.provenance,
                "timestamp": self.timestamp,
                "oracle": self.oracle_explanation,
                **{key: str(value) for key, value in self.coverage.items()},
                **self.metadata,
            },
        )


def unavailable_result(engine: str, language: str, target: str, *, reason: str) -> DynamicResult:
    return DynamicResult(
        engine=engine,
        language=language,
        target=target,
        status=ResultStatus.UNAVAILABLE,
        executed=False,
        provenance="tool_unavailable",
        oracle_explanation=reason,
        stderr=reason,
    )


def not_implemented_result(
    engine: str, language: str, target: str, operation: str
) -> DynamicResult:
    reason = f"{engine} does not implement {operation}"
    return DynamicResult(
        engine=engine,
        language=language,
        target=target,
        status=ResultStatus.NOT_IMPLEMENTED,
        executed=False,
        provenance="capability",
        oracle_explanation=reason,
    )


def as_dict(result: DynamicResult) -> dict[str, Any]:
    return {
        "engine": result.engine,
        "engine_version": result.engine_version,
        "language": result.language,
        "target": result.target,
        "campaign_id": result.campaign_id,
        "status": result.status.value,
        "executed": result.executed,
        "verified": False,
    }
