"""Optional Semgrep adapter.

Missing binary yields UNAVAILABLE. Scanner JSON is untrusted static evidence
and never a verified finding. Results dedupe on rule id, path, and line.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from dataclasses import dataclass

from app.adapters.security_tools.base import SecurityToolAdapter, SecurityToolCapability
from app.domain.evidence import Evidence, EvidenceKind
from app.domain.scope import ScopeConstraint
from app.security_testing.failures import ToolExecutionResult, ToolExecutionState
from app.security_testing.sanitization import wrap_untrusted


@dataclass(frozen=True)
class SemgrepHit:
    rule_id: str
    path: str
    line: int
    message: str


def semgrep_available(binary: str | None = None) -> bool:
    if binary:
        return True
    return shutil.which("semgrep") is not None


def normalize_semgrep(payload: str) -> tuple[str, list[SemgrepHit]]:
    """Return status and deduped hits. Invalid JSON is an error, not a finding."""
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("semgrep output was not JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("semgrep output was not an object")
    results = data.get("results")
    if not isinstance(results, list):
        return "UNAVAILABLE", []
    seen: set[tuple[str, str, int]] = set()
    hits: list[SemgrepHit] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        rule = str(item.get("check_id") or "")
        path = str(item.get("path") or "")
        start_raw = item.get("start")
        start: dict[str, object] = start_raw if isinstance(start_raw, dict) else {}
        line = int(str(start.get("line") or 0))
        key = (rule, path, line)
        if not rule or not path or key in seen:
            continue
        seen.add(key)
        extra_raw = item.get("extra")
        raw_extra: dict[str, object] = extra_raw if isinstance(extra_raw, dict) else {}
        message = wrap_untrusted("semgrep", str(raw_extra.get("message") or "")[:300])
        hits.append(SemgrepHit(rule, path, line, message))
    return "AVAILABLE", hits


def hits_as_evidence(hits: list[SemgrepHit]) -> list[Evidence]:
    """Static observations only. This kind cannot verify a finding."""
    evidence: list[Evidence] = []
    for hit in hits:
        evidence.append(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                source="semgrep",
                summary=f"{hit.rule_id} {hit.path}:{hit.line}",
                details=hit.message,
                metadata={
                    "rule_id": hit.rule_id,
                    "path": hit.path,
                    "line": hit.line,
                    "is_finding": False,
                    "status": "potential",
                    "verified": False,
                },
            )
        )
    return evidence


class SemgrepAdapter(SecurityToolAdapter):
    def __init__(self, *, binary: str | None = None) -> None:
        self._binary = binary
        self.last_result: ToolExecutionResult | None = None

    @property
    def tool_id(self) -> str:
        return "semgrep"

    @property
    def display_name(self) -> str:
        return "Semgrep"

    def is_available(self) -> bool:
        return semgrep_available(self._binary)

    def capabilities(self) -> frozenset[SecurityToolCapability]:
        return frozenset({SecurityToolCapability.PASSIVE_EVIDENCE})

    def health(self) -> ToolExecutionResult:
        if not self.is_available():
            result = ToolExecutionResult(tool="semgrep", state=ToolExecutionState.TOOL_UNAVAILABLE)
            self.last_result = result
            return result
        result = ToolExecutionResult(tool="semgrep", state=ToolExecutionState.OK, detail="semgrep")
        self.last_result = result
        return result

    def ingest_json(self, payload: str) -> list[Evidence]:
        status, hits = normalize_semgrep(payload)
        if status != "AVAILABLE":
            self.last_result = ToolExecutionResult(
                tool="semgrep", state=ToolExecutionState.TOOL_UNAVAILABLE
            )
            return [
                Evidence(
                    kind=EvidenceKind.TOOL_STATUS,
                    source="semgrep",
                    summary="semgrep tool_unavailable",
                    metadata={"state": "tool_unavailable", "is_finding": False, "verified": False},
                )
            ]
        self.last_result = ToolExecutionResult(
            tool="semgrep",
            state=ToolExecutionState.RESULTS_AVAILABLE,
            detail=f"{len(hits)} results",
        )
        return hits_as_evidence(hits)

    def _collect_passive_evidence(self, *, scope: ScopeConstraint) -> Sequence[Evidence]:
        del scope
        if not self.is_available():
            return [
                Evidence(
                    kind=EvidenceKind.TOOL_STATUS,
                    source="semgrep",
                    summary="semgrep tool_unavailable",
                    metadata={"state": "tool_unavailable", "is_finding": False, "verified": False},
                )
            ]
        return ()

    def _active_scan(self, *, scope: ScopeConstraint, target: str) -> Sequence[Evidence]:
        del scope, target
        self.last_result = ToolExecutionResult(
            tool="semgrep", state=ToolExecutionState.TOOL_UNAVAILABLE
        )
        return [
            Evidence(
                kind=EvidenceKind.TOOL_STATUS,
                source="semgrep",
                summary="semgrep tool_unavailable",
                details="Semgrep does not scan live targets from this adapter.",
                metadata={"state": "tool_unavailable", "is_finding": False, "verified": False},
            )
        ]
