"""Nuclei adapter. Targets must pass ScopeGuard; templates are policy-gated."""

from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from app.adapters.security_tools.base import SecurityToolAdapter, SecurityToolCapability
from app.domain.evidence import Evidence, EvidenceKind
from app.domain.scope import ScopeConstraint
from app.security_testing.engine import SecurityTestEngine
from app.security_testing.errors import AuthorizationDeniedError
from app.security_testing.failures import ToolExecutionResult, ToolExecutionState
from app.security_testing.sanitization import wrap_untrusted
from app.security_testing.secrets import redact_text


@dataclass(frozen=True)
class NucleiTemplatePolicy:
    allowed_tags: tuple[str, ...] = ("misconfig", "exposure", "tech")
    denied_tags: tuple[str, ...] = ("dos", "intrusive", "takeover")
    max_severity: str = "medium"
    deny_all: bool = False

    _ORDER = ("info", "low", "medium", "high", "critical")

    def allows(self, *, tags: Sequence[str], severity: str) -> bool:
        if self.deny_all:
            return False
        lowered = {tag.lower() for tag in tags}
        if lowered & {tag.lower() for tag in self.denied_tags}:
            return False
        if self.allowed_tags and not (lowered & {tag.lower() for tag in self.allowed_tags}):
            if lowered:
                return False
        sev = severity.lower()
        if sev not in self._ORDER:
            return False
        return self._ORDER.index(sev) <= self._ORDER.index(self.max_severity.lower())


class NucleiAdapter(SecurityToolAdapter):
    def __init__(
        self,
        *,
        engine: SecurityTestEngine | None = None,
        policy: NucleiTemplatePolicy | None = None,
    ) -> None:
        self._engine = engine
        self.policy = policy or NucleiTemplatePolicy()

    @property
    def tool_id(self) -> str:
        return "nuclei"

    @property
    def display_name(self) -> str:
        return "Nuclei"

    def is_available(self) -> bool:
        return shutil.which("nuclei") is not None

    def capabilities(self) -> frozenset[SecurityToolCapability]:
        return frozenset(
            {SecurityToolCapability.PASSIVE_EVIDENCE, SecurityToolCapability.ACTIVE_SCAN}
        )

    def attach_engine(self, engine: SecurityTestEngine) -> None:
        self._engine = engine

    def health(self) -> ToolExecutionResult:
        if not self.is_available():
            return ToolExecutionResult(tool="nuclei", state=ToolExecutionState.TOOL_UNAVAILABLE)
        return ToolExecutionResult(
            tool="nuclei", state=ToolExecutionState.OK, detail="nuclei on PATH"
        )

    def ingest_jsonl(self, payload: str | Path) -> list[Evidence]:
        text = Path(payload).read_text(encoding="utf-8") if isinstance(payload, Path) else payload
        evidence: list[Evidence] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            info_raw = row.get("info")
            info = info_raw if isinstance(info_raw, dict) else {}
            severity = str(info.get("severity") or row.get("severity") or "info")
            tags_raw = info.get("tags")
            tags = tags_raw if isinstance(tags_raw, list) else []
            template_id = str(
                row.get("template-id") or row.get("templateID") or info.get("name") or ""
            )
            if not self.policy.allows(tags=[str(t) for t in tags], severity=severity):
                continue
            matched = str(row.get("matched-at") or row.get("host") or row.get("url") or "")
            evidence.append(
                Evidence(
                    kind=EvidenceKind.SCANNER,
                    source="nuclei",
                    summary=redact_text(f"{template_id} {severity} {matched}").strip(),
                    details=wrap_untrusted("nuclei", json.dumps(row, default=str)[:4000]),
                    metadata={
                        "template_id": template_id,
                        "severity": severity,
                        "endpoint": matched,
                    },
                )
            )
        return evidence

    def validate_targets(self, targets: Sequence[str]) -> list[str]:
        if self._engine is None:
            raise AuthorizationDeniedError("Nuclei requires a SecurityTestEngine", tool="nuclei")
        return self._engine.runner.authorize_targets(list(targets), tool="nuclei", active=True)

    def _collect_passive_evidence(self, *, scope: ScopeConstraint) -> Sequence[Evidence]:
        return ()

    def active_scan(self, *, scope: ScopeConstraint, target: str) -> Sequence[Evidence]:
        if self._engine is None:
            from app.adapters.scope.authorization import require_active_testing

            require_active_testing(scope, target)
            return ()
        allowed = self.validate_targets([target])
        if not allowed:
            return []
        if not self.is_available():
            return [
                Evidence(
                    kind=EvidenceKind.LOG,
                    source="nuclei",
                    summary="Nuclei binary not installed; targets validated but not scanned",
                )
            ]
        return [
            Evidence(
                kind=EvidenceKind.SCANNER,
                source="nuclei",
                summary=f"Nuclei scan authorized for {target}",
            )
        ]
