"""OWASP ZAP adapter using the Automation Framework (YAML plans) plus alert ingest."""

from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from pathlib import Path

from app.adapters.security_tools.base import SecurityToolAdapter, SecurityToolCapability
from app.domain.evidence import Evidence, EvidenceKind
from app.domain.scope import ScopeConstraint
from app.security_testing.engine import SecurityTestEngine
from app.security_testing.errors import AuthorizationDeniedError
from app.security_testing.failures import ToolExecutionResult, ToolExecutionState
from app.security_testing.sanitization import wrap_untrusted
from app.security_testing.secrets import redact_text


class ZapAdapter(SecurityToolAdapter):
    def __init__(self, *, engine: SecurityTestEngine | None = None) -> None:
        self._engine = engine

    @property
    def tool_id(self) -> str:
        return "zap"

    @property
    def display_name(self) -> str:
        return "OWASP ZAP"

    def is_available(self) -> bool:
        return shutil.which("zap.sh") is not None or shutil.which("zap-cli") is not None

    def capabilities(self) -> frozenset[SecurityToolCapability]:
        return frozenset(
            {SecurityToolCapability.PASSIVE_EVIDENCE, SecurityToolCapability.ACTIVE_SCAN}
        )

    def attach_engine(self, engine: SecurityTestEngine) -> None:
        self._engine = engine

    def automation_plan(
        self,
        target: str,
        *,
        spider: bool = True,
        active: bool = False,
        max_duration_minutes: int = 5,
    ) -> str:
        """YAML plan whose targets must already have passed ScopeGuard."""
        jobs: list[dict[str, object]] = [
            {
                "type": "passiveScan-wait",
                "parameters": {"maxDuration": max_duration_minutes},
            }
        ]
        if spider:
            jobs.insert(0, {"type": "spider", "parameters": {"url": target, "maxDuration": 2}})
        if active:
            jobs.append(
                {
                    "type": "activeScan",
                    "parameters": {"url": target, "maxDuration": max_duration_minutes},
                }
            )
        # Keep this as YAML-ish text without requiring PyYAML.
        lines = [
            "env:",
            "  contexts:",
            "    - name: bugforge",
            "      urls:",
            f"        - {target}",
            "jobs:",
        ]
        for job in jobs:
            lines.append(f"  - type: {job['type']}")
            params = job.get("parameters", {})
            if isinstance(params, dict) and params:
                lines.append("    parameters:")
                for key, value in params.items():
                    lines.append(f"      {key}: {value}")
        return "\n".join(lines) + "\n"

    def ingest_alerts(
        self, payload: str | Path | dict[str, object] | list[object]
    ) -> list[Evidence]:
        data: object
        if isinstance(payload, Path):
            data = json.loads(payload.read_text(encoding="utf-8"))
        elif isinstance(payload, str):
            data = json.loads(payload)
        else:
            data = payload
        alerts: list[object]
        if isinstance(data, dict):
            site = data.get("site")
            if isinstance(site, list) and site and isinstance(site[0], dict):
                alerts = list(site[0].get("alerts") or [])
            else:
                alerts = list(data.get("alerts") or [])
        elif isinstance(data, list):
            alerts = data
        else:
            alerts = []
        evidence: list[Evidence] = []
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            name = redact_text(str(alert.get("alert") or alert.get("name") or "zap-alert"))
            url = redact_text(str(alert.get("url") or ""))
            evidence.append(
                Evidence(
                    kind=EvidenceKind.SCANNER,
                    source="zap",
                    summary=f"{name} @ {url}".strip(),
                    details=wrap_untrusted("zap", str(alert.get("description") or "")),
                    metadata={
                        "risk": str(alert.get("risk") or alert.get("riskcode") or ""),
                        "pluginid": str(alert.get("pluginid") or ""),
                    },
                )
            )
        return evidence

    def _collect_passive_evidence(self, *, scope: ScopeConstraint) -> Sequence[Evidence]:
        return ()

    def active_scan(self, *, scope: ScopeConstraint, target: str) -> Sequence[Evidence]:
        if self._engine is None:
            from app.adapters.scope.authorization import require_active_testing

            require_active_testing(scope, target)
            return ()
        decision = self._engine.authorize(
            target,
            method="GET",
            tool="zap",
            active=True,
            require_live_scan_approval=self._engine.mode.value == "live",
            high_risk=True,
        )
        if not decision.allowed:
            raise AuthorizationDeniedError(decision.reason, target=target, tool="zap")
        _plan = self.automation_plan(target, spider=True, active=True)
        if not self.is_available():
            return [
                Evidence(
                    kind=EvidenceKind.LOG,
                    source="zap",
                    summary="ZAP binary not installed; plan generated but not executed",
                    details=_plan,
                )
            ]
        # Never let ZAP's own target list override BugForge scope: only `target` is used.
        return [
            Evidence(
                kind=EvidenceKind.SCANNER,
                source="zap",
                summary=f"ZAP active scan authorized for {target} (execution delegated)",
                details=wrap_untrusted("zap-plan", _plan),
            )
        ]

    def unavailable(self) -> ToolExecutionResult:
        return ToolExecutionResult(tool="zap", state=ToolExecutionState.TOOL_UNAVAILABLE)
