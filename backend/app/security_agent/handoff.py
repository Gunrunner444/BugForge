"""Prepare a verified finding for the existing HackerOne workflow. Human still approves."""

from __future__ import annotations

from typing import Any

from app.domain.findings import SecurityFinding
from app.security_agent.agent import ResearchSession
from app.security_agent.export import export_package
from app.security_testing.errors import RestrictedActivityError


def prepare_hackerone_handoff(session: ResearchSession, finding: SecurityFinding) -> dict[str, Any]:
    if not finding.is_verified:
        raise RestrictedActivityError("handoff_requires_verified_finding")
    matched = None
    for rule in session.engine.session.scope.includes:
        if finding.target and rule.identifier in (finding.target or ""):
            matched = rule
            break
    return {
        "target": finding.target or session.target,
        "scope_match": matched.identifier if matched else "",
        "structured_scope_id": matched.structured_scope_id if matched else None,
        "weakness_candidate": finding.vulnerability_class,
        "severity_candidate": finding.impact or finding.confidence,
        "reproduction": finding.reproduction or finding.observed_behavior,
        "evidence_package": export_package(session, finding),
        "sanitized_report_candidate": {
            "title": finding.report_title or finding.title,
            "description": finding.report_description or finding.description,
        },
        "cannot_approve": True,
        "cannot_submit": True,
    }
