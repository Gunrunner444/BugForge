"""Deterministic sanitized evidence export packages."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from app.domain.findings import SecurityFinding
from app.security_agent.agent import ResearchSession
from app.security_testing.secrets import redact_text


def export_package(
    session: ResearchSession, finding: SecurityFinding | None = None
) -> dict[str, Any]:
    graph = session.graph.snapshot()
    package = {
        "finding": None
        if finding is None
        else {
            "id": str(finding.id),
            "title": finding.title,
            "status": finding.status.value,
            "target": finding.target,
            "vulnerability_class": finding.vulnerability_class,
        },
        "hypotheses": [item.snapshot() for item in session.hypotheses],
        "evidence_graph": graph,
        "http_exchanges": [
            json.loads(redact_text(json.dumps(item, default=str)))
            for item in session.exchanges.values()
        ],
        "reproductions": [
            node.snapshot() for node in session.graph.nodes.values() if node.kind == "reproduction"
        ],
        "source_references": [
            node.snapshot() for node in session.graph.nodes.values() if node.kind == "source"
        ],
        "tool_results": [
            item.snapshot() if hasattr(item, "snapshot") else {"tool": item}
            for item in getattr(session, "tool_call_records", session.tool_history)
        ],
        "timestamps": {
            "session_created": session.created_at.isoformat(),
        },
        "scope": {
            "program": session.program_handle,
            "mode": session.mode.value,
        },
    }
    raw = json.dumps(package, sort_keys=True, separators=(",", ":"), default=str)
    package["hashes"] = {"sha256": sha256(raw.encode("utf-8")).hexdigest()}
    return package
