"""Relevance-selected model context. Never dump the whole repository."""

from __future__ import annotations

from typing import Any

from app.security_agent.injection import TRUSTED_CHANNEL, channel
from app.security_agent.states import EvidenceGraphKind
from app.security_testing.secrets import redact_text


class ContextManager:
    """Build the next model turn from relevant evidence, not a 5-event summary."""

    def build(self, session: Any) -> dict[str, Any]:
        graph = session.graph
        hypotheses = list(session.hypotheses)
        supported = [item for item in hypotheses if item.supporting_evidence_ids]
        contradicted = [item for item in hypotheses if item.contradicting_evidence_ids]
        relevant_nodes = graph.relevant(
            limit=16,
            kinds=(
                EvidenceGraphKind.OBSERVATION.value,
                EvidenceGraphKind.SCANNER_RESULT.value,
                EvidenceGraphKind.BROWSER_OBSERVATION.value,
                EvidenceGraphKind.SOURCE.value,
                EvidenceGraphKind.REQUEST.value,
                EvidenceGraphKind.RESPONSE.value,
                EvidenceGraphKind.REPRODUCTION.value,
            ),
        )
        exchanges = list(getattr(session, "exchanges", {}).values())[-8:]
        reproductions = [
            node.snapshot()
            for node in graph.nodes.values()
            if node.kind == EvidenceGraphKind.REPRODUCTION.value
        ][-6:]
        scope = session.engine.session.scope
        trusted = {
            "target": session.target,
            "mode": session.mode.value,
            "state": session.state.value,
            "program": session.program_handle,
            "scope_instructions": scope.instructions,
            "scope_includes": [rule.identifier for rule in scope.includes][:40],
            "remaining_budget": session.budget.remaining(),
            "disabled_tools": sorted(session.disabled_tools),
            "termination_reason": getattr(session, "termination_reason", None)
            and session.termination_reason.value,
        }
        untrusted = {
            "source_excerpts": [
                node.snapshot()
                for node in relevant_nodes
                if node.kind == EvidenceGraphKind.SOURCE.value
            ],
            "evidence": [node.snapshot() for node in relevant_nodes],
            "http_exchanges": exchanges,
            "scanner_results": [
                node.snapshot()
                for node in relevant_nodes
                if node.kind == EvidenceGraphKind.SCANNER_RESULT.value
            ],
            "browser_observations": [
                node.snapshot()
                for node in relevant_nodes
                if node.kind == EvidenceGraphKind.BROWSER_OBSERVATION.value
            ],
            "hypotheses": [item.snapshot() for item in hypotheses[-8:]],
            "contradictions": [item.snapshot() for item in contradicted],
            "supported": [item.snapshot() for item in supported],
            "reproduction": reproductions,
            "recent_actions": [item.snapshot() for item in session.timeline[-12:]],
        }
        return {
            "trusted": trusted,
            "untrusted": untrusted,
        }

    def for_model(self, session: Any) -> str:
        payload = self.build(session)
        trusted = channel(
            TRUSTED_CHANNEL,
            redact_text(_compact(payload["trusted"])),
            trusted=True,
        )
        untrusted_blocks = []
        mapping = {
            "source_excerpts": "UNTRUSTED_SOURCE",
            "evidence": "UNTRUSTED_EVIDENCE",
            "http_exchanges": "UNTRUSTED_HTTP",
            "scanner_results": "UNTRUSTED_SCANNER",
            "browser_observations": "UNTRUSTED_BROWSER",
            "hypotheses": "UNTRUSTED_EVIDENCE",
            "contradictions": "UNTRUSTED_EVIDENCE",
            "supported": "UNTRUSTED_EVIDENCE",
            "reproduction": "UNTRUSTED_EVIDENCE",
            "recent_actions": "UNTRUSTED_EVIDENCE",
        }
        untrusted = payload["untrusted"]
        for key, label in mapping.items():
            untrusted_blocks.append(channel(label, redact_text(_compact(untrusted.get(key)))))
        return trusted + "\n\n" + "\n\n".join(untrusted_blocks)


def _compact(value: object, *, limit: int = 6000) -> str:
    text = str(value)
    return text[:limit]
