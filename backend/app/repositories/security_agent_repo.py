"""Persist research sessions. Secrets are never stored."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.ai import get_provider
from app.models.security_agent import (
    DBResearchEvidenceEdge,
    DBResearchEvidenceNode,
    DBResearchHypothesis,
    DBResearchSession,
    DBResearchTimelineEvent,
    DBResearchToolCall,
)
from app.security_agent.agent import (
    FingerprintRecord,
    ResearchSession,
    SecurityResearchAgent,
    TimelineEvent,
)
from app.security_agent.budget import SessionBudget
from app.security_agent.evidence_graph import EvidenceGraph
from app.security_agent.privilege import (
    PrivilegeSnapshot,
    apply_privilege_snapshot,
    capture_privileges,
    expire_stale_privileges,
    intersect_privileges,
    program_scope_from_hackerone,
)
from app.security_agent.schemas import ResearchHypothesis
from app.security_agent.states import (
    HypothesisStatus,
    ResearchMode,
    ResearchState,
    TerminationReason,
)
from app.security_testing.engine import SecurityTestEngine, SecurityTestSession, TestingMode
from app.security_testing.safety import SafetyLimits
from app.security_testing.scope_model import ProgramScope
from app.security_testing.secrets import redact_text


class SecurityAgentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_session(self, session: ResearchSession) -> None:
        row = await self._session.get(DBResearchSession, session.id)
        if row is None:
            row = DBResearchSession(id=session.id)
            self._session.add(row)
        row.project_id = UUID(session.project_id) if _is_uuid(session.project_id) else None
        row.program_handle = session.program_handle
        row.target = session.target
        row.mode = session.mode.value
        row.state = session.state.value
        row.model_provider = session.provider.provider_name
        row.model_name = session.model_name or session.provider.model_name
        row.model_config = {"thinking": session.thinking_enabled}
        row.budget = session.budget.snapshot()
        row.usage = {
            "tokens": session.budget.tokens,
            "scan_seconds": session.budget.scan_seconds,
        }
        row.error = session.error
        row.paused_reason = "paused" if session.paused else None
        row.termination_reason = (
            session.termination_reason.value if session.termination_reason else None
        )
        row.privilege_snapshot = (
            session.privilege.as_dict()
            if session.privilege
            else capture_privileges(
                session.engine,
                mode=session.mode,
                program_handle=session.program_handle,
                disabled_tools=session.disabled_tools,
            ).as_dict()
        )
        row.disabled_tools = sorted(session.disabled_tools)
        row.repo_root = session.repo_root
        row.stopped = session.stopped
        row.exchanges = session.exchanges
        row.updated_at = datetime.now(UTC)
        await self._session.flush()
        for hyp in session.hypotheses:
            existing = await self._session.get(DBResearchHypothesis, hyp.id)
            if existing is None:
                existing = DBResearchHypothesis(id=hyp.id, session_id=session.id)
                self._session.add(existing)
            existing.title = hyp.title
            existing.vulnerability_class = hyp.vulnerability_class
            existing.target = hyp.target
            existing.reason = redact_text(hyp.reason)
            existing.confidence = hyp.confidence
            existing.severity = hyp.severity
            existing.impact = redact_text(hyp.impact)
            existing.reproducibility = hyp.reproducibility
            existing.evidence_strength = hyp.evidence_strength
            existing.supporting_evidence_ids = list(hyp.supporting_evidence_ids)
            existing.contradicting_evidence_ids = list(hyp.contradicting_evidence_ids)
            existing.suggested_next_action = hyp.suggested_next_action
            existing.status = hyp.status.value
        await self._session.execute(
            delete(DBResearchTimelineEvent).where(DBResearchTimelineEvent.session_id == session.id)
        )
        await self._session.execute(
            delete(DBResearchToolCall).where(DBResearchToolCall.session_id == session.id)
        )
        await self._session.execute(
            delete(DBResearchEvidenceNode).where(DBResearchEvidenceNode.session_id == session.id)
        )
        await self._session.execute(
            delete(DBResearchEvidenceEdge).where(DBResearchEvidenceEdge.session_id == session.id)
        )
        for event in session.timeline:
            self._session.add(
                DBResearchTimelineEvent(
                    session_id=session.id,
                    event_type=event.event_type,
                    decision=redact_text(event.decision),
                    tool=event.tool,
                    target=event.target,
                    authorization=event.authorization,
                    result=redact_text(event.result),
                    evidence_id=event.evidence_id,
                    finding_id=event.finding_id,
                    created_at=event.created_at,
                )
            )
        for record in session.fingerprint_records or []:
            tool, _, rest = record.fingerprint.partition(":")
            self._session.add(
                DBResearchToolCall(
                    id=uuid4().hex,
                    session_id=session.id,
                    tool=tool,
                    arguments={"fingerprint": redact_text(record.fingerprint)[:500]},
                    reason=record.quality,
                    authorization="",
                    authorization_reason="",
                    result_summary=redact_text(rest)[:500],
                )
            )
        if not session.fingerprint_records:
            for fingerprint in session.fingerprints:
                tool, _, rest = fingerprint.partition(":")
                self._session.add(
                    DBResearchToolCall(
                        id=uuid4().hex,
                        session_id=session.id,
                        tool=tool,
                        arguments={"fingerprint": redact_text(fingerprint)[:500]},
                        reason="",
                        authorization="",
                        authorization_reason="",
                        result_summary=redact_text(rest)[:500],
                    )
                )
        for node in session.graph.nodes.values():
            self._session.add(
                DBResearchEvidenceNode(
                    id=node.id,
                    session_id=session.id,
                    project_id=session.project_id,
                    kind=node.kind,
                    provenance=node.provenance,
                    summary=redact_text(node.summary),
                    source=node.source,
                    extra=node.extra,
                    created_at=node.created_at,
                )
            )
        for src, dst, rel in session.graph.edges:
            self._session.add(
                DBResearchEvidenceEdge(
                    id=uuid4().hex,
                    session_id=session.id,
                    source_node=src,
                    destination_node=dst,
                    relation=rel,
                )
            )
        await self._session.flush()

    async def load_row(self, session_id: str) -> DBResearchSession | None:
        result = await self._session.execute(
            select(DBResearchSession)
            .options(
                selectinload(DBResearchSession.hypotheses),
                selectinload(DBResearchSession.timeline),
                selectinload(DBResearchSession.tool_calls),
                selectinload(DBResearchSession.evidence_nodes),
                selectinload(DBResearchSession.evidence_edges),
            )
            .where(DBResearchSession.id == session_id)
        )
        return result.scalar_one_or_none()

    async def reconstruct(
        self,
        session_id: str,
        *,
        current_program: Any | None = None,
    ) -> SecurityResearchAgent | None:
        row = await self.load_row(session_id)
        if row is None:
            return None
        mode = ResearchMode(row.mode)
        persisted = PrivilegeSnapshot.from_dict(row.privilege_snapshot)
        engine = await _engine_for_restore(row, mode, persisted, current_program)
        budget = SessionBudget.from_settings()
        budget.restore(row.budget)
        graph = EvidenceGraph(session_id=row.id, project_id=str(row.project_id or ""))
        for node in row.evidence_nodes:
            graph.add(
                kind=node.kind,
                provenance=node.provenance,
                summary=node.summary,
                source=node.source,
                extra=node.extra or {},
                node_id=node.id,
                created_at=node.created_at,
            )
            stored = graph.nodes[node.id]
            stored.session_id = row.id
            stored.project_id = node.project_id
        for edge in row.evidence_edges:
            graph.edges.append((edge.source_node, edge.destination_node, edge.relation))
        research = ResearchSession(
            id=row.id,
            project_id=str(row.project_id or ""),
            target=row.target,
            mode=mode,
            engine=engine,
            provider=get_provider(),
            program_handle=row.program_handle,
            state=ResearchState(row.state),
            model_name=row.model_name,
            thinking_enabled=bool((row.model_config or {}).get("thinking", True)),
            budget=budget,
            graph=graph,
            error=row.error,
            paused=bool(row.paused_reason),
            stopped=bool(row.stopped),
            repo_root=row.repo_root or ".",
            exchanges=dict(row.exchanges or {}),
            created_at=row.created_at,
            disabled_tools=set(row.disabled_tools or []),
        )
        if row.termination_reason:
            try:
                research.termination_reason = TerminationReason(row.termination_reason)
            except ValueError:
                research.termination_reason = TerminationReason.FAILED
        for hyp in row.hypotheses:
            research.hypotheses.append(
                ResearchHypothesis(
                    id=hyp.id,
                    title=hyp.title,
                    vulnerability_class=hyp.vulnerability_class,
                    target=hyp.target,
                    reason=hyp.reason,
                    confidence=hyp.confidence,
                    severity=getattr(hyp, "severity", "medium"),
                    impact=getattr(hyp, "impact", ""),
                    supporting_evidence_ids=tuple(hyp.supporting_evidence_ids or ()),
                    contradicting_evidence_ids=tuple(hyp.contradicting_evidence_ids or ()),
                    suggested_next_action=hyp.suggested_next_action,
                    status=HypothesisStatus(hyp.status),
                    reproducibility=getattr(hyp, "reproducibility", "unknown"),
                    evidence_strength=int(getattr(hyp, "evidence_strength", 0) or 0),
                )
            )
        for event in row.timeline:
            research.timeline.append(
                TimelineEvent(
                    event_type=event.event_type,
                    decision=event.decision,
                    tool=event.tool,
                    target=event.target,
                    authorization=event.authorization,
                    result=event.result,
                    evidence_id=event.evidence_id,
                    finding_id=event.finding_id,
                    created_at=event.created_at,
                )
            )
        for call in row.tool_calls:
            fingerprint = str((call.arguments or {}).get("fingerprint") or call.tool)
            research.fingerprints.append(fingerprint)
            research.fingerprint_records.append(
                FingerprintRecord(
                    fingerprint=fingerprint,
                    at=call.created_at,
                    quality=call.reason or "success",
                )
            )
        agent = SecurityResearchAgent(research)
        agent.tools.restore_disabled(sorted(research.disabled_tools))
        agent._refresh_privilege()
        return agent


async def _engine_for_restore(
    row: DBResearchSession,
    mode: ResearchMode,
    persisted: PrivilegeSnapshot | None,
    current_program: Any | None,
) -> SecurityTestEngine:
    if mode is ResearchMode.LAB:
        snapshot = expire_stale_privileges(persisted) if persisted else None
        allow_active = bool(snapshot.active_testing) if snapshot else False
        engine = SecurityTestEngine.lab(
            str(row.project_id or "lab"),
            allow_active_testing=allow_active,
            limits=SafetyLimits.lab(),
        )
        if snapshot:
            apply_privilege_snapshot(engine, snapshot)
        return engine
    handle = row.program_handle
    if current_program is not None:
        current_scope = program_scope_from_hackerone(current_program)
        current_handle = current_program.handle
    else:
        current_scope = ProgramScope(program_name=handle, lab_mode=False)
        current_handle = handle
    if persisted:
        snapshot = intersect_privileges(
            persisted, current_scope=current_scope, current_program_handle=current_handle
        )
    else:
        snapshot = PrivilegeSnapshot(
            mode=mode.value,
            program_handle=current_handle,
            scope_hash="",
            active_testing=False,
            fuzzing=False,
            dry_run=True,
        )
    engine = SecurityTestEngine(
        SecurityTestSession(
            project_id=str(row.project_id or handle or "live"),
            mode=TestingMode.LIVE,
            scope=current_scope,
            limits=SafetyLimits.conservative(),
            dry_run=snapshot.dry_run,
            active_testing_enabled=False,
        )
    )
    apply_privilege_snapshot(engine, snapshot)
    return engine


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
        return True
    except ValueError:
        return False
