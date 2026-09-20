"""Persist research sessions. Secrets are never stored."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.ai.restore import restore_provider, snapshot_provider
from app.domain.evidence import Evidence, EvidenceBundle, EvidenceKind, EvidenceProvenance
from app.domain.findings import FindingStatus, SecurityFinding
from app.models.security_agent import (
    DBResearchCheckpoint,
    DBResearchEvidenceEdge,
    DBResearchEvidenceLink,
    DBResearchEvidenceNode,
    DBResearchFinding,
    DBResearchHypothesis,
    DBResearchIdentity,
    DBResearchMemory,
    DBResearchProject,
    DBResearchSession,
    DBResearchTimelineEvent,
    DBResearchToolCall,
)
from app.security_agent.agent import (
    FingerprintRecord,
    ResearchSession,
    SecurityResearchAgent,
    TimelineEvent,
    ToolCallRecord,
)
from app.security_agent.budget import SessionBudget
from app.security_agent.checkpoints import ResearchCheckpoint
from app.security_agent.evidence_graph import EvidenceGraph, GraphIntegrityError
from app.security_agent.identities import IdentityPair, ResearchIdentity
from app.security_agent.memory import ResearchMemory
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
        row.model_config = snapshot_provider(session.provider, thinking=session.thinking_enabled)
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
        row.exchanges = _redact_json(session.exchanges)
        row.operator_identity = session.operator_identity
        row.research_project_id = session.research_project_id
        row.human_overrides = {"strategy": session.strategy, "next_action": session.next_action}
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
        await self._session.execute(
            delete(DBResearchEvidenceLink).where(DBResearchEvidenceLink.session_id == session.id)
        )
        await self._session.execute(
            delete(DBResearchFinding).where(DBResearchFinding.session_id == session.id)
        )
        await self._session.execute(
            delete(DBResearchIdentity).where(DBResearchIdentity.session_id == session.id)
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
        records = list(session.tool_call_records)
        if not records:
            for fingerprint in session.fingerprints:
                tool, _, rest = fingerprint.partition(":")
                records.append(
                    ToolCallRecord(
                        tool=tool,
                        arguments={"fingerprint": redact_text(fingerprint)[:500]},
                        result_summary=redact_text(rest)[:500],
                        execution_state="unknown",
                    )
                )
        for record in records:
            self._session.add(
                DBResearchToolCall(
                    id=record.id,
                    session_id=session.id,
                    tool=record.tool,
                    arguments=_redact_json(record.arguments),
                    reason=redact_text(record.reason),
                    authorization=record.authorization,
                    authorization_reason=redact_text(record.authorization_reason),
                    result_summary=redact_text(record.result_summary)[:2000],
                    execution_state=record.execution_state,
                    result_quality=record.result_quality,
                    evidence_ids=list(record.evidence_ids),
                    error=redact_text(record.error) if record.error else None,
                    created_at=record.created_at,
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
            self._session.add(
                DBResearchEvidenceLink(
                    id=uuid4().hex,
                    session_id=session.id,
                    hypothesis_id=src if rel in {"supports", "contradicted_by"} else "",
                    evidence_id=dst,
                    tool_call_id=src if rel in {"produced", "executes", "observes"} else "",
                    finding_id="",
                    kind=rel,
                    provenance=rel,
                    summary=f"{src}->{dst}:{rel}",
                    extra={"source": src, "destination": dst, "relation": rel},
                )
            )
        for finding in session.findings:
            self._session.add(_finding_row(session, finding))
        pair = session.identities
        if pair is not None:
            from app.security_agent.secrets import secrets_for

            store = secrets_for(session.id)
            for ident in (pair.context_a, pair.context_b):
                ident.ingest_secrets(store)
                snap = ident.snapshot()
                self._session.add(
                    DBResearchIdentity(
                        id=ident.id,
                        session_id=session.id,
                        label=ident.label,
                        credential_ref=ident.credential_ref,
                        browser_context_id=ident.browser_context_id,
                        http_session_id=ident.http_session_id,
                        storage_namespace=ident.storage_namespace,
                        authentication_state=ident.authentication_state,
                        credential_provenance=ident.credential_provenance,
                        header_names=list(ident.header_names),
                        header_secret_refs=dict(ident.header_secret_refs),
                        cookie_names=list(ident.cookie_names),
                        cookie_secret_ref=ident.cookie_secret_ref,
                        storage_keys=list(ident.storage_keys),
                        storage_secret_ref=ident.storage_secret_ref,
                    )
                )
                del snap
        memory = session.memory
        if memory is not None:
            await self._session.execute(
                delete(DBResearchMemory).where(DBResearchMemory.session_id == session.id)
            )
            for entry in memory.entries:
                self._session.add(
                    DBResearchMemory(
                        id=entry.id,
                        project_id=session.project_id,
                        session_id=session.id,
                        kind=entry.kind,
                        summary=redact_text(entry.summary),
                        payload=_redact_json(entry.extra),
                    )
                )
        await self._session.flush()

    async def save_checkpoint(self, session: ResearchSession, *, label: str = "") -> str:
        checkpoint = ResearchCheckpoint.capture(session, label=label)
        self._session.add(
            DBResearchCheckpoint(
                id=checkpoint.id,
                session_id=session.id,
                label=checkpoint.label,
                snapshot=_redact_json(checkpoint.snapshot),
            )
        )
        await self._session.flush()
        return checkpoint.id

    async def save_project(self, project: Any) -> None:
        row = await self._session.get(DBResearchProject, project.id)
        if row is None:
            row = DBResearchProject(id=project.id)
            self._session.add(row)
        row.name = project.name
        row.project_id = project.project_id
        row.session_id = project.session_id or None
        row.program_handle = project.program_handle
        row.target = project.target
        row.mode = project.mode
        row.strategy = project.strategy
        row.state = project.state.value if hasattr(project.state, "value") else str(project.state)
        row.operator_identity = project.operator_identity
        if getattr(project, "created_at", None) is not None:
            row.created_at = project.created_at
        row.updated_at = datetime.now(UTC)
        await self._session.flush()

    async def load_project(self, project_id: str) -> DBResearchProject | None:
        return await self._session.get(DBResearchProject, project_id)

    async def load_row(self, session_id: str) -> DBResearchSession | None:
        result = await self._session.execute(
            select(DBResearchSession)
            .options(
                selectinload(DBResearchSession.hypotheses),
                selectinload(DBResearchSession.timeline),
                selectinload(DBResearchSession.tool_calls),
                selectinload(DBResearchSession.evidence_nodes),
                selectinload(DBResearchSession.evidence_edges),
                selectinload(DBResearchSession.evidence_links),
                selectinload(DBResearchSession.findings),
                selectinload(DBResearchSession.identities),
                selectinload(DBResearchSession.memories),
                selectinload(DBResearchSession.checkpoints),
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
            if edge.source_node == edge.destination_node:
                continue
            try:
                graph.link(edge.source_node, edge.destination_node, edge.relation)
            except GraphIntegrityError:
                continue
        overrides = row.human_overrides if isinstance(row.human_overrides, dict) else {}
        research = ResearchSession(
            id=row.id,
            project_id=str(row.project_id or ""),
            target=row.target,
            mode=mode,
            engine=engine,
            provider=restore_provider(row.model_config),
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
            next_action=overrides.get("next_action")
            if isinstance(overrides.get("next_action"), dict)
            else None,
            strategy=str(overrides.get("strategy") or "passive_recon"),
            operator_identity=row.operator_identity or "",
            research_project_id=row.research_project_id or "",
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
            record = ToolCallRecord(
                id=call.id,
                tool=call.tool,
                arguments=dict(call.arguments or {}),
                reason=call.reason,
                authorization=call.authorization,
                authorization_reason=call.authorization_reason,
                execution_state=call.execution_state,
                result_quality=call.result_quality,
                result_summary=call.result_summary,
                evidence_ids=tuple(call.evidence_ids or ()),
                error=call.error,
                created_at=call.created_at,
            )
            research.tool_call_records.append(record)
            fingerprint = (
                f"{call.tool}:{json.dumps(call.arguments or {}, sort_keys=True, default=str)}"
            )
            research.fingerprints.append(fingerprint)
            research.fingerprint_records.append(
                FingerprintRecord(
                    fingerprint=fingerprint,
                    at=call.created_at,
                    quality=call.result_quality or call.reason or "success",
                )
            )
            research.tool_history.append(call.tool)
        for finding_row in row.findings:
            research.findings.append(_finding_from_row(finding_row, graph=graph))
        pair = IdentityPair()
        for ident in row.identities:
            auth_state = ident.authentication_state or "unauthenticated"
            if ident.cookie_secret_ref or ident.header_secret_refs:
                from app.security_agent.secrets import secrets_for

                store = secrets_for(row.id)
                available = all(
                    store.available(ref)
                    for ref in (
                        [ident.cookie_secret_ref, ident.storage_secret_ref]
                        + list((ident.header_secret_refs or {}).values())
                    )
                    if ref
                )
                if not available:
                    auth_state = "unavailable"
            obj = ResearchIdentity(
                id=ident.id,
                label=ident.label,
                credential_ref=ident.credential_ref or "",
                browser_context_id=ident.browser_context_id or "",
                http_session_id=ident.http_session_id or "",
                storage_namespace=ident.storage_namespace or "",
                authentication_state=auth_state,
                credential_provenance=ident.credential_provenance or "none",
                header_names=tuple(ident.header_names or ()),
                header_secret_refs=dict(ident.header_secret_refs or {}),
                cookie_names=tuple(ident.cookie_names or ()),
                cookie_secret_ref=ident.cookie_secret_ref or "",
                storage_keys=tuple(ident.storage_keys or ()),
                storage_secret_ref=ident.storage_secret_ref or "",
            )
            if ident.label.upper() == "B":
                pair.context_b = obj
            else:
                pair.context_a = obj
        research.identities = pair
        memory = ResearchMemory(project_id=str(row.project_id or ""))
        for item in row.memories:
            memory.restore_entry(
                entry_id=item.id,
                kind=item.kind,
                summary=item.summary,
                extra=dict(item.payload or {}),
            )
        research.memory = memory
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
        if not current_program.structured_scopes:
            current_scope = ProgramScope(program_name=current_handle, lab_mode=False)
    else:
        # Live restore without a current program record: empty scope (fail closed).
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
            dry_run=True,
            active_testing_enabled=False,
        )
    )
    apply_privilege_snapshot(engine, snapshot)
    return engine


def _finding_row(session: ResearchSession, finding: SecurityFinding) -> DBResearchFinding:
    evidence_items = [
        {
            "kind": item.kind.value,
            "provenance": item.provenance.value if item.provenance is not None else "",
            "summary": redact_text(item.summary),
            "source": item.source,
        }
        for item in finding.evidence.items
    ]
    return DBResearchFinding(
        id=str(finding.id),
        session_id=session.id,
        project_id=session.project_id,
        hypothesis_id=str(finding.hypothesis or ""),
        title=finding.title,
        status=finding.status.value,
        vulnerability_class=finding.vulnerability_class or "",
        target=finding.target or "",
        verification_state=finding.status.value,
        evidence_ids=list(finding.observation_refs),
        reproduction_ids=[
            node.id for node in session.graph.nodes.values() if node.kind == "reproduction"
        ],
        confidence=finding.confidence,
        severity=finding.impact or "medium",
        impact=finding.impact or "",
        extra={"evidence_items": evidence_items},
        created_at=finding.created_at,
    )


def _finding_from_row(
    row: DBResearchFinding, *, graph: EvidenceGraph | None = None
) -> SecurityFinding:
    extra = row.extra if isinstance(row.extra, dict) else {}
    items: list[Evidence] = []
    for raw in extra.get("evidence_items") or []:
        if not isinstance(raw, dict):
            continue
        try:
            kind = EvidenceKind(str(raw.get("kind") or "reproduction"))
        except ValueError:
            kind = EvidenceKind.REPRODUCTION
        try:
            provenance = EvidenceProvenance(str(raw.get("provenance") or "execution"))
        except ValueError:
            provenance = EvidenceProvenance.EXECUTION
        if provenance is EvidenceProvenance.REPLAY:
            kind = EvidenceKind.REPLAY
        items.append(
            Evidence(
                kind=kind,
                source=str(raw.get("source") or "research"),
                summary=str(raw.get("summary") or "persisted evidence"),
                provenance=provenance,
            )
        )
    refs = list(row.evidence_ids or ())
    if graph is not None:
        refs = [ident for ident in refs if ident in graph.nodes]
    status_raw = str(row.status or "potential")
    try:
        status = FindingStatus(status_raw)
    except ValueError:
        status = FindingStatus.POTENTIAL
    bundle = EvidenceBundle.from_items(items) if items else EvidenceBundle()
    live_items = [
        item
        for item in bundle.verifying_items()
        if item.provenance is not EvidenceProvenance.REPLAY
    ]
    claimed_verified = status in {
        FindingStatus.VERIFIED,
        FindingStatus.REPRODUCED,
        FindingStatus.HUMAN_ACCEPTED,
    }
    if claimed_verified and not live_items:
        status = FindingStatus.POTENTIAL
        bundle = EvidenceBundle.from_items(
            [item for item in items if item.provenance is not EvidenceProvenance.REPLAY]
        )
    ident = UUID(row.id) if _is_uuid(row.id) else uuid4()
    common: dict[str, Any] = {
        "vulnerability_class": row.vulnerability_class or None,
        "target": row.target or None,
        "hypothesis": row.hypothesis_id or None,
        "confidence": row.confidence or "low",
        "impact": row.impact or None,
        "observation_refs": tuple(refs),
        "id": ident,
        "created_at": row.created_at,
    }
    title = row.title or "restored finding"
    if status is FindingStatus.POTENTIAL:
        return SecurityFinding.potential(title, evidence=bundle, **common)
    if status is FindingStatus.REJECTED:
        return SecurityFinding.rejected(title, evidence=bundle, **common)
    if status is FindingStatus.VERIFIED:
        try:
            return SecurityFinding.verified(title, evidence=bundle, **common)
        except ValueError:
            return SecurityFinding.potential(title, evidence=bundle, **common)
    finding = SecurityFinding.potential(title, evidence=bundle, **common)
    if status is FindingStatus.CORROBORATED:
        return finding.corroborate()
    if status is FindingStatus.REPRODUCED:
        try:
            return finding.reproduce(bundle)
        except ValueError:
            return finding
    if status is FindingStatus.HUMAN_ACCEPTED:
        try:
            return finding.reproduce(bundle).human_accept()
        except ValueError:
            return finding
    return finding


def _redact_json(value: Any) -> Any:
    if value is None:
        return None
    try:
        return json.loads(redact_text(json.dumps(value, default=str)))
    except (TypeError, ValueError):
        return None


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
        return True
    except ValueError:
        return False
