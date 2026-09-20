"""Persist research sessions. Secrets are never stored."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.security_agent import (
    DBResearchHypothesis,
    DBResearchSession,
    DBResearchTimelineEvent,
    DBResearchToolCall,
)
from app.security_agent.agent import ResearchSession
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
        row.usage = {"tokens": session.budget.tokens}
        row.error = session.error
        row.paused_reason = "paused" if session.paused else None
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
        await self._session.flush()

    async def load_row(self, session_id: str) -> DBResearchSession | None:
        result = await self._session.execute(
            select(DBResearchSession)
            .options(
                selectinload(DBResearchSession.hypotheses),
                selectinload(DBResearchSession.timeline),
                selectinload(DBResearchSession.tool_calls),
            )
            .where(DBResearchSession.id == session_id)
        )
        return result.scalar_one_or_none()


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
        return True
    except ValueError:
        return False
