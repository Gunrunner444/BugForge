"""Persisted guided security-research agent sessions. Secrets are never stored."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class DBResearchSession(Base):
    __tablename__ = "security_research_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True
    )
    program_handle: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="lab")
    state: Mapped[str] = mapped_column(String(64), nullable=False, default="created")
    model_provider: Mapped[str] = mapped_column(String(64), nullable=False, default="mock")
    model_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    model_config: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    budget: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    usage: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    paused_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    human_overrides: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    hypotheses: Mapped[list[DBResearchHypothesis]] = relationship(
        "DBResearchHypothesis", back_populates="session", cascade="all, delete-orphan"
    )
    tool_calls: Mapped[list[DBResearchToolCall]] = relationship(
        "DBResearchToolCall", back_populates="session", cascade="all, delete-orphan"
    )
    timeline: Mapped[list[DBResearchTimelineEvent]] = relationship(
        "DBResearchTimelineEvent", back_populates="session", cascade="all, delete-orphan"
    )
    evidence_links: Mapped[list[DBResearchEvidenceLink]] = relationship(
        "DBResearchEvidenceLink", back_populates="session", cascade="all, delete-orphan"
    )


class DBResearchHypothesis(Base):
    __tablename__ = "security_research_hypotheses"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("security_research_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    vulnerability_class: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="low")
    supporting_evidence_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    contradicting_evidence_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    suggested_next_action: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="open")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    session: Mapped[DBResearchSession] = relationship(
        "DBResearchSession", back_populates="hypotheses"
    )


class DBResearchToolCall(Base):
    __tablename__ = "security_research_tool_calls"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("security_research_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool: Mapped[str] = mapped_column(String(128), nullable=False)
    arguments: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    authorization: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    authorization_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    result_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    session: Mapped[DBResearchSession] = relationship(
        "DBResearchSession", back_populates="tool_calls"
    )


class DBResearchTimelineEvent(Base):
    __tablename__ = "security_research_timeline"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("security_research_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")
    authorization: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    result: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    session: Mapped[DBResearchSession] = relationship(
        "DBResearchSession", back_populates="timeline"
    )


class DBResearchEvidenceLink(Base):
    __tablename__ = "security_research_evidence_links"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("security_research_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hypothesis_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    tool_call_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    provenance: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    extra: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    session: Mapped[DBResearchSession] = relationship(
        "DBResearchSession", back_populates="evidence_links"
    )


class DBReproductionPlan(Base):
    __tablename__ = "security_reproduction_plans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    preconditions: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    setup: Mapped[str] = mapped_column(Text, nullable=False, default="")
    actions: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    expected_result: Mapped[str] = mapped_column(Text, nullable=False, default="")
    actual_result: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_to_collect: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    cleanup: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="planned")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
