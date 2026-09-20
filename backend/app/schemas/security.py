from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SecurityFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID | None
    analysis_id: UUID | None
    title: str
    status: str
    vulnerability_class: str | None
    evidence_tier: str
    confidence: str
    description: str
    hypothesis: str | None
    ai_analysis: str | None
    impact: str | None
    file_path: str | None
    line: int | None
    analyzer: str | None
    rule_ids: str
    observation_refs: str
    asset: str | None
    created_at: datetime


class PaginatedSecurityFindingsResponse(BaseModel):
    items: list[SecurityFindingResponse]
    total: int
    offset: int
    limit: int


class SecurityAnalyzerInfo(BaseModel):
    language_id: str
    display_name: str
    capabilities: list[str]
    extensions: list[str]


class SecurityStatusResponse(BaseModel):
    status: str
    language_analyzers: list[SecurityAnalyzerInfo]
    rule_ids: list[str]
    ai_provider: str
    ai_model: str
    ai_local: bool
    thinking_enabled: bool
    notes: str = (
        "Static and AI hypotheses remain potential or corroborated. "
        "They are not verified vulnerabilities. Active testing is Phase 3."
    )


class RunSecurityAnalysisRequest(BaseModel):
    use_ai: bool = Field(default=False)
