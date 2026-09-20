"""HackerOne integration API schemas. Tokens never appear here."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HackerOneSyncRequest(BaseModel):
    handle: str
    operator: str = "researcher"


class OpenScopeAckRequest(BaseModel):
    operator: str
    policy: str


class ActiveTestingRequest(BaseModel):
    operator: str


class FindingEvidencePayload(BaseModel):
    kind: str = "reproduction"
    source: str = "researcher"
    summary: str
    details: str = ""


class FindingPayload(BaseModel):
    title: str
    status: str = "verified"
    description: str = ""
    vulnerability_class: str | None = None
    target: str | None = None
    impact: str | None = None
    reproduction: str | None = None
    evidence: list[FindingEvidencePayload] = Field(default_factory=list)
    id: str | None = None


class CreateDraftRequest(BaseModel):
    program_handle: str
    finding: FindingPayload
    severity: str | None = None
    weakness_id: str | None = None
    operator: str = "researcher"


class DraftActionRequest(BaseModel):
    operator: str
    program_handle: str | None = None


class IntentRequest(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)
