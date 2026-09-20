"""Structured tool calls, hypotheses, and research plans. Typed before execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from app.security_agent.states import HypothesisStatus


class ToolCallRequest(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""

    @field_validator("tool")
    @classmethod
    def tool_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("tool is required")
        return cleaned


class HttpRequestArgs(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    content: str | None = None
    active: bool = True


class BrowserNavigateArgs(BaseModel):
    url: str


class SourceInspectArgs(BaseModel):
    path: str
    query: str = ""


class EvidenceInspectArgs(BaseModel):
    evidence_id: str


class ScanArgs(BaseModel):
    target: str
    template: str | None = None


class FuzzArgs(BaseModel):
    url: str
    param: str = "q"
    count: int = 3


class ReproduceArgs(BaseModel):
    plan_id: str | None = None
    url: str
    method: str = "GET"


class ProxyEvidenceArgs(BaseModel):
    exchange_id: str = ""


class ApiTestArgs(BaseModel):
    url: str
    method: str = "GET"
    spec_path: str | None = None


TOOL_ARG_MODELS: dict[str, type[BaseModel]] = {
    "http_request": HttpRequestArgs,
    "browser_navigate": BrowserNavigateArgs,
    "source_inspect": SourceInspectArgs,
    "evidence_inspect": EvidenceInspectArgs,
    "zap_scan": ScanArgs,
    "nuclei_scan": ScanArgs,
    "fuzz": FuzzArgs,
    "reproduce": ReproduceArgs,
    "proxy_evidence": ProxyEvidenceArgs,
    "api_test": ApiTestArgs,
}


@dataclass
class ResearchHypothesis:
    title: str
    vulnerability_class: str
    target: str
    reason: str
    confidence: str = "low"
    supporting_evidence_ids: tuple[str, ...] = ()
    contradicting_evidence_ids: tuple[str, ...] = ()
    suggested_next_action: str = ""
    status: HypothesisStatus = HypothesisStatus.OPEN
    id: str = field(default_factory=lambda: uuid4().hex)

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "vulnerability_class": self.vulnerability_class,
            "target": self.target,
            "reason": self.reason,
            "confidence": self.confidence,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "contradicting_evidence_ids": list(self.contradicting_evidence_ids),
            "suggested_next_action": self.suggested_next_action,
            "status": self.status.value,
        }


@dataclass
class ResearchPlanStep:
    order: int
    action: str
    tool: str | None = None
    target: str = ""
    note: str = ""


@dataclass
class ResearchPlan:
    steps: tuple[ResearchPlanStep, ...] = ()
    current: int = 0

    def snapshot(self) -> dict[str, Any]:
        return {
            "current": self.current,
            "steps": [
                {
                    "order": step.order,
                    "action": step.action,
                    "tool": step.tool,
                    "target": step.target,
                    "note": step.note,
                }
                for step in self.steps
            ],
        }
