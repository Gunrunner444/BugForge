"""Explicit research-session state machine. Restartable from persisted state."""

from __future__ import annotations

from enum import StrEnum


class ResearchState(StrEnum):
    CREATED = "created"
    RECON = "recon"
    ANALYZING = "analyzing"
    HYPOTHESIS_CREATED = "hypothesis_created"
    PLAN_READY = "plan_ready"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    EXECUTING = "executing"
    OBSERVING = "observing"
    CORRELATING = "correlating"
    REPRODUCING = "reproducing"
    VERIFIED = "verified"
    REJECTED = "rejected"
    PAUSED = "paused"
    FAILED = "failed"
    COMPLETED = "completed"


class HypothesisStatus(StrEnum):
    OPEN = "open"
    SUPPORTED = "supported"
    WEAKENED = "weakened"
    DISPROVED = "disproved"
    REQUIRES_REPRODUCTION = "requires_reproduction"
    VERIFIED = "verified"
    REJECTED = "rejected"


class ToolAuthorization(StrEnum):
    AUTHORIZED = "authorized"
    BLOCKED = "blocked"
    REJECTED = "rejected"


class ResearchMode(StrEnum):
    LAB = "lab"
    LIVE_HACKERONE = "live_hackerone"
