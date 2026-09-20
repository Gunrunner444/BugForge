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
    COMPLETED_SUCCESS = "completed_success"
    COMPLETED_NO_FINDINGS = "completed_no_findings"
    MAX_ITERATIONS = "max_iterations"
    BUDGET_EXHAUSTED = "budget_exhausted"
    USER_STOPPED = "user_stopped"
    USER_PAUSED = "user_paused"
    INCONCLUSIVE = "inconclusive"


class TerminationReason(StrEnum):
    COMPLETED_SUCCESS = "completed_success"
    COMPLETED_NO_FINDINGS = "completed_no_findings"
    MAX_ITERATIONS = "max_iterations"
    BUDGET_EXHAUSTED = "budget_exhausted"
    USER_STOPPED = "user_stopped"
    USER_PAUSED = "user_paused"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


TERMINAL_RESEARCH_STATES = frozenset(
    {
        ResearchState.COMPLETED,
        ResearchState.COMPLETED_SUCCESS,
        ResearchState.COMPLETED_NO_FINDINGS,
        ResearchState.MAX_ITERATIONS,
        ResearchState.BUDGET_EXHAUSTED,
        ResearchState.USER_STOPPED,
        ResearchState.FAILED,
        ResearchState.REJECTED,
        ResearchState.VERIFIED,
        ResearchState.INCONCLUSIVE,
    }
)

RESUME_BLOCKED_STATES = frozenset(
    {
        ResearchState.USER_STOPPED,
        ResearchState.FAILED,
        ResearchState.COMPLETED,
        ResearchState.COMPLETED_SUCCESS,
        ResearchState.COMPLETED_NO_FINDINGS,
        ResearchState.VERIFIED,
        ResearchState.REJECTED,
    }
)


class HypothesisStatus(StrEnum):
    OPEN = "open"
    SUPPORTED = "supported"
    WEAKENED = "weakened"
    DISPROVED = "disproved"
    REQUIRES_REPRODUCTION = "requires_reproduction"
    VERIFIED = "verified"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class ToolAuthorization(StrEnum):
    AUTHORIZED = "authorized"
    BLOCKED = "blocked"
    REJECTED = "rejected"
    APPROVAL_REQUIRED = "approval_required"


class ResearchMode(StrEnum):
    LAB = "lab"
    LIVE_HACKERONE = "live_hackerone"


class ToolCapability(StrEnum):
    UNAVAILABLE = "unavailable"
    PLANNING_ONLY = "planning_only"
    EXECUTABLE = "executable"
    RESULTS_INGESTIBLE = "results_ingestible"


class ToolRiskLevel(StrEnum):
    PASSIVE = "passive"
    LOW_RISK_ACTIVE = "low_risk_active"
    ACTIVE = "active"
    HIGH_RISK = "high_risk"


class ToolResultQuality(StrEnum):
    SUCCESS = "success"
    NO_RESULT = "no_result"
    BLOCKED = "blocked"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    PARTIAL = "partial"
    RESULTS_AVAILABLE = "results_available"
    APPROVAL_REQUIRED = "approval_required"


class ReproductionOutcome(StrEnum):
    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    ENVIRONMENT_ERROR = "environment_error"
    BLOCKED = "blocked"


class EvidenceGraphKind(StrEnum):
    TOOL_REQUEST = "tool_request"
    TOOL_EXECUTION = "tool_execution"
    OBSERVATION = "observation"
    REQUEST = "request"
    RESPONSE = "response"
    SOURCE = "source"
    SCANNER_RESULT = "scanner_result"
    BROWSER_OBSERVATION = "browser_observation"
    REPRODUCTION = "reproduction"
    HYPOTHESIS = "hypothesis"
