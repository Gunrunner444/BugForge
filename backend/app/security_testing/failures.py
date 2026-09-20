"""Tool/infrastructure outcomes. These must never be stored as vulnerabilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ToolExecutionState(StrEnum):
    """Canonical lifecycle for every security tool.

    Execution errors are infrastructure outcomes, not findings.
    """

    NOT_REQUESTED = "not_requested"
    AUTHORIZED = "authorized"
    PLANNED = "planned"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    RUNNING = "running"
    COMPLETED = "completed"
    RESULTS_AVAILABLE = "results_available"
    RESULTS_INGESTED = "results_ingested"
    TOOL_UNAVAILABLE = "tool_unavailable"
    TIMEOUT = "timeout"
    NETWORK_FAILURE = "network_failure"
    INVALID_SCOPE = "invalid_scope"
    SAFETY_BLOCKED = "safety_blocked"
    EXECUTION_ERROR = "execution_error"
    FAILED = "failed"
    AUTHENTICATION_FAILURE = "authentication_failure"
    RATE_LIMITED = "rate_limited"
    MALFORMED_INPUT = "malformed_input"
    DENIED = "denied"
    DRY_RUN = "dry_run"
    APPROVAL_REQUIRED = "approval_required"
    OK = "ok"


_SUCCESS_STATES = frozenset(
    {
        ToolExecutionState.OK,
        ToolExecutionState.COMPLETED,
        ToolExecutionState.RESULTS_AVAILABLE,
        ToolExecutionState.RESULTS_INGESTED,
        ToolExecutionState.PLANNED,
        ToolExecutionState.AUTHORIZED,
        ToolExecutionState.DRY_RUN,
        ToolExecutionState.NOT_REQUESTED,
    }
)


@dataclass(frozen=True)
class ToolExecutionResult:
    tool: str
    state: ToolExecutionState
    detail: str = ""
    evidence_ids: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_finding(self) -> bool:
        return False

    @property
    def ok(self) -> bool:
        return self.state in _SUCCESS_STATES
