"""Tool/infrastructure outcomes. These must never be stored as vulnerabilities."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ToolExecutionState(StrEnum):
    OK = "ok"
    TIMEOUT = "timeout"
    TOOL_UNAVAILABLE = "tool_unavailable"
    AUTHENTICATION_FAILURE = "authentication_failure"
    RATE_LIMITED = "rate_limited"
    NETWORK_FAILURE = "network_failure"
    INVALID_SCOPE = "invalid_scope"
    MALFORMED_INPUT = "malformed_input"
    DENIED = "denied"
    DRY_RUN = "dry_run"
    APPROVAL_REQUIRED = "approval_required"


@dataclass(frozen=True)
class ToolExecutionResult:
    tool: str
    state: ToolExecutionState
    detail: str = ""
    evidence_ids: tuple[str, ...] = ()

    @property
    def is_finding(self) -> bool:
        return False

    @property
    def ok(self) -> bool:
        return self.state is ToolExecutionState.OK
