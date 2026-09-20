"""Human approval gates. The AI may propose; a human must authorize active work."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from app.security_testing.errors import ApprovalRequiredError, RestrictedActivityError


class ApprovalKind(StrEnum):
    ENABLE_ACTIVE_TESTING = "enable_active_testing"
    START_LIVE_SCAN = "start_live_scan"
    ENABLE_FUZZING = "enable_fuzzing"
    HIGH_RISK_SCANNER = "high_risk_scanner"
    SEND_POC_REQUEST = "send_poc_request"
    SUBMIT_HACKERONE_REPORT = "submit_hackerone_report"


class ApprovalState(StrEnum):
    MISSING = "missing"
    GRANTED = "granted"
    DENIED = "denied"


@dataclass(frozen=True)
class ApprovalRecord:
    kind: ApprovalKind
    state: ApprovalState
    operator: str
    note: str = ""
    id: str = field(default_factory=lambda: uuid4().hex)
    granted_at: datetime = field(default_factory=lambda: datetime.now(UTC))


_AI_OPERATORS = frozenset({"ai", "model", "llm", "assistant", "bugforge-ai", "qwen", "system"})


def is_ai_operator(operator: str) -> bool:
    return operator.strip().lower() in _AI_OPERATORS


class HumanApprovalGate:
    """In-memory approval ledger. AI operators cannot grant HackerOne submission."""

    def __init__(self) -> None:
        self._records: dict[ApprovalKind, ApprovalRecord] = {}

    def grant(self, kind: ApprovalKind, *, operator: str, note: str = "") -> ApprovalRecord:
        if kind is ApprovalKind.SUBMIT_HACKERONE_REPORT and is_ai_operator(operator):
            raise RestrictedActivityError("hackerone_submission")
        record = ApprovalRecord(
            kind=kind, state=ApprovalState.GRANTED, operator=operator, note=note
        )
        self._records[kind] = record
        return record

    def deny(self, kind: ApprovalKind, *, operator: str, note: str = "") -> ApprovalRecord:
        record = ApprovalRecord(kind=kind, state=ApprovalState.DENIED, operator=operator, note=note)
        self._records[kind] = record
        return record

    def state_of(self, kind: ApprovalKind) -> ApprovalState:
        record = self._records.get(kind)
        if record is None:
            return ApprovalState.MISSING
        return record.state

    def require(self, kind: ApprovalKind) -> ApprovalRecord:
        record = self._records.get(kind)
        if record is None or record.state is not ApprovalState.GRANTED:
            raise ApprovalRequiredError(kind.value)
        return record

    def is_granted(self, kind: ApprovalKind) -> bool:
        return self.state_of(kind) is ApprovalState.GRANTED

    def snapshot(self) -> dict[str, str]:
        return {kind.value: self.state_of(kind).value for kind in ApprovalKind}
