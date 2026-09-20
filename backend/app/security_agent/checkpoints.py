"""Session checkpoints. Live resume re-checks current scope and permissions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from app.security_agent.agent import ResearchSession
from app.security_agent.privilege import capture_privileges, scope_fingerprint
from app.security_testing.errors import RestrictedActivityError


@dataclass
class ResearchCheckpoint:
    id: str
    label: str
    snapshot: dict[str, Any]

    @classmethod
    def capture(cls, session: ResearchSession, *, label: str = "") -> ResearchCheckpoint:
        privilege = capture_privileges(
            session.engine,
            mode=session.mode,
            program_handle=session.program_handle,
            disabled_tools=session.disabled_tools,
        )
        return cls(
            id=uuid4().hex,
            label=label or session.state.value,
            snapshot={
                "session": session.snapshot(),
                "model": {
                    "provider": session.provider.provider_name,
                    "model": session.provider.model_name,
                    "thinking": session.thinking_enabled,
                },
                "privilege": privilege.as_dict(),
                "budget": session.budget.snapshot(),
                "hypotheses": [item.snapshot() for item in session.hypotheses],
                "graph": session.graph.snapshot(),
                "tool_history": [
                    item.snapshot() if hasattr(item, "snapshot") else item
                    for item in getattr(session, "tool_call_records", session.tool_history)
                ],
                "plan": session.plan.snapshot() if session.plan else None,
                "findings": [
                    {"id": str(item.id), "status": item.status.value, "title": item.title}
                    for item in session.findings
                ],
            },
        )

    def verify_live(self, session: ResearchSession) -> None:
        current = scope_fingerprint(session.engine.session.scope)
        stored = str((self.snapshot.get("privilege") or {}).get("scope_hash") or "")
        if stored and stored != current:
            raise RestrictedActivityError("checkpoint_scope_changed")
        if (
            session.engine.session.mode.value == "live"
            and session.engine.session.active_testing_enabled
        ):
            approvals = (self.snapshot.get("privilege") or {}).get("approvals") or {}
            active = approvals.get("enable_active_testing") or {}
            if str(active.get("state") or "") != "granted":
                raise RestrictedActivityError("checkpoint_active_testing_not_granted")
