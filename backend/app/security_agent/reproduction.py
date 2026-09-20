"""ReproductionPlan executed through ScopeGuard + SafetyController."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from app.security_testing.engine import SecurityTestEngine
from app.security_testing.errors import AuthorizationDeniedError, RestrictedActivityError


@dataclass
class ReproductionAction:
    method: str
    url: str
    content: str | None = None
    expected_status: int | None = None


@dataclass
class ReproductionPlan:
    preconditions: tuple[str, ...] = ()
    setup: str = ""
    actions: tuple[ReproductionAction, ...] = ()
    expected_result: str = ""
    actual_result: str = ""
    evidence_to_collect: tuple[str, ...] = ()
    cleanup: str = ""
    status: str = "planned"
    id: str = field(default_factory=lambda: uuid4().hex)

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "preconditions": list(self.preconditions),
            "setup": self.setup,
            "actions": [
                {"method": item.method, "url": item.url, "expected_status": item.expected_status}
                for item in self.actions
            ],
            "expected_result": self.expected_result,
            "actual_result": self.actual_result,
            "evidence_to_collect": list(self.evidence_to_collect),
            "cleanup": self.cleanup,
            "status": self.status,
        }


async def execute_reproduction(
    plan: ReproductionPlan,
    engine: SecurityTestEngine,
) -> ReproductionPlan:
    """Run the plan through the existing safety architecture. Never mutate real data."""
    results: list[str] = []
    for action in plan.actions:
        if (
            action.method.upper() in {"DELETE", "PUT", "PATCH"}
            and not engine.session.scope.lab_mode
        ):
            raise RestrictedActivityError("destructive_reproduction")
        try:
            exchange = await engine.http("reproduce").request(
                action.method,
                action.url,
                content=action.content,
                active=True,
                destructive=False,
            )
        except AuthorizationDeniedError:
            plan.status = "blocked"
            plan.actual_result = "blocked by ScopeGuard/SafetyController"
            return plan
        status = getattr(exchange, "response_status", None) or getattr(
            exchange, "status_code", None
        )
        if status is None and hasattr(exchange, "state"):
            results.append(str(exchange.state))
            continue
        results.append(f"{action.method} {action.url} -> {status}")
        if action.expected_status is not None and status != action.expected_status:
            plan.status = "mismatch"
            plan.actual_result = "; ".join(results)
            return plan
    plan.actual_result = "; ".join(results) or "no actions"
    plan.status = "reproduced" if results else "empty"
    return plan
