"""Session budgets. The AI may request more budget but cannot grant it."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import get_settings
from app.security_testing.errors import SafetyLimitExceededError


@dataclass
class SessionBudget:
    max_tool_calls: int = 40
    max_requests: int = 50
    max_browser_actions: int = 20
    max_fuzz_requests: int = 20
    max_iterations: int = 20
    max_tokens: int = 200_000
    max_scan_seconds: float = 300.0
    tool_calls: int = 0
    requests: int = 0
    browser_actions: int = 0
    fuzz_requests: int = 0
    iterations: int = 0
    tokens: int = 0
    scan_seconds: float = 0.0
    extra_granted_by: str | None = None

    @classmethod
    def from_settings(cls) -> SessionBudget:
        settings = get_settings()
        return cls(
            max_tool_calls=settings.security_agent_max_tool_calls,
            max_requests=settings.security_agent_max_requests,
            max_browser_actions=settings.security_agent_max_browser_actions,
            max_fuzz_requests=settings.security_agent_max_fuzz_requests,
            max_iterations=settings.security_agent_max_iterations,
        )

    def consume(self, kind: str, *, amount: int = 1) -> None:
        if kind == "tool":
            self.tool_calls += amount
            if self.tool_calls > self.max_tool_calls:
                raise SafetyLimitExceededError("tool call budget exhausted")
        elif kind == "request":
            self.requests += amount
            if self.requests > self.max_requests:
                raise SafetyLimitExceededError("request budget exhausted")
        elif kind == "browser":
            self.browser_actions += amount
            if self.browser_actions > self.max_browser_actions:
                raise SafetyLimitExceededError("browser action budget exhausted")
        elif kind == "fuzz":
            self.fuzz_requests += amount
            if self.fuzz_requests > self.max_fuzz_requests:
                raise SafetyLimitExceededError("fuzz request budget exhausted")
        elif kind == "iteration":
            self.iterations += amount
            if self.iterations > self.max_iterations:
                raise SafetyLimitExceededError("reasoning iteration budget exhausted")
        elif kind == "token":
            self.tokens += amount
            if self.tokens > self.max_tokens:
                raise SafetyLimitExceededError("token budget exhausted")

    def remaining(self) -> dict[str, int]:
        return {
            "tool_calls": self.max_tool_calls - self.tool_calls,
            "requests": self.max_requests - self.requests,
            "browser_actions": self.max_browser_actions - self.browser_actions,
            "fuzz_requests": self.max_fuzz_requests - self.fuzz_requests,
            "iterations": self.max_iterations - self.iterations,
        }

    def grant_more(self, *, operator: str, extra_tool_calls: int = 0) -> None:
        from app.security_testing.approvals import is_ai_operator
        from app.security_testing.errors import RestrictedActivityError

        if is_ai_operator(operator):
            raise RestrictedActivityError("The AI cannot grant itself additional budget")
        self.max_tool_calls += max(0, extra_tool_calls)
        self.extra_granted_by = operator

    def snapshot(self) -> dict[str, object]:
        return {
            "max": {
                "tool_calls": self.max_tool_calls,
                "requests": self.max_requests,
                "browser_actions": self.max_browser_actions,
                "fuzz_requests": self.max_fuzz_requests,
                "iterations": self.max_iterations,
            },
            "used": {
                "tool_calls": self.tool_calls,
                "requests": self.requests,
                "browser_actions": self.browser_actions,
                "fuzz_requests": self.fuzz_requests,
                "iterations": self.iterations,
                "tokens": self.tokens,
            },
            "remaining": self.remaining(),
        }
