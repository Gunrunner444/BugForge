"""Advanced research orchestrator. Reuses SecurityResearchAgent; no second executor."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.security_agent.agent import AgentDecision, ResearchSession, SecurityResearchAgent
from app.security_agent.correlation import prioritize
from app.security_agent.states import HypothesisStatus, ResearchState
from app.security_agent.strategies import ResearchStrategy, tools_for_strategy
from app.security_testing.errors import RestrictedActivityError


@dataclass
class NextActionExplanation:
    tool: str
    target: str
    reason: str
    expected_evidence: str
    estimated_requests: int
    risk_level: str
    approval_required: bool

    def snapshot(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "reason": self.reason,
            "expected_evidence": self.expected_evidence,
            "estimated_requests": self.estimated_requests,
            "risk_level": self.risk_level,
            "approval_required": self.approval_required,
        }


@dataclass
class AdvancedResearchOrchestrator:
    agent: SecurityResearchAgent
    strategy: ResearchStrategy = ResearchStrategy.PASSIVE_RECON
    next_action: NextActionExplanation | None = None
    false_positives: list[dict[str, Any]] = field(default_factory=list)

    @property
    def session(self) -> ResearchSession:
        return self.agent.session

    def recommend_strategy(self, suggested: str) -> ResearchStrategy:
        try:
            strategy = ResearchStrategy(suggested)
        except ValueError:
            strategy = ResearchStrategy.PASSIVE_RECON
        self.strategy = strategy
        return strategy

    def permitted_tools(self) -> tuple[str, ...]:
        wanted = tools_for_strategy(self.strategy)
        known = set(self.agent.tools.known())
        disabled = self.session.disabled_tools
        return tuple(name for name in wanted if name in known and name not in disabled)

    def identify_missing_evidence(self) -> list[str]:
        missing: list[str] = []
        for hyp in self.session.hypotheses:
            if not hyp.supporting_evidence_ids:
                missing.append(f"{hyp.id}:no_evidence")
            if hyp.status is HypothesisStatus.REQUIRES_REPRODUCTION:
                missing.append(f"{hyp.id}:reproduction")
        return missing

    def should_reproduce(self) -> bool:
        return (
            any(
                item.status is HypothesisStatus.REQUIRES_REPRODUCTION
                for item in self.session.hypotheses
            )
            and "reproduce" in self.permitted_tools()
        )

    def evidence_sufficient(self) -> bool:
        return any(item.status.value == "reproduced" for item in self.session.findings) or (
            not self.identify_missing_evidence() and bool(self.session.hypotheses)
        )

    def explain_next(self, tool: str, *, reason: str, target: str = "") -> NextActionExplanation:
        spec = self.agent.tools.spec(tool)
        self.next_action = NextActionExplanation(
            tool=tool,
            target=target or self.session.target,
            reason=reason,
            expected_evidence=spec.description,
            estimated_requests=1 if spec.budget_kind in {"request", "fuzz"} else 0,
            risk_level=spec.risk_level.value,
            approval_required=bool(spec.requires_human_approval),
        )
        return self.next_action

    def reject_escalation(self, kind: str) -> None:
        raise RestrictedActivityError(kind)

    async def step(self) -> AgentDecision:
        if self.session.budget.exhausted():
            self.session.state = ResearchState.BUDGET_EXHAUSTED
            return AgentDecision(kind="budget_exhausted")
        if self.evidence_sufficient() and not self.should_reproduce():
            return AgentDecision(kind="complete", note="evidence sufficient")
        return await self.agent.step()

    def dashboard(self) -> dict[str, Any]:
        ranked = prioritize(self.session.hypotheses)
        current = ranked[0] if ranked else None
        return {
            "target": self.session.target,
            "scope_status": self.session.engine.session.scope.program_name,
            "strategy": self.strategy.value,
            "hypothesis": current.snapshot() if current else None,
            "evidence_strength": current.evidence_strength if current else 0,
            "contradicting_evidence": list(current.contradicting_evidence_ids) if current else [],
            "tools_used": list(self.session.tool_history),
            "remaining_budget": self.session.budget.remaining(),
            "authorization": {
                "active_testing": self.session.engine.session.active_testing_enabled,
                "fuzzing": self.session.engine.session.fuzzing_enabled,
                "dry_run": self.session.engine.safety.dry_run,
                "mode": self.session.mode.value,
            },
            "approval_requirements": [
                spec.approval_kind
                for spec in (self.agent.tools.spec(name) for name in self.permitted_tools())
                if spec.approval_kind
            ],
            "reproduction_status": current.reproducibility if current else "unknown",
            "next_action": self.next_action.snapshot() if self.next_action else None,
        }

    def record_false_positive(self, *, why: str, evidence: str, source: str) -> None:
        self.false_positives.append({"why": why, "evidence": evidence, "source": source})
