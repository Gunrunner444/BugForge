"""Guided SecurityResearchAgent. Planner only — not scope/verify/approve authority."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.ai.provider import CompletionRequest, LLMProvider
from app.domain.findings import SecurityFinding
from app.security_agent.budget import SessionBudget
from app.security_agent.evidence_graph import EvidenceGraph
from app.security_agent.injection import contains_injection_attempt, untrusted_observation
from app.security_agent.reproduction import ReproductionPlan, execute_reproduction
from app.security_agent.schemas import (
    ResearchHypothesis,
    ResearchPlan,
    ToolCallRequest,
)
from app.security_agent.states import (
    HypothesisStatus,
    ResearchMode,
    ResearchState,
    ToolAuthorization,
)
from app.security_agent.tools import ToolRegistry, default_registry
from app.security_testing.engine import SecurityTestEngine
from app.security_testing.errors import (
    AuthorizationDeniedError,
    RestrictedActivityError,
    SafetyLimitExceededError,
)
from app.security_testing.sanitization import wrap_untrusted

Planner = Callable[["ResearchSession"], Awaitable["AgentDecision"]]

_FORBIDDEN_AI_ACTIONS = frozenset(
    {
        "mark_verified",
        "verify_finding",
        "approve_report",
        "submit_hackerone",
        "grant_budget",
        "enable_tool",
        "change_scope",
        "declare_in_scope",
    }
)


@dataclass
class AgentDecision:
    kind: str
    tool: ToolCallRequest | None = None
    hypothesis: ResearchHypothesis | None = None
    plan: ResearchPlan | None = None
    note: str = ""
    thinking: str | None = None


@dataclass
class TimelineEvent:
    event_type: str
    decision: str = ""
    tool: str = ""
    target: str = ""
    authorization: str = ""
    result: str = ""
    evidence_id: str = ""
    finding_id: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def snapshot(self) -> dict[str, Any]:
        return {
            "time": self.created_at.isoformat(),
            "event_type": self.event_type,
            "decision": self.decision,
            "tool": self.tool,
            "target": self.target,
            "authorization": self.authorization,
            "result": self.result,
            "evidence_id": self.evidence_id,
            "finding_id": self.finding_id,
        }


@dataclass
class ResearchSession:
    project_id: str
    target: str
    mode: ResearchMode
    engine: SecurityTestEngine
    provider: LLMProvider
    program_handle: str = ""
    state: ResearchState = ResearchState.CREATED
    model_name: str = ""
    thinking_enabled: bool = True
    budget: SessionBudget = field(default_factory=SessionBudget.from_settings)
    hypotheses: list[ResearchHypothesis] = field(default_factory=list)
    plan: ResearchPlan | None = None
    graph: EvidenceGraph = field(default_factory=EvidenceGraph)
    timeline: list[TimelineEvent] = field(default_factory=list)
    tool_history: list[str] = field(default_factory=list)
    fingerprints: list[str] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)
    disabled_tools: set[str] = field(default_factory=set)
    paused: bool = False
    stopped: bool = False
    error: str | None = None
    id: str = field(default_factory=lambda: uuid4().hex)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "program_handle": self.program_handle,
            "target": self.target,
            "mode": self.mode.value,
            "state": self.state.value,
            "model": self.model_name or self.provider.model_name,
            "budget": self.budget.snapshot(),
            "hypotheses": [item.snapshot() for item in self.hypotheses],
            "plan": self.plan.snapshot() if self.plan else None,
            "timeline": [item.snapshot() for item in self.timeline],
            "error": self.error,
            "paused": self.paused,
            "stopped": self.stopped,
        }


class SecurityResearchAgent:
    """Observe → analyze → hypothesize → plan → request tool → authorize → execute."""

    def __init__(
        self,
        session: ResearchSession,
        *,
        tools: ToolRegistry | None = None,
        planner: Planner | None = None,
    ) -> None:
        self.session = session
        self.tools = tools or bind_engine_tools(session.engine, default_registry())
        self.planner = planner or self._llm_planner

    def pause(self, reason: str = "operator") -> None:
        self.session.paused = True
        self.session.state = ResearchState.PAUSED
        self._timeline("human_override", decision=f"PAUSE:{reason}")

    def stop(self, reason: str = "operator") -> None:
        self.session.stopped = True
        self.session.state = ResearchState.COMPLETED
        self._timeline("human_override", decision=f"STOP:{reason}")

    def reject_action(self, reason: str) -> None:
        self._timeline("human_override", decision=f"REJECT_ACTION:{reason}")

    def disable_tool(self, name: str) -> None:
        self.session.disabled_tools.add(name)
        self.tools.disable(name)
        self._timeline("human_override", decision=f"DISABLE_TOOL:{name}")

    def reject_finding(self, finding_id: str) -> None:
        self._timeline(
            "human_override", decision=f"REJECT_FINDING:{finding_id}", finding_id=finding_id
        )

    def change_limits(self, *, operator: str, extra_tool_calls: int = 0) -> None:
        self.session.budget.grant_more(operator=operator, extra_tool_calls=extra_tool_calls)
        self._timeline("human_override", decision=f"CHANGE_LIMITS:{operator}")

    async def run(self, *, max_steps: int | None = None) -> ResearchSession:
        limit = max_steps if max_steps is not None else self.session.budget.max_iterations
        for _ in range(limit):
            if self.session.stopped or self.session.paused:
                break
            if self.session.state in {
                ResearchState.COMPLETED,
                ResearchState.FAILED,
                ResearchState.REJECTED,
                ResearchState.VERIFIED,
            }:
                break
            await self.step()
        if self.session.state not in {
            ResearchState.COMPLETED,
            ResearchState.FAILED,
            ResearchState.PAUSED,
            ResearchState.REJECTED,
        }:
            self.session.state = ResearchState.COMPLETED
        return self.session

    async def step(self) -> AgentDecision:
        if self.session.stopped:
            return AgentDecision(kind="stopped")
        if self.session.paused:
            return AgentDecision(kind="paused")
        try:
            self.session.budget.consume("iteration")
        except SafetyLimitExceededError as exc:
            self.session.state = ResearchState.FAILED
            self.session.error = str(exc)
            return AgentDecision(kind="budget_exhausted", note=str(exc))
        decision = await self.planner(self.session)
        if decision.thinking:
            self._timeline("thinking", decision="thinking discarded as non-evidence")
        if decision.kind in _FORBIDDEN_AI_ACTIONS:
            self._timeline("blocked", decision=decision.kind, authorization="blocked")
            raise RestrictedActivityError(decision.kind)
        if decision.kind == "hypothesis" and decision.hypothesis:
            if decision.hypothesis.status is HypothesisStatus.VERIFIED:
                raise RestrictedActivityError("verify_finding")
            self.session.hypotheses.append(decision.hypothesis)
            self.session.state = ResearchState.HYPOTHESIS_CREATED
            self._timeline("hypothesis", decision=decision.hypothesis.title)
            return decision
        if decision.kind == "plan" and decision.plan:
            self.session.plan = decision.plan
            self.session.state = ResearchState.PLAN_READY
            self._timeline("plan", decision=f"{len(decision.plan.steps)} steps")
            return decision
        if decision.kind == "tool" and decision.tool:
            await self._execute_tool(decision.tool, reason=decision.note)
            return decision
        if decision.kind == "reproduce":
            self.session.state = ResearchState.REPRODUCING
            return decision
        if decision.kind == "complete":
            self.session.state = ResearchState.COMPLETED
            return decision
        self.session.state = ResearchState.ANALYZING
        return decision

    async def request_tool(self, request: ToolCallRequest) -> dict[str, Any]:
        return await self._execute_tool(request, reason=request.reason)

    async def _execute_tool(self, request: ToolCallRequest, *, reason: str) -> dict[str, Any]:
        fingerprint = f"{request.tool}:{json.dumps(request.arguments, sort_keys=True, default=str)}"
        if self.session.fingerprints.count(fingerprint) >= 2:
            raise RestrictedActivityError("repeated_identical_tool_call")
        self.session.fingerprints.append(fingerprint)
        if request.tool in self.session.disabled_tools:
            raise RestrictedActivityError(f"disabled_tool:{request.tool}")
        parsed = self.tools.validate(request)
        target = str(
            parsed.model_dump().get("url")
            or parsed.model_dump().get("target")
            or self.session.target
        )
        auth = self._authorize_target(target, tool=request.tool)
        if auth is ToolAuthorization.BLOCKED:
            self._timeline(
                "tool",
                decision=reason,
                tool=request.tool,
                target=target,
                authorization="blocked",
                result="BLOCKED",
            )
            return {"authorization": "BLOCKED", "reason": "ScopeGuard denied the target"}
        kind = (
            "browser"
            if request.tool.startswith("browser")
            else "fuzz"
            if request.tool == "fuzz"
            else "request"
            if request.tool in {"http_request", "api_test", "reproduce"}
            else "tool"
        )
        try:
            self.session.budget.consume("tool")
            if kind != "tool":
                self.session.budget.consume(kind)
        except SafetyLimitExceededError as exc:
            self._timeline("tool", tool=request.tool, authorization="blocked", result=str(exc))
            raise
        self.session.state = ResearchState.EXECUTING
        try:
            result = await self.tools.execute(request)
        except AuthorizationDeniedError as exc:
            self._timeline(
                "tool", tool=request.tool, target=target, authorization="blocked", result=str(exc)
            )
            return {"authorization": "BLOCKED", "reason": str(exc)}
        summary = json.dumps(result, default=str)[:500]
        if contains_injection_attempt(summary):
            summary = untrusted_observation(request.tool, summary)
        node = self.session.graph.add(
            kind="tool_result",
            provenance="tool_execution",
            summary=summary,
            source=request.tool,
        )
        self.session.state = ResearchState.OBSERVING
        self._timeline(
            "tool",
            decision=reason,
            tool=request.tool,
            target=target,
            authorization="authorized",
            result=summary[:200],
            evidence_id=node.id,
        )
        return {"authorization": "AUTHORIZED", "result": result, "evidence_id": node.id}

    def _authorize_target(self, target: str, *, tool: str) -> ToolAuthorization:
        if self.session.mode is ResearchMode.LIVE_HACKERONE:
            if not self.session.engine.session.scope.includes:
                return ToolAuthorization.BLOCKED
            if not self.session.engine.session.active_testing_enabled:
                return ToolAuthorization.BLOCKED
        decision = self.session.engine.authorize(target, tool=tool, active=True)
        if not decision.allowed:
            return ToolAuthorization.BLOCKED
        return ToolAuthorization.AUTHORIZED

    def correlate(self) -> list[ResearchHypothesis]:
        """Strengthen hypotheses with independent sources. Never auto-verify."""
        self.session.state = ResearchState.CORRELATING
        by_class: dict[str, list[ResearchHypothesis]] = {}
        for item in self.session.hypotheses:
            by_class.setdefault(item.vulnerability_class, []).append(item)
        updated: list[ResearchHypothesis] = []
        for group in by_class.values():
            if len(group) > 1:
                for item in group:
                    if item.status is HypothesisStatus.OPEN:
                        item.status = HypothesisStatus.SUPPORTED
            updated.extend(group)
        return updated

    def investigate_conflicts(self, hypothesis: ResearchHypothesis) -> HypothesisStatus:
        if hypothesis.contradicting_evidence_ids and hypothesis.supporting_evidence_ids:
            hypothesis.status = HypothesisStatus.WEAKENED
            return hypothesis.status
        if hypothesis.contradicting_evidence_ids and not hypothesis.supporting_evidence_ids:
            hypothesis.status = HypothesisStatus.DISPROVED
            return hypothesis.status
        if hypothesis.supporting_evidence_ids:
            hypothesis.status = HypothesisStatus.SUPPORTED
            return hypothesis.status
        return HypothesisStatus.OPEN

    def prioritize(self) -> list[ResearchHypothesis]:
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return sorted(
            self.session.hypotheses,
            key=lambda item: (
                rank.get(item.confidence, 0),
                len(item.supporting_evidence_ids),
                1 if item.status is HypothesisStatus.REQUIRES_REPRODUCTION else 0,
            ),
            reverse=True,
        )

    def draft_report(self, hypothesis: ResearchHypothesis) -> dict[str, Any]:
        """Summarize validated graph evidence. Cannot verify, approve, or submit."""
        why = []
        for evidence_id in hypothesis.supporting_evidence_ids:
            why.extend(self.session.graph.why(evidence_id))
        return {
            "title": hypothesis.title,
            "vulnerability_class": hypothesis.vulnerability_class,
            "target": hypothesis.target,
            "impact": "Impact is described from corroborated evidence only.",
            "evidence": why,
            "not_verified": True,
            "cannot_approve": True,
            "cannot_submit": True,
            "thinking_excluded": True,
        }

    def context_window(self) -> dict[str, Any]:
        recent = self.session.timeline[-5:]
        return {
            "target": self.session.target,
            "mode": self.session.mode.value,
            "state": self.session.state.value,
            "program": self.session.program_handle,
            "hypotheses": [item.snapshot() for item in self.session.hypotheses[-3:]],
            "recent": [item.snapshot() for item in recent],
            "budget": self.session.budget.remaining(),
        }

    async def _llm_planner(self, session: ResearchSession) -> AgentDecision:
        context = wrap_untrusted("agent-context", json.dumps(self.context_window(), default=str))
        request = CompletionRequest(
            system_prompt=(
                "You are a BugForge research planner. You never decide scope, "
                "never mark findings verified, never approve reports, and never "
                "submit to HackerOne. Return JSON with keys kind, tool, arguments, reason."
            ),
            user_message=context,
            json_mode=True,
            thinking=session.thinking_enabled,
            tools=[{"name": name} for name in self.tools.known()],
        )
        response = await session.provider.complete(request)
        if response.thinking:
            self._timeline("thinking", decision="model thinking ignored as evidence")
        if response.tool_calls:
            first = response.tool_calls[0]
            tool = ToolCallRequest(
                tool=str(first.get("tool") or first.get("name") or ""),
                arguments=dict(first.get("arguments") or first.get("args") or {}),
                reason=str(first.get("reason") or ""),
            )
            return AgentDecision(kind="tool", tool=tool, thinking=response.thinking)
        try:
            payload = json.loads(response.content or "{}")
        except json.JSONDecodeError:
            return AgentDecision(
                kind="analyze", note="unparseable model output", thinking=response.thinking
            )
        kind = str(payload.get("kind") or payload.get("type") or "analyze")
        if kind in _FORBIDDEN_AI_ACTIONS:
            raise RestrictedActivityError(kind)
        if payload.get("tool"):
            tool = ToolCallRequest(
                tool=str(payload.get("tool")),
                arguments=dict(payload.get("arguments") or {}),
                reason=str(payload.get("reason") or ""),
            )
            return AgentDecision(kind="tool", tool=tool, thinking=response.thinking)
        if kind == "hypothesis":
            hyp = ResearchHypothesis(
                title=str(payload.get("title") or "Untitled hypothesis"),
                vulnerability_class=str(payload.get("vulnerability_class") or "unknown"),
                target=str(payload.get("target") or session.target),
                reason=str(payload.get("reason") or ""),
                confidence=str(payload.get("confidence") or "low"),
            )
            return AgentDecision(kind="hypothesis", hypothesis=hyp, thinking=response.thinking)
        return AgentDecision(
            kind=kind, note=str(payload.get("reason") or ""), thinking=response.thinking
        )

    def _timeline(self, event_type: str, **fields: Any) -> None:
        self.session.timeline.append(TimelineEvent(event_type=event_type, **fields))


def bind_engine_tools(engine: SecurityTestEngine, registry: ToolRegistry) -> ToolRegistry:
    async def http_request(arguments: dict[str, Any]) -> dict[str, Any]:
        exchange = await engine.http("agent_http").request(
            str(arguments.get("method") or "GET"),
            str(arguments["url"]),
            headers=arguments.get("headers") or None,
            content=arguments.get("content"),
            active=bool(arguments.get("active", True)),
        )
        if hasattr(exchange, "response_status"):
            body = wrap_untrusted(
                "http-response", str(getattr(exchange, "response_body", "") or "")[:1000]
            )
            return {"status": exchange.response_status, "body": body, "url": arguments["url"]}
        return {"state": getattr(exchange, "state", "unknown")}

    async def browser_navigate(arguments: dict[str, Any]) -> dict[str, Any]:
        decision = engine.authorize(str(arguments["url"]), tool="browser_navigate", active=True)
        if not decision.allowed:
            raise AuthorizationDeniedError(
                decision.reason, target=str(arguments["url"]), tool="browser"
            )
        return {"navigated": arguments["url"], "authorization": "AUTHORIZED"}

    async def source_inspect(arguments: dict[str, Any]) -> dict[str, Any]:
        path = str(arguments.get("path") or "")
        if path.startswith("/") and not path.startswith(engine.project_id):
            # Keep inspection inside the bound project workspace conceptually.
            pass
        return {
            "path": path,
            "excerpt": untrusted_observation("source", arguments.get("query") or ""),
        }

    async def evidence_inspect(arguments: dict[str, Any]) -> dict[str, Any]:
        return {"evidence_id": arguments.get("evidence_id"), "note": "inspection only"}

    async def scan_stub(arguments: dict[str, Any]) -> dict[str, Any]:
        target = str(arguments.get("target") or "")
        decision = engine.authorize(target, tool="scanner", active=True)
        if not decision.allowed:
            raise AuthorizationDeniedError(decision.reason, target=target, tool="scanner")
        return {
            "target": target,
            "ran": False,
            "reason": "scanner bound through SafetyController envelope",
        }

    async def fuzz(arguments: dict[str, Any]) -> dict[str, Any]:
        count = int(arguments.get("count") or 1)
        if count > engine.safety.limits.max_payload_count:
            raise SafetyLimitExceededError("fuzz count exceeds safety limits")
        exchange = await engine.http("agent_fuzz").request(
            "GET", str(arguments["url"]), active=True
        )
        return {"url": arguments["url"], "status": getattr(exchange, "response_status", None)}

    async def reproduce(arguments: dict[str, Any]) -> dict[str, Any]:
        plan = ReproductionPlan(
            actions=(),
            expected_result="controlled reproduction",
        )
        # Single GET reproduction through the gated client.
        from app.security_agent.reproduction import ReproductionAction

        plan.actions = (
            ReproductionAction(
                method=str(arguments.get("method") or "GET"), url=str(arguments["url"])
            ),
        )
        done = await execute_reproduction(plan, engine)
        return done.snapshot()

    async def proxy_evidence(arguments: dict[str, Any]) -> dict[str, Any]:
        return {"exchange_id": arguments.get("exchange_id"), "note": "proxy evidence inspection"}

    async def api_test(arguments: dict[str, Any]) -> dict[str, Any]:
        return await http_request(arguments)

    registry._executors["http_request"] = http_request
    registry._executors["browser_navigate"] = browser_navigate
    registry._executors["source_inspect"] = source_inspect
    registry._executors["evidence_inspect"] = evidence_inspect
    registry._executors["zap_scan"] = scan_stub
    registry._executors["nuclei_scan"] = scan_stub
    registry._executors["fuzz"] = fuzz
    registry._executors["reproduce"] = reproduce
    registry._executors["proxy_evidence"] = proxy_evidence
    registry._executors["api_test"] = api_test
    return registry
