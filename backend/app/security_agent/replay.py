"""Replay recorded tool results. Default: no live network."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.security_agent.agent import AgentDecision, ResearchSession, SecurityResearchAgent
from app.security_agent.schemas import ToolCallRequest
from app.security_testing.errors import RestrictedActivityError


@dataclass
class ReplayEvent:
    tool: str
    arguments: dict[str, Any]
    result: dict[str, Any]


@dataclass
class SessionReplay:
    events: list[ReplayEvent] = field(default_factory=list)
    live_network: bool = False
    cursor: int = 0

    def record(self, tool: str, arguments: dict[str, Any], result: dict[str, Any]) -> None:
        self.events.append(ReplayEvent(tool=tool, arguments=dict(arguments), result=dict(result)))

    async def play(self, agent: SecurityResearchAgent) -> list[AgentDecision]:
        if self.live_network:
            raise RestrictedActivityError("replay_default_is_offline")
        decisions: list[AgentDecision] = []

        async def planner(_session: ResearchSession) -> AgentDecision:
            if self.cursor >= len(self.events):
                return AgentDecision(kind="complete")
            event = self.events[self.cursor]
            self.cursor += 1
            return AgentDecision(
                kind="tool",
                tool=ToolCallRequest(tool=event.tool, arguments=event.arguments, reason="replay"),
                note="replay",
            )

        original = agent.planner
        agent.planner = planner
        try:
            for event in self.events:
                agent.tools._executors[event.tool] = _canned(event.result)
            while self.cursor < len(self.events):
                decisions.append(await agent.step())
        finally:
            agent.planner = original
        return decisions


def _canned(result: dict[str, Any]) -> Any:
    async def _run(_arguments: dict[str, Any]) -> dict[str, Any]:
        return dict(result)

    return _run
