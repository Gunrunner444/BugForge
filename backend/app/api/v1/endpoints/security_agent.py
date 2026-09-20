"""Guided security-research agent API. The AI cannot grant itself authority."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import get_provider
from app.database import get_db
from app.repositories.security_agent_repo import SecurityAgentRepository
from app.security_agent.agent import ResearchSession, SecurityResearchAgent
from app.security_agent.schemas import ToolCallRequest
from app.security_agent.states import ResearchMode
from app.security_testing.engine import SecurityTestEngine, SecurityTestSession, TestingMode
from app.security_testing.errors import RestrictedActivityError, SafetyLimitExceededError
from app.security_testing.operator_auth import OperatorSession, require_operator
from app.security_testing.safety import SafetyLimits
from app.security_testing.scope_model import ProgramScope

router = APIRouter(prefix="/security-agent", tags=["Security Agent"])

_SESSIONS: dict[str, SecurityResearchAgent] = {}


class CreateAgentSessionRequest(BaseModel):
    project_id: str
    target: str
    mode: str = "lab"
    program_handle: str = ""
    thinking: bool = True


class ToolActionRequest(BaseModel):
    tool: str
    arguments: dict[str, object]
    reason: str = ""


class OverrideRequest(BaseModel):
    action: str
    reason: str = ""
    extra_tool_calls: int = 0


@router.post("/sessions")
async def create_session(
    payload: CreateAgentSessionRequest,
    session: OperatorSession = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    del session
    try:
        mode = ResearchMode(payload.mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="mode must be lab or live_hackerone") from exc
    if mode is ResearchMode.LIVE_HACKERONE:
        engine = SecurityTestEngine(
            SecurityTestSession(
                project_id=payload.project_id,
                mode=TestingMode.LIVE,
                scope=ProgramScope(program_name=payload.program_handle or "live", lab_mode=False),
                limits=SafetyLimits.conservative(),
                dry_run=True,
                active_testing_enabled=False,
            )
        )
    else:
        engine = SecurityTestEngine.lab(
            payload.project_id,
            allow_active_testing=True,
            limits=SafetyLimits.lab(),
        )
    research = ResearchSession(
        project_id=payload.project_id,
        target=payload.target,
        mode=mode,
        engine=engine,
        provider=get_provider(),
        program_handle=payload.program_handle,
        thinking_enabled=payload.thinking,
    )
    agent = SecurityResearchAgent(research)
    _SESSIONS[research.id] = agent
    await SecurityAgentRepository(db).save_session(research)
    await db.commit()
    return research.snapshot()


@router.get("/sessions/{session_id}")
async def get_session(session_id: str) -> dict[str, object]:
    return _require(session_id).session.snapshot()


@router.post("/sessions/{session_id}/step")
async def step_session(
    session_id: str,
    session: OperatorSession = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    del session
    agent = _require(session_id)
    try:
        decision = await agent.step()
    except RestrictedActivityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except SafetyLimitExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    await SecurityAgentRepository(db).save_session(agent.session)
    await db.commit()
    return {"decision": decision.kind, "session": agent.session.snapshot()}


@router.post("/sessions/{session_id}/tools")
async def request_tool(
    session_id: str,
    payload: ToolActionRequest,
    session: OperatorSession = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    del session
    agent = _require(session_id)
    try:
        result = await agent.request_tool(
            ToolCallRequest(
                tool=payload.tool, arguments=dict(payload.arguments), reason=payload.reason
            )
        )
    except RestrictedActivityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except SafetyLimitExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    await SecurityAgentRepository(db).save_session(agent.session)
    await db.commit()
    return result


@router.post("/sessions/{session_id}/override")
async def override_session(
    session_id: str,
    payload: OverrideRequest,
    session: OperatorSession = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    agent = _require(session_id)
    action = payload.action.lower()
    if action == "pause":
        agent.pause(payload.reason)
    elif action == "stop":
        agent.stop(payload.reason)
    elif action == "reject_action":
        agent.reject_action(payload.reason)
    elif action.startswith("disable_tool:"):
        agent.disable_tool(action.split(":", 1)[1])
    elif action == "change_limits":
        agent.change_limits(operator=session.identity, extra_tool_calls=payload.extra_tool_calls)
    else:
        raise HTTPException(status_code=400, detail="Unknown override")
    await SecurityAgentRepository(db).save_session(agent.session)
    await db.commit()
    return agent.session.snapshot()


@router.get("/sessions/{session_id}/timeline")
async def timeline(session_id: str) -> dict[str, object]:
    agent = _require(session_id)
    return {"items": [item.snapshot() for item in agent.session.timeline]}


def _require(session_id: str) -> SecurityResearchAgent:
    agent = _SESSIONS.get(session_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Unknown research session")
    return agent
