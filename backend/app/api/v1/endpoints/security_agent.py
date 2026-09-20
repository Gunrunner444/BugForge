"""Guided security-research agent API. The AI cannot grant itself authority."""

from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import get_provider
from app.database import get_db
from app.models.project import Project
from app.repositories.hackerone_repo import HackerOneRepository
from app.repositories.security_agent_repo import SecurityAgentRepository
from app.security_agent.agent import ResearchSession, SecurityResearchAgent
from app.security_agent.privilege import program_scope_from_hackerone
from app.security_agent.schemas import ToolCallRequest
from app.security_agent.states import RESUME_BLOCKED_STATES, ResearchMode
from app.security_testing.approvals import ApprovalKind, is_ai_operator
from app.security_testing.engine import SecurityTestEngine, SecurityTestSession, TestingMode
from app.security_testing.errors import (
    ApprovalRequiredError,
    RestrictedActivityError,
    SafetyLimitExceededError,
)
from app.security_testing.operator_auth import OperatorSession, require_operator
from app.security_testing.safety import SafetyLimits

router = APIRouter(prefix="/security-agent", tags=["Security Agent"])

_SESSIONS: dict[str, SecurityResearchAgent] = {}
_LOCKS: dict[str, asyncio.Lock] = {}


class CreateAgentSessionRequest(BaseModel):
    project_id: str
    target: str
    mode: str = "lab"
    program_handle: str = ""
    thinking: bool = True
    repo_root: str | None = None


class ToolActionRequest(BaseModel):
    tool: str
    arguments: dict[str, object]
    reason: str = ""


class OverrideRequest(BaseModel):
    action: str
    reason: str = ""
    extra_tool_calls: int = 0
    tool: str | None = None


class ApprovalActionRequest(BaseModel):
    kind: str
    note: str = ""


def _lock_for(session_id: str) -> asyncio.Lock:
    lock = _LOCKS.get(session_id)
    if lock is None:
        lock = asyncio.Lock()
        _LOCKS[session_id] = lock
    return lock


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
    repo_root = payload.repo_root or "."
    if _is_uuid(payload.project_id):
        project = await db.get(Project, UUID(payload.project_id))
        if project is not None and project.repository_path:
            repo_root = project.repository_path
    if mode is ResearchMode.LIVE_HACKERONE:
        handle = payload.program_handle.strip()
        if not handle:
            raise HTTPException(
                status_code=400, detail="program_handle is required for live sessions"
            )
        program = await HackerOneRepository(db).get_program(handle)
        if program is None or not program.structured_scopes:
            raise HTTPException(
                status_code=409,
                detail="LIVE_SCOPE_MISSING: synchronize structured scope before creating a live research session",
            )
        scope = program_scope_from_hackerone(program)
        if not scope.includes:
            raise HTTPException(
                status_code=409,
                detail="LIVE_SCOPE_EMPTY: refusing a permissive live session without includes",
            )
        engine = SecurityTestEngine(
            SecurityTestSession(
                project_id=payload.project_id,
                mode=TestingMode.LIVE,
                scope=scope,
                limits=SafetyLimits.conservative(),
                dry_run=False,
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
        repo_root=str(Path(repo_root)),
    )
    agent = SecurityResearchAgent(research)
    _SESSIONS[research.id] = agent
    await SecurityAgentRepository(db).save_session(research)
    await db.commit()
    return research.snapshot()


@router.get("/sessions/{session_id}")
async def get_session(session_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    agent = await _require(session_id, db)
    return agent.session.snapshot()


@router.post("/sessions/{session_id}/step")
async def step_session(
    session_id: str,
    session: OperatorSession = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    del session
    agent = await _require(session_id, db)
    async with _lock_for(session_id):
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
    agent = await _require(session_id, db)
    async with _lock_for(session_id):
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
        except ApprovalRequiredError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
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
    agent = await _require(session_id, db)
    action = payload.action.lower()
    if action == "pause":
        agent.pause(payload.reason)
    elif action == "stop":
        agent.stop(payload.reason)
    elif action == "resume":
        try:
            agent.resume(operator=session.identity)
        except RestrictedActivityError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    elif action == "reject_action":
        agent.reject_action(payload.reason)
    elif action.startswith("disable_tool:"):
        agent.disable_tool(action.split(":", 1)[1])
    elif action == "disable_tool" and payload.tool:
        agent.disable_tool(payload.tool)
    elif action == "change_limits":
        agent.change_limits(operator=session.identity, extra_tool_calls=payload.extra_tool_calls)
    else:
        raise HTTPException(status_code=400, detail="Unknown override")
    await SecurityAgentRepository(db).save_session(agent.session)
    await db.commit()
    return agent.session.snapshot()


@router.post("/sessions/{session_id}/approvals")
async def grant_session_approval(
    session_id: str,
    payload: ApprovalActionRequest,
    session: OperatorSession = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    if is_ai_operator(session.identity):
        raise HTTPException(status_code=403, detail="The AI cannot grant approvals")
    agent = await _require(session_id, db)
    try:
        kind = ApprovalKind(payload.kind)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="unknown approval kind") from exc
    try:
        if kind is ApprovalKind.ENABLE_ACTIVE_TESTING:
            agent.enable_active_testing(operator=session.identity, note=payload.note)
        else:
            agent.grant_tool_approval(kind, operator=session.identity, note=payload.note)
    except RestrictedActivityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    await SecurityAgentRepository(db).save_session(agent.session)
    await db.commit()
    return {
        "approvals": agent.session.engine.approvals.snapshot(),
        "active_testing": agent.session.engine.session.active_testing_enabled,
        "fuzzing": agent.session.engine.session.fuzzing_enabled,
    }


@router.post("/sessions/{session_id}/resume")
async def resume_session(
    session_id: str,
    session: OperatorSession = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    agent = await _require(session_id, db)
    if agent.session.state in RESUME_BLOCKED_STATES or agent.session.stopped:
        raise HTTPException(
            status_code=409,
            detail="Terminal sessions require an explicit operator reopen; automatic resume is blocked",
        )
    try:
        agent.resume(operator=session.identity)
    except RestrictedActivityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    await SecurityAgentRepository(db).save_session(agent.session)
    await db.commit()
    return agent.session.snapshot()


@router.get("/sessions/{session_id}/timeline")
async def timeline(session_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    agent = await _require(session_id, db)
    return {"items": [item.snapshot() for item in agent.session.timeline]}


@router.get("/sessions/{session_id}/tools")
async def list_tools(session_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    agent = await _require(session_id, db)
    return {"tools": agent.tools.catalog()}


async def _require(session_id: str, db: AsyncSession) -> SecurityResearchAgent:
    agent = _SESSIONS.get(session_id)
    if agent is not None:
        return agent
    program = None
    row_preview = await SecurityAgentRepository(db).load_row(session_id)
    if row_preview is None:
        raise HTTPException(status_code=404, detail="Unknown research session")
    if row_preview.mode == ResearchMode.LIVE_HACKERONE.value and row_preview.program_handle:
        program = await HackerOneRepository(db).get_program(row_preview.program_handle)
    restored = await SecurityAgentRepository(db).reconstruct(session_id, current_program=program)
    if restored is None:
        raise HTTPException(status_code=404, detail="Unknown research session")
    _SESSIONS[session_id] = restored
    return restored


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
        return True
    except ValueError:
        return False
