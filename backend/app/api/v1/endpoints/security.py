"""Security analysis status, language analyzers, and potential findings."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.database import get_db
from app.domain.language import LanguageCapability
from app.parsing.engine import installed_parser_report
from app.plugins import get_plugin_catalog
from app.repositories.security_finding_repo import (
    SecurityFindingRepository,
    to_security_response,
)
from app.schemas.security import (
    PaginatedSecurityFindingsResponse,
    RunSecurityAnalysisRequest,
    SecurityAnalyzerInfo,
    SecurityStatusResponse,
)
from app.security.rules.catalog import builtin_security_rules

router = APIRouter(prefix="/security", tags=["Security"])


@router.get("/status", response_model=SecurityStatusResponse)
async def security_status() -> SecurityStatusResponse:
    catalog = get_plugin_catalog()
    analyzers = [
        SecurityAnalyzerInfo(
            language_id=adapter.language_id,
            display_name=adapter.display_name,
            capabilities=sorted(cap.value for cap in adapter.capabilities),
            extensions=sorted(adapter.file_extensions),
            parser_tier=str(adapter.parser_tier()),
            parser_backend=adapter.parser_backend(),
            native_available=bool(installed_parser_report(adapter.language_id)["native_available"]),
            parser_status=str(installed_parser_report(adapter.language_id)["status"]),
        )
        for adapter in catalog.languages.all_adapters()
        if adapter.supports(LanguageCapability.SECURITY_ANALYSIS)
        or adapter.supports(LanguageCapability.PARSE)
    ]
    return SecurityStatusResponse(
        status="available",
        language_analyzers=analyzers,
        rule_ids=[rule.rule_id for rule in builtin_security_rules()],
        ai_provider=settings.ai_provider,
        ai_model=settings.mlx_model if settings.ai_provider == "mlx" else settings.ai_model,
        ai_local=settings.is_local_ai(),
        thinking_enabled=settings.ai_thinking_enabled,
    )


@router.get("/findings", response_model=PaginatedSecurityFindingsResponse)
async def list_security_findings(
    project_id: UUID = Query(...),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
) -> PaginatedSecurityFindingsResponse:
    repo = SecurityFindingRepository(db)
    items, total = await repo.list_for_project(project_id, offset=offset, limit=limit)
    return PaginatedSecurityFindingsResponse(
        items=[to_security_response(item) for item in items],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post(
    "/projects/{project_id}/analyze",
    response_model=PaginatedSecurityFindingsResponse,
)
async def run_project_security_analysis(
    project_id: UUID,
    request: RunSecurityAnalysisRequest | None = None,
    db: AsyncSession = Depends(get_db),
) -> PaginatedSecurityFindingsResponse:
    from pathlib import Path

    from app.models.project import Project
    from app.security.agent import SecurityAnalysisAgent

    project = await db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    use_ai = request.use_ai if request is not None else False
    agent = SecurityAnalysisAgent()
    result = await agent.analyze(Path(project.repository_path), use_ai=use_ai)
    repo = SecurityFindingRepository(db)
    await repo.bulk_create(result.findings, project_id=project.id, analysis_id=None)
    await db.commit()
    items, total = await repo.list_for_project(project.id)
    return PaginatedSecurityFindingsResponse(
        items=[to_security_response(item) for item in items],
        total=total,
        offset=0,
        limit=total,
    )
