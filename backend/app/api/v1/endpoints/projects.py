from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.analysis import AnalysisResponse, AnalysisSummarySchema
from app.schemas.project import ProjectCreate, ProjectListResponse, ProjectResponse
from app.services.analysis_service import AnalysisService
from app.services.project_service import ProjectNotFoundError, ProjectService

router = APIRouter(prefix="/projects", tags=["Projects"])
logger = logging.getLogger(__name__)


def _project_to_response(project) -> ProjectResponse:
    latest = project.analyses[0] if project.analyses else None
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        repository_path=project.repository_path,
        created_at=project.created_at,
        updated_at=project.updated_at,
        latest_analysis_id=latest.id if latest else None,
        latest_analysis_status=latest.status if latest else None,
    )


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    data: ProjectCreate,
    db: AsyncSession = Depends(get_db),
) -> ProjectResponse:
    service = ProjectService(db)
    try:
        project = await service.create_project(data)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    return _project_to_response(project)


@router.get("", response_model=ProjectListResponse)
async def list_projects(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> ProjectListResponse:
    service = ProjectService(db)
    return await service.list_projects(offset=offset, limit=limit)


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> ProjectResponse:
    service = ProjectService(db)
    try:
        project = await service.get_project(project_id)
    except ProjectNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return _project_to_response(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> None:
    service = ProjectService(db)
    try:
        await service.delete_project(project_id)
    except ProjectNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")


@router.post(
    "/{project_id}/analyze",
    response_model=AnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_analysis(
    project_id: UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> AnalysisResponse:
    # Verify the project exists (uses the request-scoped session)
    project_service = ProjectService(db)
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    # Create the analysis record with the request session so tests can override it
    from app.repositories.analysis_repo import AnalysisRepository as _Repo

    analysis_repo = _Repo(db)
    analysis = await analysis_repo.create(
        project_id=project.id, repository_path=project.repository_path
    )
    await db.commit()
    await db.refresh(analysis)

    # Schedule the heavy analysis to run after the response is sent
    analysis_service = AnalysisService()
    background_tasks.add_task(
        analysis_service.run_analysis,
        analysis_id=analysis.id,
        repository_path=project.repository_path,
    )

    return AnalysisResponse(
        id=analysis.id,
        project_id=analysis.project_id,
        status=analysis.status,
        repository_path=analysis.repository_path,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        error_message=analysis.error_message,
        summary=None,
        created_at=analysis.created_at,
    )


@router.get("/{project_id}/analyses", response_model=dict)
async def list_project_analyses(
    project_id: UUID,
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> dict:
    from app.repositories.analysis_repo import AnalysisRepository

    project_service = ProjectService(db)
    try:
        await project_service.get_project(project_id)
    except ProjectNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    analysis_repo = AnalysisRepository(db)
    analyses, total = await analysis_repo.list_for_project(
        project_id, offset=offset, limit=limit
    )

    items = []
    for a in analyses:
        summary = AnalysisSummarySchema(**a.summary) if a.summary else None
        items.append(
            AnalysisResponse(
                id=a.id,
                project_id=a.project_id,
                status=a.status,
                repository_path=a.repository_path,
                started_at=a.started_at,
                completed_at=a.completed_at,
                error_message=a.error_message,
                summary=summary,
                created_at=a.created_at,
            )
        )

    return {"items": [i.model_dump() for i in items], "total": total, "offset": offset, "limit": limit}
