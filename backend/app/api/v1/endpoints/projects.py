from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.project import Project
from app.schemas.analysis import AnalysisResponse, AnalysisSummarySchema
from app.schemas.project import ProjectCreate, ProjectListResponse, ProjectResponse
from app.schemas.test_run import PaginatedTestRunsResponse, TestRunResponse
from app.services.analysis_service import AnalysisService
from app.services.project_service import ProjectNotFoundError, ProjectService

router = APIRouter(prefix="/projects", tags=["Projects"])
logger = logging.getLogger(__name__)


def _project_to_response(project: Project) -> ProjectResponse:
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


@router.get("/{project_id}/analyses")
async def list_project_analyses(
    project_id: UUID,
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
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


@router.post(
    "/{project_id}/tests/run",
    response_model=TestRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_test_run(
    project_id: UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> TestRunResponse:
    project_service = ProjectService(db)
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    from app.execution import ExecutorFactory
    from app.repositories.test_run_repo import TestRunRepository
    from app.services.test_runner_service import TestRunnerService
    from app.workers.job_runner import FastAPIBackgroundRunner

    run_repo = TestRunRepository(db)
    run = await run_repo.create(
        project_id=project.id, repository_path=project.repository_path
    )
    await db.commit()
    await db.refresh(run)

    svc = TestRunnerService(executor=ExecutorFactory.create())
    runner = FastAPIBackgroundRunner(background_tasks)
    runner.submit(
        svc.execute_test_run,
        test_run_id=run.id,
        repository_path=project.repository_path,
    )

    return TestRunResponse(
        id=run.id,
        project_id=run.project_id,
        status=run.status,
        framework=run.framework,
        repository_path=run.repository_path,
        command=run.command,
        exit_code=run.exit_code,
        duration_seconds=run.duration_seconds,
        error_message=run.error_message,
        total_tests=run.total_tests,
        passed=run.passed,
        failed=run.failed,
        skipped=run.skipped,
        errors=run.errors,
        started_at=run.started_at,
        completed_at=run.completed_at,
        created_at=run.created_at,
    )


@router.get("/{project_id}/test-runs", response_model=PaginatedTestRunsResponse)
async def list_project_test_runs(
    project_id: UUID,
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> PaginatedTestRunsResponse:
    project_service = ProjectService(db)
    try:
        await project_service.get_project(project_id)
    except ProjectNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    from app.repositories.test_run_repo import TestRunRepository

    run_repo = TestRunRepository(db)
    runs, total = await run_repo.list_for_project(project_id, offset=offset, limit=limit)

    return PaginatedTestRunsResponse(
        items=runs,  # type: ignore[arg-type]
        total=total,
        offset=offset,
        limit=limit,
    )
