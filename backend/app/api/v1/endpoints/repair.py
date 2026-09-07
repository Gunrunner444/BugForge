from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.repositories.repair_repo import RepairRepository
from app.schemas.repair import (
    PatchCandidateResponse,
    RepairSessionDetailResponse,
    RepairSessionResponse,
)

router = APIRouter(prefix="/repair", tags=["Automated Repair"])
logger = logging.getLogger(__name__)


@router.get("/{session_id}", response_model=RepairSessionDetailResponse)
async def get_repair_session(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> RepairSessionDetailResponse:
    repo = RepairRepository(db)
    s = await repo.get_session_by_id(session_id)
    if s is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repair session not found")
    candidates = [PatchCandidateResponse.from_orm_with_files(c) for c in s.candidates]
    base = RepairSessionResponse.model_validate(s)
    return RepairSessionDetailResponse(**base.model_dump(), candidates=candidates)


@router.get("/{session_id}/candidates", response_model=list[PatchCandidateResponse])
async def list_candidates(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> list[PatchCandidateResponse]:
    repo = RepairRepository(db)
    s = await repo.get_session_by_id(session_id)
    if s is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repair session not found")
    return [PatchCandidateResponse.from_orm_with_files(c) for c in s.candidates]


@router.get("/{session_id}/candidates/{candidate_id}", response_model=PatchCandidateResponse)
async def get_candidate(
    session_id: UUID,
    candidate_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> PatchCandidateResponse:
    repo = RepairRepository(db)
    c = await repo.get_candidate(candidate_id)
    if c is None or c.session_id != session_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patch candidate not found")
    return PatchCandidateResponse.from_orm_with_files(c)
