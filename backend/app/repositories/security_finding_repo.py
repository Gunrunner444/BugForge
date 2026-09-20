from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.findings import SecurityFinding
from app.models.security_finding import DBSecurityFinding


class SecurityFindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def bulk_create(
        self,
        findings: list[SecurityFinding],
        *,
        project_id: UUID | None,
        analysis_id: UUID | None,
    ) -> list[DBSecurityFinding]:
        rows: list[DBSecurityFinding] = []
        for finding in findings:
            row = _to_row(finding, project_id=project_id, analysis_id=analysis_id)
            self._session.add(row)
            rows.append(row)
        await self._session.flush()
        return rows

    async def list_for_project(
        self, project_id: UUID, *, offset: int = 0, limit: int = 100
    ) -> tuple[list[DBSecurityFinding], int]:
        count_result = await self._session.execute(
            select(DBSecurityFinding).where(DBSecurityFinding.project_id == project_id)
        )
        total = len(count_result.scalars().all())
        result = await self._session.execute(
            select(DBSecurityFinding)
            .where(DBSecurityFinding.project_id == project_id)
            .order_by(DBSecurityFinding.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(result.scalars().all()), total

    async def list_for_analysis(self, analysis_id: UUID) -> list[DBSecurityFinding]:
        result = await self._session.execute(
            select(DBSecurityFinding)
            .where(DBSecurityFinding.analysis_id == analysis_id)
            .order_by(DBSecurityFinding.created_at.desc())
        )
        return list(result.scalars().all())


def _to_row(
    finding: SecurityFinding,
    *,
    project_id: UUID | None,
    analysis_id: UUID | None,
) -> DBSecurityFinding:
    loc = finding.source_location
    evidence = [
        {
            "kind": item.kind.value,
            "source": item.source,
            "summary": item.summary,
            "details": item.details,
            "artifact_path": item.artifact_path,
            "provenance": item.provenance.value if item.provenance else None,
        }
        for item in finding.evidence.items
    ]
    return DBSecurityFinding(
        id=finding.id,
        project_id=project_id,
        analysis_id=analysis_id,
        title=finding.title,
        status=finding.status.value,
        vulnerability_class=finding.vulnerability_class,
        evidence_tier=finding.evidence_tier.value,
        confidence=finding.confidence,
        description=finding.description,
        hypothesis=finding.hypothesis,
        ai_analysis=finding.ai_analysis,
        impact=finding.impact,
        file_path=loc.file_path if loc else finding.asset,
        line=loc.line if loc else None,
        language=None,
        analyzer=finding.analyzer,
        rule_ids=",".join(finding.rule_ids),
        observation_refs=",".join(finding.observation_refs),
        evidence_json=json.dumps(evidence),
        asset=finding.asset,
        report_title=finding.report_title,
        report_description=finding.report_description,
        created_at=finding.created_at,
    )
