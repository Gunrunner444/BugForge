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

    async def get(self, finding_id: UUID) -> DBSecurityFinding | None:
        return await self._session.get(DBSecurityFinding, finding_id)

    async def get_domain(self, finding_id: UUID) -> SecurityFinding | None:
        row = await self.get(finding_id)
        return to_domain(row) if row else None


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
        target=finding.target,
        endpoint=finding.endpoint,
        reproduction=finding.reproduction,
        observed_behavior=finding.observed_behavior,
        expected_behavior=finding.expected_behavior,
        report_title=finding.report_title,
        report_description=finding.report_description,
        created_at=finding.created_at,
    )


def to_domain(row: DBSecurityFinding) -> SecurityFinding:
    from app.domain.evidence import Evidence, EvidenceBundle, EvidenceKind
    from app.domain.findings import FindingStatus
    from app.domain.security import EvidenceTier

    items: list[Evidence] = []
    try:
        raw = json.loads(row.evidence_json or "[]")
    except json.JSONDecodeError:
        raw = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                kind = EvidenceKind(str(item.get("kind") or "reproduction"))
            except ValueError:
                kind = EvidenceKind.REPRODUCTION
            items.append(
                Evidence(
                    kind=kind,
                    source=str(item.get("source") or "unknown"),
                    summary=str(item.get("summary") or "evidence"),
                    details=str(item.get("details") or ""),
                    artifact_path=item.get("artifact_path"),
                )
            )
    status = FindingStatus(row.status)
    title = row.title
    kwargs: dict[str, object] = {
        "id": row.id,
        "description": row.description,
        "vulnerability_class": row.vulnerability_class,
        "target": row.target,
        "endpoint": row.endpoint,
        "hypothesis": row.hypothesis,
        "evidence": EvidenceBundle.from_items(items),
        "reproduction": row.reproduction,
        "observed_behavior": row.observed_behavior,
        "expected_behavior": row.expected_behavior,
        "impact": row.impact,
        "confidence": row.confidence,
        "ai_analysis": row.ai_analysis,
        "evidence_tier": EvidenceTier(row.evidence_tier),
        "analyzer": row.analyzer,
        "asset": row.asset,
        "report_title": row.report_title,
        "report_description": row.report_description,
        "created_at": row.created_at,
    }
    if status is FindingStatus.VERIFIED:
        return SecurityFinding.verified(title, **kwargs)  # type: ignore[arg-type]
    if status is FindingStatus.HUMAN_ACCEPTED:
        return SecurityFinding.verified(title, **kwargs).human_accept()  # type: ignore[arg-type]
    if status is FindingStatus.REJECTED:
        return SecurityFinding.rejected(title, **kwargs)  # type: ignore[arg-type]
    finding = SecurityFinding.potential(title, **kwargs)  # type: ignore[arg-type]
    if status is FindingStatus.CORROBORATED:
        return finding.corroborate()
    if status is FindingStatus.REPRODUCED:
        return finding.reproduce()
    return finding
