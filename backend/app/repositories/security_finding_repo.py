from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.findings import SecurityFinding
from app.models.security_finding import DBSecurityFinding
from app.schemas.security import SecurityFindingResponse


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
        existing_by_key: dict[str, DBSecurityFinding] = {}
        keys = [finding.finding_key for finding in findings if finding.finding_key]
        if project_id is not None and keys:
            result = await self._session.execute(
                select(DBSecurityFinding).where(
                    DBSecurityFinding.project_id == project_id,
                    DBSecurityFinding.finding_key.in_(keys),
                )
            )
            existing_by_key = {
                row.finding_key: row
                for row in result.scalars().all()
                if row.finding_key
            }
        rows: list[DBSecurityFinding] = []
        seen: set[str] = set()
        for finding in findings:
            key = finding.finding_key or ""
            if project_id is not None and key and key in existing_by_key:
                row = existing_by_key[key]
                _reconcile_row(row, finding, analysis_id=analysis_id)
                rows.append(row)
                seen.add(key)
                continue
            if project_id is not None and key and key in seen:
                continue
            row = _to_row(finding, project_id=project_id, analysis_id=analysis_id)
            self._session.add(row)
            rows.append(row)
            if key:
                existing_by_key[key] = row
                seen.add(key)
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
            "metadata": _json_metadata(item.metadata),
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
        language=finding.evidence.items[0].metadata.get("language")
        if finding.evidence.items
        else None,
        analyzer=finding.analyzer,
        parser_backend=(
            finding.evidence.items[0].metadata.get("parser_backend")
            if finding.evidence.items
            else None
        ),
        node_id=finding.evidence.items[0].metadata.get("node_id")
        if finding.evidence.items
        else None,
        taint_path=finding.evidence.items[0].metadata.get("taint_path")
        if finding.evidence.items
        else None,
        rule_ids=",".join(finding.rule_ids),
        observation_refs=",".join(finding.observation_refs),
        evidence_json=json.dumps(evidence),
        intelligence_json=json.dumps(_intelligence(finding), sort_keys=True),
        finding_key=finding.finding_key or None,
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


_INTELLIGENCE_FIELDS = (
    "finding_key",
    "flow_summary",
    "flow_source",
    "flow_sink",
    "field_path",
    "files_crossed",
    "analysis_incomplete",
    "parser_completeness",
    "evidence_summary",
    "related_group",
    "human_review_state",
)


def _stored_intelligence(raw: str | None) -> dict[str, str]:
    try:
        loaded = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    if not isinstance(loaded, dict):
        return {}
    return {
        key: str(loaded[key])
        for key in _INTELLIGENCE_FIELDS
        if key in loaded and isinstance(loaded[key], str)
    }


def to_security_response(row: DBSecurityFinding) -> SecurityFindingResponse:
    """Map a stored row to the API shape, including additive flow fields."""
    data = {
        "id": row.id,
        "project_id": row.project_id,
        "analysis_id": row.analysis_id,
        "title": row.title,
        "status": row.status,
        "vulnerability_class": row.vulnerability_class,
        "evidence_tier": row.evidence_tier,
        "confidence": row.confidence,
        "description": row.description,
        "hypothesis": row.hypothesis,
        "ai_analysis": row.ai_analysis,
        "impact": row.impact,
        "file_path": row.file_path,
        "line": row.line,
        "analyzer": row.analyzer,
        "rule_ids": row.rule_ids,
        "observation_refs": row.observation_refs,
        "asset": row.asset,
        "created_at": row.created_at,
        "parser_backend": row.parser_backend,
        "node_id": row.node_id,
        "taint_path": row.taint_path,
        "language": row.language,
    }
    data.update(_stored_intelligence(row.intelligence_json))
    if row.finding_key:
        data["finding_key"] = row.finding_key
    return SecurityFindingResponse.model_validate(data)


def _json_metadata(metadata: object) -> dict[str, object]:
    """Keep evidence metadata in the existing JSON blob. Non-JSON values are dropped."""
    if not isinstance(metadata, dict):
        return {}
    try:
        encoded = json.dumps(metadata, sort_keys=True)
    except (TypeError, ValueError):
        return {}
    loaded = json.loads(encoded)
    if not isinstance(loaded, dict):
        return {}
    return loaded


def _intelligence(finding: SecurityFinding) -> dict[str, str]:
    return {
        "finding_key": finding.finding_key,
        "flow_summary": finding.flow_summary,
        "flow_source": finding.flow_source,
        "flow_sink": finding.flow_sink,
        "field_path": finding.field_path,
        "files_crossed": finding.files_crossed,
        "analysis_incomplete": finding.analysis_incomplete,
        "parser_completeness": finding.parser_completeness,
        "evidence_summary": finding.evidence_summary,
        "related_group": finding.related_group,
        "human_review_state": finding.human_review_state.value,
    }


def _reconcile_row(
    row: DBSecurityFinding,
    finding: SecurityFinding,
    *,
    analysis_id: UUID | None,
) -> None:
    """Update static facts without destroying higher-trust lifecycle state."""
    incoming = _to_row(finding, project_id=row.project_id, analysis_id=analysis_id)
    protected = row.status in {
        "verified",
        "human_accepted",
        "rejected",
        "reproduced",
    }
    row.title = incoming.title
    row.vulnerability_class = incoming.vulnerability_class
    row.confidence = incoming.confidence
    row.description = incoming.description
    row.file_path = incoming.file_path
    row.line = incoming.line
    row.language = incoming.language
    row.analyzer = incoming.analyzer
    row.parser_backend = incoming.parser_backend
    row.node_id = incoming.node_id
    row.taint_path = incoming.taint_path
    row.rule_ids = incoming.rule_ids
    row.observation_refs = incoming.observation_refs
    row.intelligence_json = incoming.intelligence_json
    row.finding_key = incoming.finding_key
    row.asset = incoming.asset
    row.target = incoming.target
    row.endpoint = incoming.endpoint
    row.report_title = incoming.report_title
    row.report_description = incoming.report_description
    if analysis_id is not None:
        row.analysis_id = analysis_id
    if protected:
        row.evidence_json = _merge_evidence_json(row.evidence_json, incoming.evidence_json)
        if incoming.hypothesis and not row.hypothesis:
            row.hypothesis = incoming.hypothesis
        if incoming.ai_analysis:
            row.ai_analysis = incoming.ai_analysis
        if incoming.impact:
            row.impact = incoming.impact
        return
    row.status = incoming.status
    row.evidence_tier = incoming.evidence_tier
    row.hypothesis = incoming.hypothesis or row.hypothesis
    row.ai_analysis = incoming.ai_analysis or row.ai_analysis
    row.impact = incoming.impact or row.impact
    row.evidence_json = incoming.evidence_json


def _merge_evidence_json(existing_json: str, incoming_json: str) -> str:
    existing = _parse_evidence_list(existing_json)
    incoming = _parse_evidence_list(incoming_json)
    kept = [item for item in existing if str(item.get("kind") or "") != "static_analysis"]
    static_new = [item for item in incoming if str(item.get("kind") or "") == "static_analysis"]
    ai_new = [item for item in incoming if str(item.get("kind") or "") == "ai_analysis"]
    if ai_new:
        kept = [item for item in kept if str(item.get("kind") or "") != "ai_analysis"]
        kept.extend(ai_new)
    return json.dumps(static_new + kept)


def _parse_evidence_list(raw: str) -> list[dict[str, object]]:
    try:
        loaded = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(loaded, list):
        return []
    return [item for item in loaded if isinstance(item, dict)]


def to_domain(row: DBSecurityFinding) -> SecurityFinding:
    from app.domain.evidence import Evidence, EvidenceBundle, EvidenceKind
    from app.domain.findings import FindingStatus, HumanReviewState, SourceLocation
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
            raw_meta = item.get("metadata", {})
            metadata = raw_meta if isinstance(raw_meta, dict) else {}
            items.append(
                Evidence(
                    kind=kind,
                    source=str(item.get("source") or "unknown"),
                    summary=str(item.get("summary") or "evidence"),
                    details=str(item.get("details") or ""),
                    artifact_path=item.get("artifact_path"),
                    metadata=metadata,
                )
            )
    status = FindingStatus(row.status)
    title = row.title
    intel = _stored_intelligence(row.intelligence_json)
    review = intel.pop("human_review_state", "")
    if row.finding_key:
        intel["finding_key"] = row.finding_key
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
        **intel,
    }
    if row.file_path:
        kwargs["source_location"] = SourceLocation(file_path=row.file_path, line=row.line)
    if review:
        try:
            kwargs["human_review_state"] = HumanReviewState(review)
        except ValueError:
            pass
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
