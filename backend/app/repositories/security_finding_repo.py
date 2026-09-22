from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.findings import SecurityFinding
from app.models.security_finding import DBSecurityFinding
from app.repositories.finding_identity import intelligence_with_column_key
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
        existing_by_key = await self._load_existing_by_key(project_id, findings)
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
            row = await self._insert_or_reconcile(
                finding, project_id=project_id, analysis_id=analysis_id
            )
            rows.append(row)
            if key:
                existing_by_key[key] = row
                seen.add(key)
        await self._session.flush()
        return rows

    async def save_domain(
        self,
        finding: SecurityFinding,
        *,
        project_id: UUID | None,
        analysis_id: UUID | None = None,
    ) -> DBSecurityFinding:
        """Persist a complete domain finding after an explicit lifecycle update.

        Unlike scan reconciliation this writes status, evidence, and review
        state from the domain object. ``analysis_id`` is left unchanged unless
        a new analysis is supplied.
        """
        row = await self.get(finding.id)
        if row is None and project_id is not None and finding.finding_key:
            row = await self.get_by_key(project_id, finding.finding_key)
        keep_analysis = row.analysis_id if row is not None and analysis_id is None else analysis_id
        incoming = _to_row(finding, project_id=project_id, analysis_id=keep_analysis)
        if row is None:
            return await self._add_row(incoming, finding, project_id=project_id)
        _overwrite_row(row, incoming, replace_analysis=analysis_id is not None)
        await self._session.flush()
        return row

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

    async def get_by_key(self, project_id: UUID, finding_key: str) -> DBSecurityFinding | None:
        result = await self._session.execute(
            select(DBSecurityFinding).where(
                DBSecurityFinding.project_id == project_id,
                DBSecurityFinding.finding_key == finding_key,
            )
        )
        return result.scalars().first()

    async def get_domain(self, finding_id: UUID) -> SecurityFinding | None:
        row = await self.get(finding_id)
        return to_domain(row) if row else None

    async def _load_existing_by_key(
        self, project_id: UUID | None, findings: list[SecurityFinding]
    ) -> dict[str, DBSecurityFinding]:
        keys = [finding.finding_key for finding in findings if finding.finding_key]
        if project_id is None or not keys:
            return {}
        result = await self._session.execute(
            select(DBSecurityFinding).where(
                DBSecurityFinding.project_id == project_id,
                DBSecurityFinding.finding_key.in_(keys),
            )
        )
        return {row.finding_key: row for row in result.scalars().all() if row.finding_key}

    async def _insert_or_reconcile(
        self,
        finding: SecurityFinding,
        *,
        project_id: UUID | None,
        analysis_id: UUID | None,
    ) -> DBSecurityFinding:
        row = _to_row(finding, project_id=project_id, analysis_id=analysis_id)
        return await self._add_row(row, finding, project_id=project_id)

    async def _add_row(
        self,
        row: DBSecurityFinding,
        finding: SecurityFinding,
        *,
        project_id: UUID | None,
    ) -> DBSecurityFinding:
        try:
            async with self._session.begin_nested():
                self._session.add(row)
                await self._session.flush()
            return row
        except IntegrityError:
            if row in self._session:
                self._session.expunge(row)
            if project_id is None or not finding.finding_key:
                raise
            raced = await self.get_by_key(project_id, finding.finding_key)
            if raced is None:
                raise
            _reconcile_row(raced, finding, analysis_id=row.analysis_id)
            return raced


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
    key = finding.finding_key or None
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
        intelligence_json=intelligence_with_column_key(
            json.dumps(_intelligence(finding), sort_keys=True), key
        ),
        finding_key=key,
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


def _row_intelligence(row: DBSecurityFinding) -> dict[str, str]:
    """Column ``finding_key`` is authoritative, including NULL."""
    intel = _stored_intelligence(row.intelligence_json)
    intel.pop("finding_key", None)
    if row.finding_key:
        intel["finding_key"] = row.finding_key
    else:
        intel["finding_key"] = ""
    return intel


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
    data.update(_row_intelligence(row))
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
    payload = {
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
    if finding.finding_key:
        payload["finding_key"] = finding.finding_key
    return payload


def _reconcile_row(
    row: DBSecurityFinding,
    finding: SecurityFinding,
    *,
    analysis_id: UUID | None,
) -> None:
    """Update static facts without destroying higher-trust lifecycle state.

    A rescan may refresh location and flow fields. It must not erase status,
    human review state, or independent verification evidence. ``analysis_id``
    is the latest scan that observed this finding; older analyses are not a
    historical finding store.
    """
    incoming = _to_row(finding, project_id=row.project_id, analysis_id=analysis_id)
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
    row.intelligence_json = _merge_intelligence_json(
        row.intelligence_json, incoming.intelligence_json, finding_key=incoming.finding_key
    )
    row.finding_key = incoming.finding_key or row.finding_key
    row.asset = incoming.asset
    row.target = incoming.target
    row.endpoint = incoming.endpoint
    row.report_title = incoming.report_title
    row.report_description = incoming.report_description
    row.evidence_json = _merge_evidence_json(row.evidence_json, incoming.evidence_json)
    if analysis_id is not None:
        row.analysis_id = analysis_id
    if incoming.hypothesis and not row.hypothesis:
        row.hypothesis = incoming.hypothesis
    if incoming.ai_analysis:
        row.ai_analysis = incoming.ai_analysis
    if incoming.impact:
        row.impact = incoming.impact
    # Status, tier, reproduction notes, and review stay on the existing row.
    # Incoming static scans are potential/unreviewed and must not downgrade.


def _overwrite_row(
    row: DBSecurityFinding, incoming: DBSecurityFinding, *, replace_analysis: bool
) -> None:
    """Write every persistable field from an explicit domain save."""
    row.title = incoming.title
    row.status = incoming.status
    row.vulnerability_class = incoming.vulnerability_class
    row.evidence_tier = incoming.evidence_tier
    row.confidence = incoming.confidence
    row.description = incoming.description
    row.hypothesis = incoming.hypothesis
    row.ai_analysis = incoming.ai_analysis
    row.impact = incoming.impact
    row.file_path = incoming.file_path
    row.line = incoming.line
    row.language = incoming.language
    row.analyzer = incoming.analyzer
    row.parser_backend = incoming.parser_backend
    row.node_id = incoming.node_id
    row.taint_path = incoming.taint_path
    row.rule_ids = incoming.rule_ids
    row.observation_refs = incoming.observation_refs
    row.evidence_json = incoming.evidence_json
    row.intelligence_json = incoming.intelligence_json
    row.finding_key = incoming.finding_key
    row.asset = incoming.asset
    row.target = incoming.target
    row.endpoint = incoming.endpoint
    row.reproduction = incoming.reproduction
    row.observed_behavior = incoming.observed_behavior
    row.expected_behavior = incoming.expected_behavior
    row.report_title = incoming.report_title
    row.report_description = incoming.report_description
    if replace_analysis:
        row.analysis_id = incoming.analysis_id


def _merge_intelligence_json(
    existing_json: str, incoming_json: str, *, finding_key: str | None
) -> str:
    existing = _stored_intelligence(existing_json)
    incoming = _stored_intelligence(incoming_json)
    merged = dict(incoming)
    existing_review = existing.get("human_review_state", "")
    if existing_review and existing_review != "unreviewed":
        merged["human_review_state"] = existing_review
    return intelligence_with_column_key(json.dumps(merged, sort_keys=True), finding_key)


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
    from app.domain.evidence import Evidence, EvidenceBundle, EvidenceKind, EvidenceProvenance
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
            provenance = None
            raw_prov = item.get("provenance")
            if isinstance(raw_prov, str) and raw_prov:
                try:
                    provenance = EvidenceProvenance(raw_prov)
                except ValueError:
                    provenance = None
            items.append(
                Evidence(
                    kind=kind,
                    source=str(item.get("source") or "unknown"),
                    summary=str(item.get("summary") or "evidence"),
                    details=str(item.get("details") or ""),
                    artifact_path=item.get("artifact_path"),
                    metadata=metadata,
                    provenance=provenance,
                )
            )
    status = FindingStatus(row.status)
    title = row.title
    intel = _row_intelligence(row)
    review = intel.pop("human_review_state", "")
    finding_key = intel.pop("finding_key", "")
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
        "finding_key": finding_key,
        **intel,
    }
    if row.rule_ids:
        kwargs["rule_ids"] = tuple(part for part in row.rule_ids.split(",") if part)
    if row.observation_refs:
        kwargs["observation_refs"] = tuple(part for part in row.observation_refs.split(",") if part)
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
