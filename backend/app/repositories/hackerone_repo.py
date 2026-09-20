"""Persist HackerOne adapter state. Never stores API tokens or cookies."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.adapters.hackerone.models import (
    HackerOneProgram,
    ProgramSyncStatus,
    ScopeExclusionRecord,
    ScopeMode,
    ScopeSnapshot,
    StructuredScopeRecord,
    WeaknessRecord,
    asset_type_from_hackerone,
)
from app.adapters.hackerone.provider import HackerOneProvider
from app.adapters.hackerone.reports import (
    ApprovalRecord,
    HackerOneRemoteState,
    HackerOneReportDraft,
    ReportHumanReviewState,
    ReportSubmissionState,
    SubmissionRecord,
)
from app.models.hackerone import (
    DBHackerOneApprovalEvent,
    DBHackerOneAuditEvent,
    DBHackerOneProgram,
    DBHackerOneReportDraft,
    DBHackerOneScopeExclusion,
    DBHackerOneStructuredScope,
    DBHackerOneSubmission,
    DBHackerOneSync,
    DBHackerOneWeakness,
)
from app.security_testing.secrets import redact_text
from app.security_testing.target import AssetType


class HackerOneRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def persist_provider(self, provider: HackerOneProvider) -> None:
        for program in provider.programs.values():
            await self.replace_program(program)
        for draft in provider.reports.drafts.values():
            await self.save_draft(draft)
        for record in provider.reports.submissions.values():
            await self.save_submission(record)
        await self._session.flush()

    async def hydrate(self, provider: HackerOneProvider) -> None:
        programs = await self.list_programs()
        for program in programs:
            provider.programs[program.handle] = program
            provider.scope_provider.program = program
        drafts = await self.list_drafts()
        for draft in drafts:
            provider.reports.drafts[draft.id] = draft
        submissions = await self.list_submissions()
        for item in submissions:
            provider.reports.submissions[(item.finding_id, item.program)] = item

    async def replace_program(self, program: HackerOneProgram) -> DBHackerOneProgram:
        """Transactional replacement of scope/exclusion/weakness children."""
        row = await self._program_row(program.handle)
        if row is None:
            row = DBHackerOneProgram(handle=program.handle)
            self._session.add(row)
            await self._session.flush()
        row.program_id = program.program_id
        row.name = program.name
        row.program_url = program.program_url
        row.fetched_at = program.fetched_at
        row.sync_status = program.sync_status.value
        row.error = program.error
        row.scope_mode = program.scope_mode.value
        row.offers_bounties = program.offers_bounties
        row.requires_severity = program.requires_severity
        row.instructions = program.instructions
        row.open_scope_policy = program.open_scope_policy
        row.open_scope_acknowledged = program.open_scope_acknowledged
        row.active_testing_approved = program.active_testing_approved
        row.scope_version = program.scope_version
        row.scope_sync_complete = program.scope_sync_complete
        row.scope_count = len(program.structured_scopes)
        row.last_scope_id = program.last_scope_id
        row.continuation_state = program.continuation_state
        row.updated_at = datetime.now(UTC)
        await self._session.flush()
        await self._session.execute(
            delete(DBHackerOneStructuredScope).where(
                DBHackerOneStructuredScope.program_pk == row.id
            )
        )
        await self._session.execute(
            delete(DBHackerOneScopeExclusion).where(DBHackerOneScopeExclusion.program_pk == row.id)
        )
        await self._session.execute(
            delete(DBHackerOneWeakness).where(DBHackerOneWeakness.program_pk == row.id)
        )
        for scope_item in program.structured_scopes:
            self._session.add(
                DBHackerOneStructuredScope(
                    program_pk=row.id,
                    hackerone_id=scope_item.id,
                    asset_type_raw=scope_item.asset_type_raw,
                    asset_type=scope_item.asset_type.value,
                    asset_identifier=scope_item.asset_identifier,
                    instruction=scope_item.instruction,
                    eligible_for_bounty=scope_item.eligible_for_bounty,
                    eligible_for_submission=scope_item.eligible_for_submission,
                    reference=scope_item.reference,
                    original=scope_item.original,
                    snapshot_version=program.scope_version,
                )
            )
        for exclusion in program.exclusions:
            self._session.add(
                DBHackerOneScopeExclusion(
                    program_pk=row.id,
                    hackerone_id=exclusion.id,
                    category=exclusion.category,
                    details=exclusion.details,
                    created_at_remote=exclusion.created_at,
                    updated_at_remote=exclusion.updated_at,
                    original=exclusion.original,
                )
            )
        for weakness in program.weaknesses:
            self._session.add(
                DBHackerOneWeakness(
                    program_pk=row.id,
                    hackerone_id=weakness.id,
                    name=weakness.name,
                    description=weakness.description,
                    external_id=weakness.external_id,
                    original=weakness.original,
                )
            )
        self._session.add(
            DBHackerOneSync(
                program_pk=row.id,
                status=program.sync_status.value,
                error=program.error,
                scope_count=len(program.structured_scopes),
                last_scope_id=program.last_scope_id,
                scope_sync_complete=program.scope_sync_complete,
                weakness_count=len(program.weaknesses),
            )
        )
        await self._session.flush()
        return row

    async def save_draft(self, draft: HackerOneReportDraft) -> DBHackerOneReportDraft:
        row = await self._session.get(DBHackerOneReportDraft, draft.id)
        if row is None:
            row = DBHackerOneReportDraft(id=draft.id)
            self._session.add(row)
        row.project_id = UUID(draft.project_id) if draft.project_id else None
        try:
            row.finding_id = UUID(draft.finding_id) if draft.finding_id else None
        except ValueError:
            row.finding_id = None
        row.program_handle = draft.program_handle
        row.title = draft.title
        row.vulnerability_information = draft.vulnerability_information
        row.impact = draft.impact
        row.severity = draft.severity
        row.weakness_id = draft.weakness_id
        row.weakness_candidates = list(draft.weakness_candidates)
        row.structured_scope_id = draft.structured_scope_id
        row.evidence_references = list(draft.evidence_references)
        row.reproduction = draft.reproduction
        row.target = draft.target
        row.eligible_for_submission = draft.eligible_for_submission
        row.eligible_for_bounty = draft.eligible_for_bounty
        row.finding_verification = draft.finding_verification
        row.human_review_state = draft.human_review_state.value
        row.submission_state = draft.submission_state.value
        row.remote_state = draft.remote_state.value
        row.hackerone_report_id = draft.hackerone_report_id
        row.error = draft.error
        row.last_payload = draft.last_payload
        row.report_content_hash = draft.report_content_hash
        row.evidence_hash = draft.evidence_hash
        row.scope_snapshot_hash = draft.scope_snapshot_hash
        row.payload_hash = draft.payload_hash
        if draft.approval:
            row.approved_report_content_hash = draft.approval.report_content_hash
            row.approved_evidence_hash = draft.approval.evidence_hash
            row.approved_scope_snapshot_hash = draft.approval.scope_snapshot_hash
            row.approved_payload_hash = draft.approval.payload_hash
            row.approval_timestamp = draft.approval.approved_at
            row.approved_by = draft.approval.approved_by
            row.approval_expires_at = draft.approval.expires_at
        else:
            row.approved_report_content_hash = None
            row.approved_evidence_hash = None
            row.approved_scope_snapshot_hash = None
            row.approved_payload_hash = None
            row.approval_timestamp = None
            row.approved_by = None
            row.approval_expires_at = None
        row.scope_snapshot = draft.scope_snapshot.as_dict() if draft.scope_snapshot else None
        row.updated_at = datetime.now(UTC)
        await self._session.flush()
        return row

    async def save_submission(self, record: SubmissionRecord) -> DBHackerOneSubmission:
        result = await self._session.execute(
            select(DBHackerOneSubmission).where(
                DBHackerOneSubmission.finding_id == record.finding_id,
                DBHackerOneSubmission.program_handle == record.program,
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            row = DBHackerOneSubmission(
                finding_id=record.finding_id,
                program_handle=record.program,
            )
            self._session.add(row)
        row.draft_id = record.metadata.get("draft_id")
        row.hackerone_report_id = record.hackerone_report_id
        row.submission_state = record.submission_state.value
        row.remote_state = record.remote_state.value
        row.error = record.error
        if record.submission_state is ReportSubmissionState.SUBMITTED:
            row.completed_at = datetime.now(UTC)
        await self._session.flush()
        return row

    async def record_approval_event(
        self,
        *,
        draft_id: str,
        action: str,
        approved_by: str,
        report_content_hash: str = "",
        evidence_hash: str = "",
        scope_snapshot_hash: str = "",
        payload_hash: str = "",
        reason: str = "",
    ) -> None:
        self._session.add(
            DBHackerOneApprovalEvent(
                draft_id=draft_id,
                action=action,
                approved_by=approved_by,
                report_content_hash=report_content_hash,
                evidence_hash=evidence_hash,
                scope_snapshot_hash=scope_snapshot_hash,
                payload_hash=payload_hash,
                reason=reason,
            )
        )
        await self._session.flush()

    async def audit(
        self,
        action: str,
        *,
        project_id: str = "",
        finding_id: str = "",
        draft_id: str = "",
        program_handle: str = "",
        operator_identity: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        cleaned = _redact_details(details or {})
        self._session.add(
            DBHackerOneAuditEvent(
                action=action,
                project_id=project_id,
                finding_id=finding_id,
                draft_id=draft_id,
                program_handle=program_handle,
                operator_identity=operator_identity,
                details=cleaned,
            )
        )
        await self._session.flush()

    async def list_programs(self) -> list[HackerOneProgram]:
        result = await self._session.execute(
            select(DBHackerOneProgram).options(
                selectinload(DBHackerOneProgram.structured_scopes),
                selectinload(DBHackerOneProgram.exclusions),
                selectinload(DBHackerOneProgram.weaknesses),
            )
        )
        return [_program_from_row(row) for row in result.scalars().unique().all()]

    async def get_program(self, handle: str) -> HackerOneProgram | None:
        row = await self._program_row(handle)
        return _program_from_row(row) if row else None

    async def list_drafts(self) -> list[HackerOneReportDraft]:
        result = await self._session.execute(select(DBHackerOneReportDraft))
        return [_draft_from_row(row) for row in result.scalars().all()]

    async def get_draft(self, draft_id: str) -> HackerOneReportDraft | None:
        row = await self._session.get(DBHackerOneReportDraft, draft_id)
        return _draft_from_row(row) if row else None

    async def list_submissions(self) -> list[SubmissionRecord]:
        result = await self._session.execute(select(DBHackerOneSubmission))
        return [_submission_from_row(row) for row in result.scalars().all()]

    async def get_submission(self, finding_id: str, program_handle: str) -> SubmissionRecord | None:
        result = await self._session.execute(
            select(DBHackerOneSubmission).where(
                DBHackerOneSubmission.finding_id == finding_id,
                DBHackerOneSubmission.program_handle == program_handle,
            )
        )
        row = result.scalar_one_or_none()
        return _submission_from_row(row) if row else None

    async def _program_row(self, handle: str) -> DBHackerOneProgram | None:
        result = await self._session.execute(
            select(DBHackerOneProgram)
            .options(
                selectinload(DBHackerOneProgram.structured_scopes),
                selectinload(DBHackerOneProgram.exclusions),
                selectinload(DBHackerOneProgram.weaknesses),
            )
            .where(DBHackerOneProgram.handle == handle)
        )
        return result.scalar_one_or_none()


def _program_from_row(row: DBHackerOneProgram) -> HackerOneProgram:
    scopes = tuple(
        StructuredScopeRecord(
            id=item.hackerone_id,
            asset_type_raw=item.asset_type_raw,
            asset_type=_asset(item.asset_type),
            asset_identifier=item.asset_identifier,
            instruction=item.instruction,
            eligible_for_bounty=item.eligible_for_bounty,
            eligible_for_submission=item.eligible_for_submission,
            reference=item.reference,
            original=item.original or {},
        )
        for item in row.structured_scopes
    )
    exclusions = tuple(
        ScopeExclusionRecord(
            id=item.hackerone_id,
            category=item.category,
            details=item.details,
            created_at=item.created_at_remote,
            updated_at=item.updated_at_remote,
            original=item.original or {},
        )
        for item in row.exclusions
    )
    weaknesses = tuple(
        WeaknessRecord(
            id=item.hackerone_id,
            name=item.name,
            description=item.description,
            external_id=item.external_id,
            original=item.original or {},
        )
        for item in row.weaknesses
    )
    return HackerOneProgram(
        handle=row.handle,
        name=row.name,
        program_id=row.program_id,
        program_url=row.program_url,
        fetched_at=row.fetched_at,
        sync_status=ProgramSyncStatus(row.sync_status),
        error=row.error,
        scope_mode=ScopeMode(row.scope_mode),
        offers_bounties=row.offers_bounties,
        requires_severity=row.requires_severity,
        instructions=row.instructions,
        structured_scopes=scopes,
        exclusions=exclusions,
        weaknesses=weaknesses,
        open_scope_policy=row.open_scope_policy,
        open_scope_acknowledged=row.open_scope_acknowledged,
        active_testing_approved=row.active_testing_approved,
        scope_version=row.scope_version,
        scope_sync_complete=row.scope_sync_complete,
        scope_count=row.scope_count,
        last_scope_id=row.last_scope_id,
        continuation_state=row.continuation_state,
    )


def _draft_from_row(row: DBHackerOneReportDraft) -> HackerOneReportDraft:
    approval = None
    if row.approved_by and row.approval_timestamp and row.approved_report_content_hash:
        approval = ApprovalRecord(
            approved_by=row.approved_by,
            approved_at=row.approval_timestamp,
            expires_at=row.approval_expires_at or row.approval_timestamp,
            report_content_hash=row.approved_report_content_hash,
            evidence_hash=row.approved_evidence_hash or "",
            scope_snapshot_hash=row.approved_scope_snapshot_hash or "",
            payload_hash=row.approved_payload_hash or "",
        )
    snapshot = None
    if isinstance(row.scope_snapshot, dict):
        snapshot = ScopeSnapshot(
            program_handle=str(row.scope_snapshot.get("program_handle") or row.program_handle),
            scope_version=int(row.scope_snapshot.get("scope_version") or 0),
            structured_scope_id=row.structured_scope_id,
            asset_identifier=str(row.scope_snapshot.get("asset_identifier") or ""),
            eligible_for_submission=bool(row.scope_snapshot.get("eligible_for_submission")),
            eligible_for_bounty=bool(row.scope_snapshot.get("eligible_for_bounty")),
            in_scope=bool(row.scope_snapshot.get("in_scope")),
            matched_instructions=str(row.scope_snapshot.get("matched_instructions") or ""),
            snapshot_hash=row.scope_snapshot_hash,
        )
    return HackerOneReportDraft(
        id=row.id,
        program_handle=row.program_handle,
        title=row.title,
        vulnerability_information=row.vulnerability_information,
        impact=row.impact,
        severity=row.severity,
        weakness_id=row.weakness_id,
        weakness_candidates=tuple(row.weakness_candidates or []),
        structured_scope_id=row.structured_scope_id,
        evidence_references=tuple(row.evidence_references or []),
        finding_id=str(row.finding_id) if row.finding_id else None,
        project_id=str(row.project_id) if row.project_id else None,
        created_at=row.created_at,
        human_review_state=ReportHumanReviewState(row.human_review_state),
        submission_state=ReportSubmissionState(row.submission_state),
        remote_state=HackerOneRemoteState(row.remote_state),
        hackerone_report_id=row.hackerone_report_id,
        finding_verification=row.finding_verification,
        error=row.error,
        last_payload=row.last_payload,
        reproduction=row.reproduction,
        target=row.target,
        eligible_for_submission=row.eligible_for_submission,
        eligible_for_bounty=row.eligible_for_bounty,
        report_content_hash=row.report_content_hash,
        evidence_hash=row.evidence_hash,
        scope_snapshot_hash=row.scope_snapshot_hash,
        payload_hash=row.payload_hash,
        approval=approval,
        scope_snapshot=snapshot,
    )


def _submission_from_row(row: DBHackerOneSubmission) -> SubmissionRecord:
    return SubmissionRecord(
        finding_id=row.finding_id,
        program=row.program_handle,
        submission_state=ReportSubmissionState(row.submission_state),
        hackerone_report_id=row.hackerone_report_id,
        created_at=row.created_at,
        metadata={"draft_id": row.draft_id or ""},
        remote_state=HackerOneRemoteState(row.remote_state),
        error=row.error,
    )


def _asset(value: str) -> AssetType:
    try:
        return AssetType(value)
    except ValueError:
        return asset_type_from_hackerone(value)


def _redact_details(details: dict[str, Any]) -> dict[str, Any]:
    blocked = {"token", "password", "cookie", "authorization", "api_token", "secret"}
    cleaned: dict[str, Any] = {}
    for key, value in details.items():
        lowered = key.lower()
        if any(part in lowered for part in blocked):
            continue
        if isinstance(value, str):
            cleaned[key] = redact_text(value)
        else:
            cleaned[key] = value
    return cleaned
