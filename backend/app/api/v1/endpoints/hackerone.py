"""HackerOne program + report workflow API. Credentials never leave the adapter."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from app.adapters.hackerone.credentials import HackerOneCredentials
from app.adapters.hackerone.errors import HackerOneError
from app.adapters.hackerone.provider import HackerOneProvider
from app.domain.evidence import Evidence, EvidenceKind
from app.domain.findings import FindingStatus, SecurityFinding
from app.schemas.hackerone import (
    ActiveTestingRequest,
    CreateDraftRequest,
    DraftActionRequest,
    FindingPayload,
    HackerOneSyncRequest,
    IntentRequest,
    OpenScopeAckRequest,
)
from app.security_testing.errors import RestrictedActivityError

router = APIRouter(prefix="/hackerone", tags=["HackerOne"])

_PROVIDER: HackerOneProvider | None = None
_FINDINGS: dict[str, SecurityFinding] = {}


def get_hackerone_provider() -> HackerOneProvider:
    global _PROVIDER
    if _PROVIDER is None:
        _PROVIDER = HackerOneProvider(credentials=HackerOneCredentials.from_env())
    return _PROVIDER


def reset_hackerone_provider(provider: HackerOneProvider | None = None) -> None:
    global _PROVIDER, _FINDINGS
    _PROVIDER = provider
    _FINDINGS = {}


@router.get("/status")
async def connection_status() -> dict[str, object]:
    provider = get_hackerone_provider()
    status_payload = provider.connection_status()
    # Belt-and-suspenders: never echo a token-shaped value.
    return {
        key: value
        for key, value in status_payload.items()
        if "token" not in key or key == "token_present"
    }


@router.post("/programs/sync")
async def sync_program(payload: HackerOneSyncRequest) -> dict[str, object]:
    provider = get_hackerone_provider()
    if not provider.credentials.configured:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="HackerOne API credentials are not configured (HACKERONE_API_USERNAME / HACKERONE_API_TOKEN)",
        )
    try:
        program = provider.lookup_program(payload.handle)
        program = provider.sync_scope(payload.handle)
    except HackerOneError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc
    return _program_view(program)


@router.get("/programs/{handle}")
async def get_program(handle: str) -> dict[str, object]:
    provider = get_hackerone_provider()
    program = provider.programs.get(handle)
    if program is None:
        raise HTTPException(status_code=404, detail="Program has not been imported")
    return _program_view(program)


@router.post("/programs/{handle}/open-scope")
async def ack_open_scope(handle: str, payload: OpenScopeAckRequest) -> dict[str, object]:
    provider = get_hackerone_provider()
    try:
        program = provider.acknowledge_open_scope(
            handle, operator=payload.operator, policy=payload.policy
        )
    except RestrictedActivityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except HackerOneError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _program_view(program)


@router.post("/programs/{handle}/active-testing")
async def approve_active_testing(handle: str, payload: ActiveTestingRequest) -> dict[str, object]:
    provider = get_hackerone_provider()
    try:
        program = provider.approve_active_testing(handle, operator=payload.operator)
    except RestrictedActivityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except HackerOneError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _program_view(program)


@router.post("/reports/drafts")
async def create_draft(payload: CreateDraftRequest) -> dict[str, object]:
    provider = get_hackerone_provider()
    finding = _finding_from_payload(payload.finding)
    _FINDINGS[str(finding.id)] = finding
    try:
        draft = provider.draft_from_finding(
            finding,
            payload.program_handle,
            severity=payload.severity,
            weakness_id=payload.weakness_id,
            operator=payload.operator,
        )
    except HackerOneError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return draft.snapshot()


@router.post("/reports/{draft_id}/review")
async def mark_review(draft_id: str, payload: DraftActionRequest) -> dict[str, object]:
    provider = get_hackerone_provider()
    try:
        draft = provider.reports.mark_ready(draft_id)
    except HackerOneError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return draft.snapshot()


@router.post("/reports/{draft_id}/dry-run")
async def dry_run(draft_id: str, payload: DraftActionRequest) -> dict[str, object]:
    provider = get_hackerone_provider()
    program = provider.programs.get(payload.program_handle or "")
    draft = provider.reports.drafts.get(draft_id)
    if program is None or draft is None:
        raise HTTPException(status_code=404, detail="Draft or program not found")
    finding = _FINDINGS.get(draft.finding_id or "")
    return provider.reports.dry_run(draft_id, program, finding=finding)


@router.post("/reports/{draft_id}/approve")
async def approve(draft_id: str, payload: DraftActionRequest) -> dict[str, object]:
    provider = get_hackerone_provider()
    try:
        draft = provider.reports.human_approve(draft_id, operator=payload.operator)
    except RestrictedActivityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except HackerOneError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return draft.snapshot()


@router.post("/reports/{draft_id}/submit")
async def submit(draft_id: str, payload: DraftActionRequest) -> dict[str, object]:
    provider = get_hackerone_provider()
    program = provider.programs.get(payload.program_handle or "")
    draft = provider.reports.drafts.get(draft_id)
    if program is None or draft is None:
        raise HTTPException(status_code=404, detail="Draft or program not found")
    if draft.human_review_state.value != "human_approved":
        raise HTTPException(
            status_code=403,
            detail="Submit remains disabled until HUMAN_APPROVED and validation pass",
        )
    finding = _FINDINGS.get(draft.finding_id or "")
    try:
        result = provider.reports.submit(
            draft_id, program, finding=finding, operator=payload.operator
        )
    except RestrictedActivityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except HackerOneError as exc:
        raise HTTPException(status_code=exc.status_code or 400, detail=str(exc)) from exc
    return result.snapshot()


@router.post("/report-intents")
async def create_intent(payload: IntentRequest) -> dict[str, object]:
    provider = get_hackerone_provider()
    try:
        return provider.intents.create(payload.payload)
    except HackerOneError as exc:
        raise HTTPException(status_code=exc.status_code or 400, detail=str(exc)) from exc


@router.get("/report-intents/{intent_id}")
async def get_intent(intent_id: str) -> dict[str, object]:
    provider = get_hackerone_provider()
    try:
        return provider.intents.get(intent_id)
    except HackerOneError as exc:
        raise HTTPException(status_code=exc.status_code or 400, detail=str(exc)) from exc


def _program_view(program: object) -> dict[str, object]:
    from app.adapters.hackerone.models import HackerOneProgram

    assert isinstance(program, HackerOneProgram)
    snap = program.snapshot()
    snap["structured_scopes"] = [
        {
            "id": item.id,
            "asset_type": item.asset_type.value,
            "asset_identifier": item.asset_identifier,
            "instruction": item.instruction,
            "eligible_for_bounty": item.eligible_for_bounty,
            "eligible_for_submission": item.eligible_for_submission,
            "reference": item.reference,
        }
        for item in program.structured_scopes
    ]
    snap["exclusions"] = [
        {
            "id": item.id,
            "category": item.category,
            "details": item.details,
            "created_at": item.created_at,
            "updated_at": item.updated_at,
        }
        for item in program.exclusions
    ]
    snap["instructions"] = program.instructions
    return snap


def _finding_from_payload(payload: FindingPayload) -> SecurityFinding:
    try:
        status_value = FindingStatus(payload.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Unknown finding status") from exc
    evidence = [
        Evidence(
            kind=_kind(item.kind),
            source=item.source,
            summary=item.summary,
            details=item.details,
        )
        for item in payload.evidence
    ]
    if status_value is FindingStatus.VERIFIED:
        return SecurityFinding.verified(
            payload.title,
            evidence=evidence,
            description=payload.description,
            vulnerability_class=payload.vulnerability_class,
            target=payload.target,
            impact=payload.impact,
            reproduction=payload.reproduction,
        )
    if status_value is FindingStatus.HUMAN_ACCEPTED:
        return SecurityFinding.verified(
            payload.title,
            evidence=evidence,
            description=payload.description,
            vulnerability_class=payload.vulnerability_class,
            target=payload.target,
            impact=payload.impact,
            reproduction=payload.reproduction,
        ).human_accept()
    return SecurityFinding.potential(
        payload.title,
        description=payload.description,
        vulnerability_class=payload.vulnerability_class,
        target=payload.target,
        impact=payload.impact,
        reproduction=payload.reproduction,
        evidence=evidence,
    )


def _kind(value: str) -> EvidenceKind:
    try:
        return EvidenceKind(value)
    except ValueError:
        return EvidenceKind.REPRODUCTION
