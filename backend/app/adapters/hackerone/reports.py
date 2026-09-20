"""HackerOne report drafts, validation, dry-run, and gated submission."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from app.adapters.hackerone.client import HackerOneApiClient
from app.adapters.hackerone.errors import HackerOneError, HackerOneIdentityVerificationError
from app.adapters.hackerone.evaluator import HackerOneScopeDecision, HackerOneScopeEvaluator
from app.adapters.hackerone.models import HackerOneProgram
from app.adapters.hackerone.weakness import map_weakness
from app.domain.findings import FindingStatus, SecurityFinding
from app.security_testing.secrets import redact_text

_SECRET_HINTS = (
    "authorization",
    "bearer ",
    "api_key",
    "apikey",
    "password",
    "session",
    "cookie",
    "hackerone_api_token",
    "secret",
)


class ReportHumanReviewState(StrEnum):
    UNREVIEWED = "unreviewed"
    READY_FOR_REVIEW = "ready_for_review"
    HUMAN_APPROVED = "human_approved"
    REJECTED = "rejected"


class ReportSubmissionState(StrEnum):
    LOCAL_DRAFT = "local_draft"
    READY_FOR_REVIEW = "ready_for_review"
    HUMAN_APPROVED = "human_approved"
    SUBMISSION_ATTEMPTED = "submission_attempted"
    SUBMITTED = "submitted"
    SUBMISSION_FAILED = "submission_failed"
    IDENTITY_VERIFICATION_REQUIRED = "identity_verification_required"


class HackerOneRemoteState(StrEnum):
    UNKNOWN = "unknown"
    NEW = "new"
    PENDING = "pending"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    NOT_FETCHED = "not_fetched"


_SEVERITIES = ("critical", "high", "medium", "low", "informational")
_H1_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "none",
    "none": "none",
}


@dataclass(frozen=True)
class ValidationIssue:
    field: str
    message: str
    blocking: bool = True


@dataclass(frozen=True)
class ReportValidationReport:
    ok: bool
    issues: tuple[ValidationIssue, ...]

    def blocking(self) -> tuple[ValidationIssue, ...]:
        return tuple(item for item in self.issues if item.blocking)


@dataclass
class HackerOneReportDraft:
    program_handle: str
    title: str
    vulnerability_information: str
    impact: str = ""
    severity: str | None = None
    weakness_id: str | None = None
    weakness_candidates: tuple[str, ...] = ()
    structured_scope_id: str | None = None
    evidence_references: tuple[str, ...] = ()
    finding_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    human_review_state: ReportHumanReviewState = ReportHumanReviewState.UNREVIEWED
    submission_state: ReportSubmissionState = ReportSubmissionState.LOCAL_DRAFT
    remote_state: HackerOneRemoteState = HackerOneRemoteState.NOT_FETCHED
    hackerone_report_id: str | None = None
    finding_verification: str | None = None
    error: str | None = None
    last_payload: dict[str, Any] | None = None
    id: str = field(default_factory=lambda: uuid4().hex)
    operator: str | None = None
    reproduction: str | None = None
    target: str | None = None
    eligible_for_submission: bool = False

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "program_handle": self.program_handle,
            "title": self.title,
            "severity": self.severity,
            "weakness_id": self.weakness_id,
            "structured_scope_id": self.structured_scope_id,
            "finding_id": self.finding_id,
            "human_review_state": self.human_review_state.value,
            "submission_state": self.submission_state.value,
            "remote_state": self.remote_state.value,
            "finding_verification": self.finding_verification,
            "hackerone_report_id": self.hackerone_report_id,
            "eligible_for_submission": self.eligible_for_submission,
            "target": self.target,
            "error": self.error,
        }


@dataclass
class SubmissionRecord:
    finding_id: str
    hackerone_report_id: str
    program: str
    submission_state: ReportSubmissionState
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, str] = field(default_factory=dict)


class ReportQualityValidator:
    def validate(
        self,
        draft: HackerOneReportDraft,
        *,
        program: HackerOneProgram,
        scope: HackerOneScopeDecision | None,
        finding: SecurityFinding | None = None,
    ) -> ReportValidationReport:
        issues: list[ValidationIssue] = []
        if not draft.title.strip():
            issues.append(ValidationIssue("title", "Title is required"))
        if not draft.vulnerability_information.strip():
            issues.append(
                ValidationIssue(
                    "vulnerability_information", "Vulnerability information is required"
                )
            )
        if not draft.impact.strip():
            issues.append(ValidationIssue("impact", "Impact is required"))
        if not draft.target:
            issues.append(ValidationIssue("target", "Target is required"))
        if scope is None or not scope.in_scope:
            issues.append(
                ValidationIssue("target", "Target is not in the current HackerOne structured scope")
            )
        if scope is not None and not scope.eligible_for_submission:
            issues.append(ValidationIssue("target", "Target is not eligible for submission"))
        if not draft.structured_scope_id:
            issues.append(ValidationIssue("structured_scope_id", "structured_scope_id is required"))
        elif scope is not None and scope.structured_scope_id != draft.structured_scope_id:
            issues.append(
                ValidationIssue(
                    "structured_scope_id",
                    "structured_scope_id does not match the current scope match",
                )
            )
        if program.requires_severity:
            if not draft.severity:
                issues.append(ValidationIssue("severity", "Severity is required for this program"))
            elif draft.severity not in _SEVERITIES:
                issues.append(
                    ValidationIssue("severity", "Severity is not a recognized HackerOne rating")
                )
        if not draft.weakness_id:
            issues.append(
                ValidationIssue(
                    "weakness_id",
                    "Weakness must be selected by a human when ambiguous or missing",
                    blocking=True,
                )
            )
        if not draft.evidence_references:
            issues.append(ValidationIssue("evidence", "Evidence must be linked"))
        if finding is not None:
            if finding.status not in {FindingStatus.VERIFIED, FindingStatus.HUMAN_ACCEPTED}:
                issues.append(
                    ValidationIssue(
                        "finding",
                        "Only verified findings can become submission-ready reports",
                    )
                )
            if not finding.evidence.verifying_items():
                issues.append(ValidationIssue("evidence", "Finding lacks verifying evidence"))
            if not (finding.reproduction or draft.reproduction):
                issues.append(
                    ValidationIssue(
                        "reproduction", "Reproduction information is required", blocking=True
                    )
                )
        leaked = _secret_hits(
            draft.title,
            draft.vulnerability_information,
            draft.impact,
            draft.reproduction or "",
        )
        if leaked:
            issues.append(
                ValidationIssue("secrets", f"Possible secret leakage: {', '.join(leaked)}")
            )
        return ReportValidationReport(
            ok=not any(item.blocking for item in issues), issues=tuple(issues)
        )


class HackerOneReportWorkflow:
    def __init__(
        self,
        client: HackerOneApiClient,
        *,
        evaluator: HackerOneScopeEvaluator | None = None,
    ) -> None:
        self.client = client
        self.evaluator = evaluator or HackerOneScopeEvaluator()
        self.validator = ReportQualityValidator()
        self.drafts: dict[str, HackerOneReportDraft] = {}
        self.submissions: dict[str, SubmissionRecord] = {}

    def draft_from_finding(
        self,
        finding: SecurityFinding,
        program: HackerOneProgram,
        *,
        severity: str | None = None,
        weakness_id: str | None = None,
        operator: str | None = None,
    ) -> HackerOneReportDraft:
        if finding.status not in {FindingStatus.VERIFIED, FindingStatus.HUMAN_ACCEPTED}:
            raise HackerOneError(
                "A finding can become a HackerOne report draft only after independent verification",
                code="finding_not_verified",
            )
        if not finding.evidence or not finding.evidence.verifying_items():
            raise HackerOneError("Verified evidence is required", code="evidence_required")
        target = finding.target or finding.endpoint or finding.asset or ""
        scope = (
            self.evaluator.evaluate(program, target)
            if target
            else HackerOneScopeDecision(False, "Finding has no target")
        )
        mapped = map_weakness(finding.vulnerability_class)
        selected = weakness_id or mapped.selected
        if mapped.requires_human_selection and not weakness_id:
            selected = None
        draft = HackerOneReportDraft(
            program_handle=program.handle,
            title=finding.report_title or finding.title,
            vulnerability_information=finding.report_description
            or finding.description
            or finding.observed_behavior
            or "",
            impact=finding.impact or "",
            severity=_normalize_severity(severity),
            weakness_id=selected,
            weakness_candidates=mapped.candidates,
            structured_scope_id=scope.structured_scope_id,
            evidence_references=tuple(str(item.id) for item in finding.evidence.verifying_items()),
            finding_id=str(finding.id),
            finding_verification=finding.status.value,
            reproduction=finding.reproduction,
            target=target,
            eligible_for_submission=scope.eligible_for_submission,
            operator=operator,
        )
        self.drafts[draft.id] = draft
        return draft

    def mark_ready(self, draft_id: str) -> HackerOneReportDraft:
        draft = self._get(draft_id)
        updated = replace(
            draft,
            human_review_state=ReportHumanReviewState.READY_FOR_REVIEW,
            submission_state=ReportSubmissionState.READY_FOR_REVIEW,
        )
        self.drafts[draft_id] = updated
        return updated

    def human_approve(self, draft_id: str, *, operator: str) -> HackerOneReportDraft:
        from app.security_testing.approvals import is_ai_operator
        from app.security_testing.errors import RestrictedActivityError

        if is_ai_operator(operator):
            raise RestrictedActivityError("hackerone_submission")
        draft = self._get(draft_id)
        if draft.submission_state not in {
            ReportSubmissionState.READY_FOR_REVIEW,
            ReportSubmissionState.LOCAL_DRAFT,
            ReportSubmissionState.SUBMISSION_FAILED,
            ReportSubmissionState.IDENTITY_VERIFICATION_REQUIRED,
        }:
            raise HackerOneError("Draft is not awaiting human approval", code="invalid_state")
        updated = replace(
            draft,
            human_review_state=ReportHumanReviewState.HUMAN_APPROVED,
            submission_state=ReportSubmissionState.HUMAN_APPROVED,
            operator=operator,
        )
        self.drafts[draft_id] = updated
        return updated

    def build_payload(self, draft: HackerOneReportDraft) -> dict[str, Any]:
        attributes: dict[str, Any] = {
            "team_handle": draft.program_handle,
            "title": draft.title,
            "vulnerability_information": draft.vulnerability_information,
            "impact": draft.impact,
        }
        if draft.severity:
            attributes["severity_rating"] = _H1_SEVERITY.get(draft.severity, draft.severity)
        relationships: dict[str, Any] = {}
        if draft.weakness_id:
            relationships["weakness"] = {"data": {"type": "weakness", "id": str(draft.weakness_id)}}
        if draft.structured_scope_id:
            relationships["structured_scope"] = {
                "data": {"type": "structured-scope", "id": str(draft.structured_scope_id)}
            }
        payload: dict[str, Any] = {"data": {"type": "report", "attributes": attributes}}
        if relationships:
            payload["data"]["relationships"] = relationships
        return payload

    def redacted_payload(self, draft: HackerOneReportDraft) -> dict[str, Any]:
        return _redact_payload(self.build_payload(draft))

    def dry_run(
        self,
        draft_id: str,
        program: HackerOneProgram,
        *,
        finding: SecurityFinding | None = None,
    ) -> dict[str, Any]:
        draft = self._get(draft_id)
        scope = self.evaluator.evaluate(program, draft.target or "")
        report = self.validator.validate(draft, program=program, scope=scope, finding=finding)
        payload = self.redacted_payload(draft)
        before = list(self.client.calls)
        # Authenticate / program read is allowed; never POST /hackers/reports.
        return {
            "would_submit": False,
            "payload": payload,
            "validation": {
                "ok": report.ok,
                "issues": [issue.__dict__ for issue in report.issues],
            },
            "scope": scope.__dict__,
            "api_calls_during_dry_run": list(self.client.calls[len(before) :]),
        }

    def submit(
        self,
        draft_id: str,
        program: HackerOneProgram,
        *,
        finding: SecurityFinding | None = None,
        operator: str,
    ) -> HackerOneReportDraft:
        from app.security_testing.approvals import is_ai_operator
        from app.security_testing.errors import RestrictedActivityError

        if is_ai_operator(operator):
            raise RestrictedActivityError("hackerone_submission")
        draft = self._get(draft_id)
        if draft.finding_id and draft.finding_id in self.submissions:
            existing = self.submissions[draft.finding_id]
            raise HackerOneError(
                f"Finding already submitted as HackerOne report {existing.hackerone_report_id}",
                code="duplicate",
            )
        if draft.hackerone_report_id:
            raise HackerOneError("Draft already has a HackerOne report id", code="duplicate")
        if draft.submission_state is not ReportSubmissionState.HUMAN_APPROVED:
            raise HackerOneError(
                "Real submission requires HUMAN_APPROVED. Use dry-run until a human approves.",
                code="not_approved",
            )
        scope = self.evaluator.evaluate(program, draft.target or "")
        report = self.validator.validate(draft, program=program, scope=scope, finding=finding)
        if not report.ok:
            raise HackerOneError(
                "Draft failed local validation: "
                + "; ".join(item.message for item in report.blocking()),
                code="validation_failed",
            )
        payload = self.build_payload(draft)
        attempted = replace(
            draft,
            submission_state=ReportSubmissionState.SUBMISSION_ATTEMPTED,
            last_payload=self.redacted_payload(draft),
        )
        self.drafts[draft_id] = attempted
        try:
            body = self.client.post("hackers/reports", json_body=payload)
        except HackerOneIdentityVerificationError as exc:
            failed = replace(
                attempted,
                submission_state=ReportSubmissionState.IDENTITY_VERIFICATION_REQUIRED,
                error=str(exc),
            )
            self.drafts[draft_id] = failed
            return failed
        except HackerOneError as exc:
            failed = replace(
                attempted,
                submission_state=ReportSubmissionState.SUBMISSION_FAILED,
                error=str(exc),
            )
            self.drafts[draft_id] = failed
            return failed
        report_id = str((body.get("data") or {}).get("id") or "")
        submitted = replace(
            attempted,
            submission_state=ReportSubmissionState.SUBMITTED,
            remote_state=HackerOneRemoteState.NEW,
            hackerone_report_id=report_id,
            error=None,
        )
        self.drafts[draft_id] = submitted
        if submitted.finding_id and report_id:
            self.submissions[submitted.finding_id] = SubmissionRecord(
                finding_id=submitted.finding_id,
                hackerone_report_id=report_id,
                program=program.handle,
                submission_state=ReportSubmissionState.SUBMITTED,
                metadata={"draft_id": draft_id},
            )
        return submitted

    def _get(self, draft_id: str) -> HackerOneReportDraft:
        draft = self.drafts.get(draft_id)
        if draft is None:
            raise HackerOneError("Unknown report draft", code="not_found")
        return draft


class ReportIntentWorkflow:
    """Separate HackerOne Report Assistant / intents workflow. Not verified evidence."""

    def __init__(self, client: HackerOneApiClient) -> None:
        self.client = client

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.client.post("hackers/report_intents", json_body=payload)

    def get(self, intent_id: str) -> dict[str, Any]:
        return self.client.get(f"hackers/report_intents/{intent_id}")

    def patch(self, intent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.client.patch(f"hackers/report_intents/{intent_id}", json_body=payload)

    def submit(self, intent_id: str) -> dict[str, Any]:
        return self.client.post(f"hackers/report_intents/{intent_id}/submit", json_body={})


def _normalize_severity(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    lowered = value.strip().lower()
    if lowered not in _SEVERITIES and lowered != "none":
        raise HackerOneError(
            "Unknown severity; BugForge will not invent one", code="severity_invalid"
        )
    if lowered == "none":
        return "informational"
    return lowered


def _secret_hits(*parts: str) -> tuple[str, ...]:
    hits: list[str] = []
    blob = "\n".join(parts).lower()
    for hint in _SECRET_HINTS:
        if hint in blob:
            hits.append(hint.strip())
    if "hackerone" in blob and "token" in blob:
        hits.append("hackerone-token")
    return tuple(dict.fromkeys(hits))


def _redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    import json

    text = redact_text(json.dumps(payload, default=str))
    parsed: object = json.loads(text)
    if isinstance(parsed, dict):
        return parsed
    return payload
