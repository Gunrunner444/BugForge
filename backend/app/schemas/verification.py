"""Pydantic schemas for v0.8 Patch Verification."""
from __future__ import annotations

import json
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class VerificationResponse(BaseModel):
    """Full verification record returned from the API."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    candidate_id: UUID
    session_id: UUID
    project_id: UUID
    status: str
    error_message: str | None

    # baseline
    baseline_reproduced: bool | None
    baseline_reproduction_evidence: str | None
    baseline_tests_total: int
    baseline_tests_passed: int
    baseline_tests_failed: int
    baseline_tests_error: int
    baseline_tests_skipped: int
    baseline_passing_ids: list[str]
    baseline_failing_ids: list[str]
    baseline_static_findings: int

    # patch application
    patch_applied: bool | None
    patch_apply_error: str | None

    # post-patch
    post_patch_reproduced: bool | None
    post_patch_reproduction_evidence: str | None
    post_tests_total: int
    post_tests_passed: int
    post_tests_failed: int
    post_tests_error: int
    post_tests_skipped: int
    post_passing_ids: list[str]
    post_failing_ids: list[str]
    post_static_findings: int

    # comparison
    target_bug_fixed: bool | None
    newly_failing_ids: list[str]
    recovered_ids: list[str]
    regression_count: int
    new_static_introduced: int
    static_resolved: int

    # security
    security_passed: bool | None
    security_issues: list[str]

    # decision
    verification_score: float | None
    verification_decision: str | None
    decision_reasons: list[str]
    evidence_summary: str | None

    # timestamps
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None

    @classmethod
    def from_orm(cls, v: object) -> VerificationResponse:
        from app.models.verification import PatchVerification

        assert isinstance(v, PatchVerification)

        def _parse(json_str: str | None) -> list[str]:
            if not json_str:
                return []
            try:
                result = json.loads(json_str)
                return result if isinstance(result, list) else []
            except (json.JSONDecodeError, TypeError):
                return []

        return cls(
            id=v.id,
            candidate_id=v.candidate_id,
            session_id=v.session_id,
            project_id=v.project_id,
            status=v.status,
            error_message=v.error_message,
            baseline_reproduced=v.baseline_reproduced,
            baseline_reproduction_evidence=v.baseline_reproduction_evidence,
            baseline_tests_total=v.baseline_tests_total,
            baseline_tests_passed=v.baseline_tests_passed,
            baseline_tests_failed=v.baseline_tests_failed,
            baseline_tests_error=v.baseline_tests_error,
            baseline_tests_skipped=v.baseline_tests_skipped,
            baseline_passing_ids=_parse(v.baseline_passing_ids_json),
            baseline_failing_ids=_parse(v.baseline_failing_ids_json),
            baseline_static_findings=v.baseline_static_findings,
            patch_applied=v.patch_applied,
            patch_apply_error=v.patch_apply_error,
            post_patch_reproduced=v.post_patch_reproduced,
            post_patch_reproduction_evidence=v.post_patch_reproduction_evidence,
            post_tests_total=v.post_tests_total,
            post_tests_passed=v.post_tests_passed,
            post_tests_failed=v.post_tests_failed,
            post_tests_error=v.post_tests_error,
            post_tests_skipped=v.post_tests_skipped,
            post_passing_ids=_parse(v.post_passing_ids_json),
            post_failing_ids=_parse(v.post_failing_ids_json),
            post_static_findings=v.post_static_findings,
            target_bug_fixed=v.target_bug_fixed,
            newly_failing_ids=_parse(v.newly_failing_ids_json),
            recovered_ids=_parse(v.recovered_ids_json),
            regression_count=v.regression_count,
            new_static_introduced=v.new_static_introduced,
            static_resolved=v.static_resolved,
            security_passed=v.security_passed,
            security_issues=_parse(v.security_issues_json),
            verification_score=v.verification_score,
            verification_decision=v.verification_decision,
            decision_reasons=_parse(v.decision_reasons_json),
            evidence_summary=v.evidence_summary,
            created_at=v.created_at,
            started_at=v.started_at,
            completed_at=v.completed_at,
        )


class StartVerificationRequest(BaseModel):
    """Request body for starting verification of a patch candidate."""
    pass  # No body required; candidate_id comes from the path
