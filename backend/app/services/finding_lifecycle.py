"""Attach trusted evidence to persisted findings and apply domain transitions.

Correlation answers whether evidence belongs to a finding. Verification is a
separate domain transition. This service never assigns ``FindingStatus``
directly and never treats model text as independent evidence.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from uuid import UUID

from app.domain.evidence import Evidence
from app.domain.findings import SecurityFinding
from app.repositories.security_finding_repo import SecurityFindingRepository, to_domain
from app.security.evidence_correlation import (
    correlate_finding,
    evidence_contradicts,
)


class LifecycleTransition(StrEnum):
    NONE = "none"
    CORROBORATE = "corroborate"
    REPRODUCE = "reproduce"
    VERIFY = "verify"
    HUMAN_ACCEPT = "human_accept"
    REJECT = "reject"


class FindingNotFoundError(LookupError):
    """No persisted security finding matches the requested id."""


class FindingLifecycleService:
    def __init__(self, repo: SecurityFindingRepository) -> None:
        self._repo = repo

    async def attach_evidence(
        self,
        finding_id: UUID,
        evidence: Sequence[Evidence],
        *,
        project_id: UUID | None = None,
        analysis_id: UUID | None = None,
        transition: LifecycleTransition = LifecycleTransition.NONE,
    ) -> SecurityFinding:
        """Correlate matching evidence, optionally transition, then persist.

        ``transition`` must be requested explicitly. Correlation alone never
        corroborates, reproduces, verifies, accepts, or rejects a finding.
        """
        finding = await self._repo.get_domain(finding_id)
        if finding is None:
            raise FindingNotFoundError(str(finding_id))
        peers = await self._peers(finding, project_id=project_id)
        updated = correlate_finding(finding, evidence, peers=peers)
        if transition is not LifecycleTransition.NONE:
            updated = apply_lifecycle_transition(updated, transition)
        persisted = await self._repo.save_domain(
            updated, project_id=project_id, analysis_id=analysis_id
        )
        return to_domain(persisted)

    async def _peers(
        self, finding: SecurityFinding, *, project_id: UUID | None
    ) -> tuple[SecurityFinding, ...]:
        if project_id is None:
            return ()
        rows, _total = await self._repo.list_for_project(project_id)
        return tuple(to_domain(row) for row in rows if row.id != finding.id)


def apply_lifecycle_transition(
    finding: SecurityFinding, transition: LifecycleTransition
) -> SecurityFinding:
    """Run one domain method. Orchestration cannot assign status itself."""
    if transition is LifecycleTransition.CORROBORATE:
        return finding.corroborate()
    if transition is LifecycleTransition.REPRODUCE:
        _require_supporting_runtime(finding, action="reproduce")
        return finding.reproduce()
    if transition is LifecycleTransition.VERIFY:
        _require_supporting_runtime(finding, action="verify")
        return finding.verify()
    if transition is LifecycleTransition.HUMAN_ACCEPT:
        return finding.human_accept()
    if transition is LifecycleTransition.REJECT:
        return finding.reject()
    return finding


def _require_supporting_runtime(finding: SecurityFinding, *, action: str) -> None:
    supporting = [
        item
        for item in finding.evidence.items
        if item.contributes_to_verification and not evidence_contradicts(item)
    ]
    if not supporting:
        raise ValueError(
            f"Cannot {action} a finding without supporting independent evidence. "
            "Contradictory, AI, static, and generated-test artifacts are not enough."
        )
