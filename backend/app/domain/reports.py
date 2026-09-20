"""Structured security report — vendor-neutral."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domain.findings import FindingStatus, HumanReviewState, SecurityFinding


@dataclass
class SecurityReport:
    """Local or remote report payload.

    ``submitted_remotely`` is always False for local rendering. Remote
    program submission (HackerOne, etc.) is reserved for a later phase.
    """

    title: str
    findings: tuple[SecurityFinding, ...]
    generated_by: str
    body: str
    metadata: Mapping[str, str] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    destination: str = "local"
    submitted_remotely: bool = False

    @property
    def verified_count(self) -> int:
        return sum(1 for finding in self.findings if finding.status is FindingStatus.VERIFIED)

    @property
    def potential_count(self) -> int:
        return sum(1 for finding in self.findings if finding.status is FindingStatus.POTENTIAL)

    @property
    def rejected_count(self) -> int:
        return sum(1 for finding in self.findings if finding.status is FindingStatus.REJECTED)

    def review_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {state.value: 0 for state in HumanReviewState}
        for finding in self.findings:
            counts[finding.human_review_state.value] += 1
        return counts


def iter_findings(findings: Sequence[SecurityFinding]) -> tuple[SecurityFinding, ...]:
    return tuple(findings)
