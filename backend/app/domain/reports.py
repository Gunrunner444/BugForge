"""Structured security report — vendor-neutral."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domain.findings import SecurityFinding


@dataclass
class SecurityReport:
    title: str
    findings: tuple[SecurityFinding, ...]
    generated_by: str
    body: str
    metadata: Mapping[str, str] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def verified_count(self) -> int:
        return sum(1 for finding in self.findings if finding.is_verified)

    @property
    def potential_count(self) -> int:
        return sum(1 for finding in self.findings if finding.status.value == "potential")


def iter_findings(findings: Sequence[SecurityFinding]) -> tuple[SecurityFinding, ...]:
    return tuple(findings)
