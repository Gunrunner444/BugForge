"""Security finding domain model.

Static-analysis :class:`app.analysis.finding.Finding` records remain the
representation of code-quality/static issues. This model is the foundation
for later security-verification work and must not import vendor SDKs.

Invariant: an AI hypothesis never becomes a verified finding by itself.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from app.domain.evidence import Evidence, EvidenceBundle


class FindingStatus(StrEnum):
    POTENTIAL = "potential"
    VERIFIED = "verified"
    REJECTED = "rejected"


class HumanReviewState(StrEnum):
    UNREVIEWED = "unreviewed"
    IN_REVIEW = "in_review"
    ACCEPTED = "accepted"
    DISMISSED = "dismissed"


@dataclass(frozen=True)
class SourceLocation:
    file_path: str
    line: int | None = None
    end_line: int | None = None
    column: int | None = None
    function: str | None = None


@dataclass
class SecurityFinding:
    """A security (or suspected security) finding with explicit verification state.

    Use the constructors :meth:`potential`, :meth:`verified`, and
    :meth:`rejected` rather than setting ``status`` ad hoc. ``verified``
    requires a non-empty evidence bundle.
    """

    title: str
    status: FindingStatus
    description: str = ""
    vulnerability_class: str | None = None
    target: str | None = None
    endpoint: str | None = None
    source_location: SourceLocation | None = None
    hypothesis: str | None = None
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    reproduction: str | None = None
    observed_behavior: str | None = None
    expected_behavior: str | None = None
    impact: str | None = None
    confidence: str = "low"
    reproducibility: str | None = None
    tools: tuple[str, ...] = ()
    ai_analysis: str | None = None
    human_review_state: HumanReviewState = HumanReviewState.UNREVIEWED
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.title.strip():
            raise ValueError("Finding title must be non-empty")
        if self.status is FindingStatus.VERIFIED and not self.evidence:
            raise ValueError(
                "A verified finding requires evidence. "
                "AI hypotheses must remain potential until independently confirmed."
            )

    @property
    def is_verified(self) -> bool:
        return self.status is FindingStatus.VERIFIED

    @classmethod
    def potential(
        cls,
        title: str,
        *,
        hypothesis: str | None = None,
        evidence: EvidenceBundle | Sequence[Evidence] | None = None,
        **kwargs: Any,
    ) -> SecurityFinding:
        """Create a potential finding. AI output must use this constructor."""
        return cls(
            title=title,
            status=FindingStatus.POTENTIAL,
            hypothesis=hypothesis,
            evidence=_as_bundle(evidence),
            **kwargs,
        )

    @classmethod
    def from_hypothesis(
        cls,
        title: str,
        hypothesis: str,
        *,
        evidence: EvidenceBundle | Sequence[Evidence] | None = None,
        ai_analysis: str | None = None,
        **kwargs: Any,
    ) -> SecurityFinding:
        """Wrap a model-generated hypothesis. Always potential, never verified."""
        return cls.potential(
            title,
            hypothesis=hypothesis,
            evidence=evidence,
            ai_analysis=ai_analysis or hypothesis,
            **kwargs,
        )

    @classmethod
    def verified(
        cls,
        title: str,
        *,
        evidence: EvidenceBundle | Sequence[Evidence],
        **kwargs: Any,
    ) -> SecurityFinding:
        bundle = _as_bundle(evidence)
        if not bundle:
            raise ValueError("Verified findings require at least one evidence item")
        return cls(title=title, status=FindingStatus.VERIFIED, evidence=bundle, **kwargs)

    @classmethod
    def rejected(
        cls,
        title: str,
        *,
        evidence: EvidenceBundle | Sequence[Evidence] | None = None,
        **kwargs: Any,
    ) -> SecurityFinding:
        return cls(
            title=title,
            status=FindingStatus.REJECTED,
            evidence=_as_bundle(evidence),
            **kwargs,
        )


def _as_bundle(evidence: EvidenceBundle | Sequence[Evidence] | None) -> EvidenceBundle:
    if evidence is None:
        return EvidenceBundle()
    if isinstance(evidence, EvidenceBundle):
        return evidence
    return EvidenceBundle.from_items(evidence)
