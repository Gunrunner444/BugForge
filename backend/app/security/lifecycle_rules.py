"""Shared reproduction and verification predicates.

Correlation decides whether evidence belongs to a finding. These predicates
decide whether that evidence is allowed to drive a domain transition.
``FindingLifecycleService`` and the research agent both use them, so
"reproduced" and "verified" do not mean different things in the two systems.
"""

from __future__ import annotations

from app.domain.evidence import Evidence, EvidenceKind, EvidenceProvenance
from app.domain.findings import SecurityFinding
from app.security.evidence_correlation import evidence_contradicts, evidence_identity

# Kinds that can verify a finding without being the reproduction record itself.
# A log, a screenshot, a test failure, a generated test, static analysis, and
# AI text are intentionally absent.
INDEPENDENT_VERIFICATION_KINDS = frozenset(
    {
        EvidenceKind.HTTP_RESPONSE,
        EvidenceKind.BROWSER,
        EvidenceKind.SCANNER,
        EvidenceKind.API_TEST,
        EvidenceKind.REPLAY,
        EvidenceKind.FUZZING,
        EvidenceKind.PROXY,
    }
)

_FAILED_OUTCOMES = frozenset(
    {
        "failed",
        "not_reproduced",
        "blocked",
        "inconclusive",
        "error",
        "no_evidence",
        "environment_error",
        "timeout",
    }
)
_POSITIVE_OUTCOMES = frozenset({"reproduced", "success", "exploited"})
_NEGATIVE_FLAGS = frozenset({"0", "false", "no"})
_POSITIVE_FLAGS = frozenset({"1", "true", "yes"})


def positive_reproduction(item: Evidence) -> bool:
    """True only for a successful reproduction record, not a failed attempt.

    ``REPRODUCTION`` provenance is necessary. A test failure, log, screenshot,
    generated test, or contradictory result is not a successful reproduction.
    A missing outcome is accepted for a ``REPRODUCTION`` record that does not
    declare failure, because the reproduction engine emits that kind only after
    a positive result. Collectors must not use this kind for plans or failures.
    """
    if item.kind is not EvidenceKind.REPRODUCTION:
        return False
    if item.provenance is not EvidenceProvenance.REPRODUCTION:
        return False
    if evidence_contradicts(item):
        return False
    outcome = _meta(item, "outcome").lower()
    reproduced = _meta(item, "reproduced").lower()
    if outcome in _FAILED_OUTCOMES or reproduced in _NEGATIVE_FLAGS:
        return False
    if outcome in _POSITIVE_OUTCOMES or reproduced in _POSITIVE_FLAGS:
        return True
    return outcome == "" and reproduced == ""


def independent_verification_items(finding: SecurityFinding) -> tuple[Evidence, ...]:
    """Observations that can verify a finding apart from its reproduction record.

    The same stable evidence identity cannot satisfy reproduction and
    verification. A single HTTP, browser, scanner, API, replay, fuzzing, or
    proxy observation can verify when it is not that reproduction record.
    """
    reproduction_keys = {
        evidence_identity(item)
        for item in finding.evidence.items
        if positive_reproduction(item)
    }
    found: list[Evidence] = []
    for item in finding.evidence.items:
        if evidence_contradicts(item) or not item.contributes_to_verification:
            continue
        if item.kind not in INDEPENDENT_VERIFICATION_KINDS:
            continue
        if evidence_identity(item) in reproduction_keys:
            continue
        found.append(item)
    return tuple(found)


def _meta(item: Evidence, key: str) -> str:
    value = item.metadata.get(key)
    return "" if value is None else str(value)
