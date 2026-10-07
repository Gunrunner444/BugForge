"""Bounty-quality research findings.

A finding here is a static candidate plus everything a reviewer needs to judge it:
scope, known-issue and duplicate status, the evidence that exists, and what is still
missing. Suppression is a statement about reporting, never about safety: a known
issue is not safe, an out-of-scope asset is not safe, and a duplicate is not safe.
Severity is only ever a candidate drawn from the program's own policy.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from app.discovery.bounty.campaign import (
    BountyManifest,
    ImpactCategory,
    KnownIssue,
    PocRequirement,
    ScopeStatus,
)
from app.discovery.bounty.vfcs import MinimizationResult, Vfcs
from app.discovery.orchestration.codec import digest
from app.discovery.orchestration.model import (
    CampaignIdentity,
    EvidenceItem,
    EvidenceQuality,
    ResearchState,
)
from app.parsing.solidity_research import SemanticCandidate

MAX_FINDINGS = 128
UNKNOWN = "unknown"
CONFIRMED_SEVERITY = "unconfirmed"

_RUNTIME_CATEGORIES = frozenset({"runtime", "differential", "economic"})


@dataclass(frozen=True)
class KnownIssueMatch:
    issue_id: str
    source: str
    basis: str


@dataclass(frozen=True)
class Qualification:
    """Why a candidate is or is not ready to be written up. Never a safety statement."""

    status: str  # report_candidate | needs_scope | needs_poc | known_issue | out_of_scope
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class ResearchFinding:
    finding_id: str
    title: str
    detector: str
    family: str
    contract: str
    function: str
    file: str
    line: int
    root_cause: str
    affected_asset: str
    impact_claim: str
    severity_candidate: str
    severity_rationale: str
    confirmed_severity: str
    scope_status: str
    scope_reason: str
    known_issue: KnownIssueMatch | None
    duplicate_of: str
    poc_status: str
    preconditions: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    evidence_quality: str
    open_contradictions: tuple[str, ...]
    sequence_ids: tuple[str, ...]
    minimization: tuple[str, ...]
    identity: tuple[tuple[str, str], ...]
    uncertainties: tuple[str, ...]
    qualification: Qualification
    verified: bool = False
    submitted: bool = False


def root_cause_key(candidate: SemanticCandidate) -> str:
    """Candidates that share a root cause share a key, whatever the entry point."""
    return f"{candidate.detector}:{candidate.contract}:{candidate.function.split('(')[0]}"


def build_findings(
    candidates: Iterable[SemanticCandidate],
    *,
    manifest: BountyManifest,
    identity: CampaignIdentity,
    state: ResearchState | None = None,
    sequences: Iterable[Vfcs] = (),
    minimized: Mapping[str, MinimizationResult] | None = None,
) -> tuple[ResearchFinding, ...]:
    sequences = tuple(sequences)
    minimized = minimized or {}
    seen_roots: dict[str, str] = {}
    findings: list[ResearchFinding] = []
    for candidate in sorted(
        candidates, key=lambda c: (c.file, c.line, c.contract, c.function, c.detector)
    ):
        if len(findings) >= MAX_FINDINGS:
            break
        finding = _one(candidate, manifest, identity, state, sequences, minimized, seen_roots)
        findings.append(finding)
    return tuple(findings)


def _one(
    candidate: SemanticCandidate,
    manifest: BountyManifest,
    identity: CampaignIdentity,
    state: ResearchState | None,
    sequences: tuple[Vfcs, ...],
    minimized: Mapping[str, MinimizationResult],
    seen_roots: dict[str, str],
) -> ResearchFinding:
    key = root_cause_key(candidate)
    finding_id = f"rf_{digest((identity.campaign_id, candidate.detector, candidate.contract, candidate.function, candidate.line))}"
    scope = manifest.scope_of(contract=candidate.contract, file=candidate.file)
    known = match_known_issue(manifest.known_issues, candidate)
    duplicate = seen_roots.get(key, "")
    seen_roots.setdefault(key, finding_id)
    related = _evidence_for(state, candidate)
    quality = _best_quality(related)
    poc = _poc_status(related)
    own = tuple(
        s
        for s in sequences
        if s.derived_from.startswith(candidate.detector + "@")
        and candidate.contract in s.derived_from
    )
    severity, rationale = severity_candidate(manifest.impact_categories, candidate)
    contradictions = _contradictions(state, candidate)
    qualification = qualify(manifest, scope.status, known, duplicate, poc, bool(own))
    uncertainties = _uncertainties(manifest, scope.status, candidate, poc, severity)
    return ResearchFinding(
        finding_id=finding_id,
        title=candidate.title,
        detector=candidate.detector,
        family=candidate.family,
        contract=candidate.contract,
        function=candidate.function,
        file=candidate.file,
        line=candidate.line,
        root_cause=candidate.summary,
        affected_asset=_asset(manifest, candidate),
        impact_claim=_impact(candidate),
        severity_candidate=severity,
        severity_rationale=rationale,
        confirmed_severity=CONFIRMED_SEVERITY,
        scope_status=scope.status.value,
        scope_reason=scope.reason,
        known_issue=known,
        duplicate_of=duplicate,
        poc_status=poc,
        preconditions=candidate.missing,
        evidence_ids=tuple(sorted(item.evidence_id for item in related)),
        evidence_quality=quality,
        open_contradictions=contradictions,
        sequence_ids=tuple(s.sequence_id for s in own),
        minimization=tuple(
            f"{s.sequence_id}:{_describe(minimized[s.sequence_id])}"
            for s in own
            if s.sequence_id in minimized
        ),
        identity=(
            ("campaign_id", identity.campaign_id),
            ("source_snapshot", identity.source_snapshot or UNKNOWN),
            ("compiler_configuration", identity.compiler_configuration or UNKNOWN),
            ("fork_reference", identity.fork_reference or UNKNOWN),
            ("program_context", identity.program_context or UNKNOWN),
        ),
        uncertainties=uncertainties,
        qualification=qualification,
    )


def match_known_issue(
    issues: Iterable[KnownIssue], candidate: SemanticCandidate
) -> KnownIssueMatch | None:
    """An issue matches only on the dimensions it declares, and all of them must agree."""
    name = candidate.function.split("(")[0]
    for issue in issues:
        checks: list[tuple[str, bool]] = []
        if issue.contracts:
            checks.append(("contract", candidate.contract in issue.contracts))
        if issue.functions:
            checks.append(
                ("function", name in issue.functions or candidate.function in issue.functions)
            )
        if issue.detectors:
            checks.append(("detector", candidate.detector in issue.detectors))
        if issue.root_cause_key:
            checks.append(("root_cause", issue.root_cause_key == root_cause_key(candidate)))
        if checks and all(ok for _label, ok in checks):
            return KnownIssueMatch(
                issue.issue_id, issue.source, "+".join(label for label, _ in checks)
            )
    return None


def severity_candidate(
    categories: tuple[ImpactCategory, ...], candidate: SemanticCandidate
) -> tuple[str, str]:
    """Severity comes from the program's categories. Without one it stays unknown."""
    if not categories:
        return UNKNOWN, "the program supplied no impact categories, so no severity is proposed"
    matched = [item for item in categories if set(item.tags) & set(candidate.impact_tags)]
    if not matched:
        return UNKNOWN, "no program impact category matches this candidate's impact tags"
    best = sorted(matched, key=lambda item: (-item.weight, item.name))[0]
    return best.severity, (
        f"program category {best.name} lists {best.severity}; this is an upper bound "
        "if the impact is demonstrated and not a confirmed severity"
    )


def qualify(
    manifest: BountyManifest,
    scope: ScopeStatus,
    known: KnownIssueMatch | None,
    duplicate: str,
    poc: str,
    has_sequence: bool,
) -> Qualification:
    reasons: list[str] = []
    if scope is ScopeStatus.OUT_OF_SCOPE:
        return Qualification(
            "out_of_scope", ("the program excludes this asset; not a safety claim",)
        )
    if known is not None:
        return Qualification(
            "known_issue",
            (f"matches known issue {known.issue_id} ({known.source}); not a safety claim",),
        )
    if scope is ScopeStatus.UNKNOWN:
        return Qualification("needs_scope", ("scope for this asset is not established",))
    if duplicate:
        reasons.append(f"shares a root cause with {duplicate}; possible duplicate, not safe")
    if manifest.poc_requirement is PocRequirement.REQUIRED and poc == "none":
        reasons.append("the program requires a proof of concept and none exists")
        return Qualification("needs_poc", tuple(reasons))
    if manifest.poc_requirement is PocRequirement.UNKNOWN:
        reasons.append("the program's proof-of-concept requirement is unknown")
    if not has_sequence:
        reasons.append("no call sequence has been derived for this candidate")
    return Qualification("report_candidate", tuple(reasons))


def _evidence_for(state: ResearchState | None, candidate: SemanticCandidate) -> list[EvidenceItem]:
    if state is None:
        return []
    identity = f"{candidate.contract}.{candidate.function}"
    return [
        item
        for item in state.evidence
        if item.attrs.get("identity") != "mismatch"
        and (
            item.attrs.get("detector") == candidate.detector
            and item.identity_key == identity
            or (item.identity_key == identity and item.attrs.get("category") in _RUNTIME_CATEGORIES)
        )
    ]


def _best_quality(items: list[EvidenceItem]) -> str:
    order = [
        EvidenceQuality.CORROBORATED,
        EvidenceQuality.CANDIDATE,
        EvidenceQuality.OBSERVATION,
        EvidenceQuality.INCOMPLETE,
        EvidenceQuality.UNKNOWN,
    ]
    present = {item.quality for item in items}
    for quality in order:
        if quality in present:
            return quality.value
    return "static_candidate" if not items else UNKNOWN


def _poc_status(related: list[EvidenceItem]) -> str:
    runtime = [
        item
        for item in related
        if item.attrs.get("category") in _RUNTIME_CATEGORIES and item.polarity == "positive"
    ]
    if runtime:
        return "runtime_observation_unverified"
    return "none"


def _contradictions(state: ResearchState | None, candidate: SemanticCandidate) -> tuple[str, ...]:
    if state is None:
        return ()
    identity = f"{candidate.contract}.{candidate.function}"
    return tuple(
        sorted(
            item.contradiction_id
            for item in state.contradictions
            if item.status == "open" and item.identity_key == identity
        )
    )


def _asset(manifest: BountyManifest, candidate: SemanticCandidate) -> str:
    for deployment in manifest.deployments:
        if deployment.contract_name == candidate.contract:
            return f"{candidate.contract} at {deployment.chain_id}:{deployment.address}"
    return f"{candidate.contract} (deployment unknown)"


def _impact(candidate: SemanticCandidate) -> str:
    tags = ", ".join(candidate.impact_tags[:4]) or "unspecified"
    return f"potential effect on: {tags}; unproven until demonstrated"


def _uncertainties(
    manifest: BountyManifest,
    scope: ScopeStatus,
    candidate: SemanticCandidate,
    poc: str,
    severity: str,
) -> tuple[str, ...]:
    found = [f"missing: {item}" for item in candidate.missing[:3]]
    if scope is ScopeStatus.UNKNOWN:
        found.append("scope is not established")
    if poc == "none":
        found.append("no runtime evidence exists for this candidate")
    if severity == UNKNOWN:
        found.append("severity cannot be derived from the program policy")
    found.extend(f"manifest gap: {gap}" for gap in manifest.gaps()[:4])
    return tuple(found)


def _describe(result: MinimizationResult) -> str:
    return (
        f"{len(result.original)}->{len(result.minimized)} calls, completed={result.completed}, "
        f"reason={result.reason}"
    )
