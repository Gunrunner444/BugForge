"""Turn static observations into potential (never verified) security findings."""

from __future__ import annotations

from app.domain.evidence import Evidence, EvidenceBundle
from app.domain.findings import SecurityFinding, SourceLocation
from app.domain.security import EvidenceTier
from app.security.correlation import ObservationCluster
from app.security.finding_intelligence import explain_cluster
from app.security.rules.base import SecurityObservation


def observation_ref(obs: SecurityObservation) -> str:
    return f"{obs.rule_id}:{obs.file_path}:{obs.line}"


def findings_from_clusters(clusters: list[ObservationCluster]) -> list[SecurityFinding]:
    return [finding_from_cluster(cluster) for cluster in clusters]


def finding_from_cluster(cluster: ObservationCluster) -> SecurityFinding:
    observations = cluster.observations
    evidence_items = [obs.to_evidence() for obs in observations]
    confidence = _cluster_confidence(observations)
    title = observations[0].title
    summary = "; ".join(obs.summary for obs in observations[:3])
    explained = explain_cluster(observations)
    finding = SecurityFinding.potential(
        title,
        hypothesis=summary,
        description=(
            "Static analysis produced a potential security issue. "
            "This is not a verified vulnerability."
        ),
        evidence=EvidenceBundle.from_items(evidence_items),
        vulnerability_class=cluster.vulnerability_class.value,
        source_location=SourceLocation(
            file_path=cluster.file_path,
            line=cluster.line,
            function=None,
        ),
        confidence=confidence,
        evidence_tier=(
            EvidenceTier.CORROBORATED if cluster.corroborated else EvidenceTier.STATIC_INDICATOR
        ),
        rule_ids=cluster.rule_ids,
        analyzer="security_rules",
        observation_refs=tuple(observation_ref(obs) for obs in observations),
        finding_key=explained.finding_key,
        flow_summary=explained.summary,
        flow_source=explained.source,
        flow_sink=explained.sink,
        field_path=explained.field_path,
        files_crossed=explained.files_crossed,
        analysis_incomplete=explained.analysis_incomplete,
        parser_completeness=explained.parser_completeness,
        evidence_summary=explained.evidence_summary,
        related_group=explained.related_group,
        report_title=title,
        report_description=summary,
        asset=cluster.file_path,
    )
    if cluster.corroborated:
        finding = finding.corroborate()
    return finding


def attach_ai_hypothesis(
    finding: SecurityFinding,
    *,
    hypothesis: str,
    analysis: str,
    impact: str | None = None,
) -> SecurityFinding:
    """Attach AI text without promoting status to verified."""
    from dataclasses import replace

    extra = Evidence.from_ai(hypothesis, details=analysis, source="security_agent")
    merged = finding.evidence.extend([extra])
    return replace(
        finding,
        status=finding.status,
        hypothesis=hypothesis,
        ai_analysis=analysis,
        impact=impact or finding.impact,
        evidence=merged,
        report_description=analysis or finding.report_description,
    )


def _cluster_confidence(observations: tuple[SecurityObservation, ...]) -> str:
    ranks = {"low": 0, "medium": 1, "high": 2}
    best = max((ranks.get(obs.confidence, 0) for obs in observations), default=0)
    if len({obs.rule_id for obs in observations}) >= 2 and best < 2:
        best = min(best + 1, 2)
    return {0: "low", 1: "medium", 2: "high"}[best]
