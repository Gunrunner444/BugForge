"""Correlate static findings with tests, reproductions, and hypotheses.

This uses the existing finding and evidence types. It does not create a
second evidence store and it never marks a finding verified. A test result
is attached evidence, not a bypass of ``SecurityFinding.verify``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace

from app.domain.evidence import Evidence, EvidenceKind, EvidenceProvenance
from app.domain.findings import SecurityFinding

_RUNTIME_KINDS = frozenset(
    {
        EvidenceKind.TEST_FAILURE,
        EvidenceKind.REPRODUCTION,
        EvidenceKind.API_TEST,
        EvidenceKind.REPLAY,
        EvidenceKind.HTTP_RESPONSE,
        EvidenceKind.LOG,
    }
)


@dataclass(frozen=True)
class ConfidenceExplanation:
    """Why a finding looks the way it does. Not a verification decision."""

    summary: str
    detected_because: str
    source: str
    sink: str
    relationships: tuple[str, ...]
    parser: str
    cross_file: bool
    field_path: str
    analysis_incomplete: str
    runtime_support: str
    evidence_kinds: tuple[str, ...]
    static_status: str


def explain_confidence(finding: SecurityFinding) -> ConfidenceExplanation:
    """Read provenance already stored on the finding. Do not invent steps."""
    static = [
        item
        for item in finding.evidence.items
        if item.provenance is EvidenceProvenance.STATIC_ANALYSIS
        or item.kind is EvidenceKind.STATIC_ANALYSIS
    ]
    meta = static[0].metadata if static else {}
    source = str(meta.get("taint_source") or meta.get("taint") or "")
    sink = str(meta.get("sink") or "")
    field_path = str(meta.get("field_path") or "")
    parser = str(meta.get("parser_backend") or meta.get("parser_tier") or "")
    incomplete = str(meta.get("analysis_incomplete") or "")
    relationships: list[str] = []
    for key in ("relationship", "re_export", "class_method", "route", "route_method"):
        value = meta.get(key)
        if value and value not in {"false", ""}:
            relationships.append(f"{key}:{value}")
    if field_path:
        relationships.append(f"field:{field_path}")
    cross_file = str(meta.get("taint_scope") or "") == "cross_file" or "cross_file:" in str(
        meta.get("taint") or ""
    )
    kinds = tuple(sorted({item.kind.value for item in finding.evidence.items}))
    runtime = _runtime_label(finding)
    because = _because(source, sink, relationships, parser, cross_file, field_path, runtime)
    return ConfidenceExplanation(
        summary=because,
        detected_because=because,
        source=source,
        sink=sink,
        relationships=tuple(relationships),
        parser=parser,
        cross_file=cross_file,
        field_path=field_path,
        analysis_incomplete=incomplete,
        runtime_support=runtime,
        evidence_kinds=kinds,
        static_status=finding.status.value,
    )


def correlate_finding(
    finding: SecurityFinding,
    evidence: Sequence[Evidence],
) -> SecurityFinding:
    """Attach same-issue evidence. Status is unchanged.

    Unrelated files, lines, or vulnerability classes are left off. Duplicate
    items are not repeated. A contradiction is kept beside the static result.
    """
    accepted: list[Evidence] = []
    seen = {_evidence_key(item) for item in finding.evidence.items}
    for item in sorted(evidence, key=_evidence_sort):
        if not _same_issue(finding, item):
            continue
        key = _evidence_key(item)
        if key in seen:
            continue
        seen.add(key)
        accepted.append(item)
    if not accepted:
        return finding
    merged = finding.evidence.extend(accepted)
    # Status is copied, not promoted. Verification stays on SecurityFinding.verify.
    return replace(finding, evidence=merged, status=finding.status)


def _same_issue(finding: SecurityFinding, evidence: Evidence) -> bool:
    loc = finding.source_location
    path = evidence.artifact_path or _meta_str(evidence, "file_path")
    if not path or loc is None or not loc.file_path:
        return False
    if not _same_path(loc.file_path, path):
        return False
    line = evidence.metadata.get("line")
    if line is not None and loc.line is not None and int(line) != loc.line:
        return False
    vuln = _meta_str(evidence, "vulnerability_class")
    if vuln and finding.vulnerability_class and vuln != finding.vulnerability_class:
        return False
    return True


def _same_path(left: str, right: str) -> bool:
    norm_left = left.replace("\\", "/").lstrip("./")
    norm_right = right.replace("\\", "/").lstrip("./")
    return (
        norm_left == norm_right
        or norm_left.endswith("/" + norm_right)
        or norm_right.endswith("/" + norm_left)
    )


def _evidence_key(item: Evidence) -> tuple[str, str, str, str, str, str]:
    return (
        item.kind.value,
        item.source,
        item.summary,
        item.artifact_path or "",
        _meta_str(item, "line"),
        _meta_str(item, "contradicts") or _meta_str(item, "reached"),
    )


def _evidence_sort(item: Evidence) -> tuple[str, str, str, str]:
    return (item.kind.value, item.source, item.summary, item.artifact_path or "")


def _meta_str(item: Evidence, key: str) -> str:
    value = item.metadata.get(key)
    return "" if value is None else str(value)


def _contradicts(item: Evidence) -> bool:
    flag = _meta_str(item, "contradicts").lower()
    reached = _meta_str(item, "reached").lower()
    return flag in {"1", "true", "yes"} or reached in {"0", "false", "no", "not_reached"}


def _runtime_label(finding: SecurityFinding) -> str:
    runtime = [item for item in finding.evidence.items if item.kind in _RUNTIME_KINDS]
    if any(_contradicts(item) for item in runtime):
        return "contradicts"
    if runtime:
        return "supports"
    if any(item.kind is EvidenceKind.AI_ANALYSIS for item in finding.evidence.items):
        return "ai_only"
    return "none"


def _because(
    source: str,
    sink: str,
    relationships: list[str],
    parser: str,
    cross_file: bool,
    field_path: str,
    runtime: str,
) -> str:
    parts = ["static analysis"]
    if source:
        parts.append(f"source {source}")
    if sink:
        parts.append(f"sink {sink}")
    if field_path:
        parts.append(f"field {field_path}")
    if cross_file:
        parts.append("cross-file flow")
    if relationships:
        parts.append("relationships " + ", ".join(relationships))
    if parser:
        parts.append(f"parser {parser}")
    if runtime == "supports":
        parts.append("a test or reproduction names the same location")
    elif runtime == "contradicts":
        parts.append("a test says this path was not reached; the static result is kept")
    elif runtime == "ai_only":
        parts.append("AI text is attached and is not verification")
    else:
        parts.append("no independent runtime evidence")
    return "; ".join(parts)
