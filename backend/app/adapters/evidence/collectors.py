"""Collectors that wrap BugForge's existing static-analysis and test evidence."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.adapters.evidence.base import EvidenceCollector
from app.domain.evidence import Evidence, EvidenceKind, EvidenceSource


class StaticAnalysisEvidenceCollector(EvidenceCollector):
    @property
    def collector_id(self) -> str:
        return "static_analysis"

    @property
    def kinds(self) -> frozenset[EvidenceKind]:
        return frozenset({EvidenceKind.STATIC_ANALYSIS})

    def collect(self, source: EvidenceSource) -> Sequence[Evidence]:
        items: list[Evidence] = []
        for finding in source.static_findings:
            items.append(_from_static_finding(finding))
        return items


class TestFailureEvidenceCollector(EvidenceCollector):
    @property
    def collector_id(self) -> str:
        return "test_failure"

    @property
    def kinds(self) -> frozenset[EvidenceKind]:
        return frozenset({EvidenceKind.TEST_FAILURE})

    def collect(self, source: EvidenceSource) -> Sequence[Evidence]:
        items: list[Evidence] = []
        for failure in source.test_failures:
            node_id = str(getattr(failure, "node_id", "") or getattr(failure, "test_name", "test"))
            traceback = getattr(failure, "traceback", None)
            items.append(
                Evidence(
                    kind=EvidenceKind.TEST_FAILURE,
                    source="test_runner",
                    summary=f"Failing test {node_id}",
                    details=str(traceback or ""),
                    metadata={
                        "test_file": getattr(failure, "test_file", None),
                        "test_name": getattr(failure, "test_name", None),
                    },
                )
            )
        return items


class SourceCodeEvidenceCollector(EvidenceCollector):
    @property
    def collector_id(self) -> str:
        return "source_code"

    @property
    def kinds(self) -> frozenset[EvidenceKind]:
        return frozenset({EvidenceKind.SOURCE_CODE})

    def collect(self, source: EvidenceSource) -> Sequence[Evidence]:
        items: list[Evidence] = []
        for file_evidence in source.source_files:
            path = str(getattr(file_evidence, "file_path", "") or "")
            content = str(getattr(file_evidence, "content", "") or "")
            language = str(getattr(file_evidence, "language", "") or "")
            items.append(
                Evidence(
                    kind=EvidenceKind.SOURCE_CODE,
                    source="repository",
                    summary=f"Source file {path}" if path else "Source file",
                    details=content[:4_000],
                    artifact_path=path or None,
                    metadata={"language": language} if language else {},
                )
            )
        return items


class ReproductionEvidenceCollector(EvidenceCollector):
    @property
    def collector_id(self) -> str:
        return "reproduction"

    @property
    def kinds(self) -> frozenset[EvidenceKind]:
        return frozenset({EvidenceKind.REPRODUCTION})

    def collect(self, source: EvidenceSource) -> Sequence[Evidence]:
        items: list[Evidence] = []
        for reproduction in source.reproductions:
            summary = str(
                getattr(reproduction, "summary", None)
                or getattr(reproduction, "classification", None)
                or "Reproduction attempt"
            )
            details = str(getattr(reproduction, "details", "") or "")
            items.append(
                Evidence(
                    kind=EvidenceKind.REPRODUCTION,
                    source="reproduction_engine",
                    summary=summary,
                    details=details,
                )
            )
        return items


def _from_static_finding(finding: Any) -> Evidence:
    category = str(getattr(finding, "category", "static"))
    file_path = str(getattr(finding, "file_path", ""))
    line = getattr(finding, "line", None)
    message = str(getattr(finding, "message", "") or category)
    location = f"{file_path}:{line}" if file_path and line is not None else file_path or category
    return Evidence(
        kind=EvidenceKind.STATIC_ANALYSIS,
        source=str(getattr(finding, "analyzer", "static_analysis")),
        summary=f"{category} at {location}: {message}",
        details=str(getattr(finding, "explanation", "") or getattr(finding, "evidence", "") or ""),
        artifact_path=file_path or None,
        metadata={
            "category": category,
            "severity": getattr(finding, "severity", None),
            "confidence": getattr(finding, "confidence", None),
            "line": line,
        },
    )
