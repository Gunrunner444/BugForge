"""Language-neutral security analysis engine.

Parses files through the syntax registry, runs security rules, and emits
potential findings. Never labels a result as verified.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from app.analyzers.framework_detector import FrameworkDetector, FrameworkInfo
from app.core.config import settings
from app.core.paths import to_relative_path
from app.domain.findings import SecurityFinding
from app.domain.language import LanguageCapability
from app.parsing.model import SyntaxGraph
from app.security.correlation import ObservationCluster, correlate_observations
from app.security.findings import findings_from_clusters
from app.security.rules.base import SecurityObservation, SecurityRule
from app.security.rules.catalog import builtin_security_rules

logger = logging.getLogger(__name__)


@dataclass
class SecurityScanResult:
    observations: list[SecurityObservation] = field(default_factory=list)
    clusters: list[ObservationCluster] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)
    frameworks: list[FrameworkInfo] = field(default_factory=list)
    graphs: dict[str, SyntaxGraph] = field(default_factory=dict)
    languages: list[str] = field(default_factory=list)
    files_analyzed: int = 0


class SecurityAnalysisEngine:
    """Run registered security rules over parsed syntax graphs."""

    def __init__(self, rules: list[SecurityRule] | None = None) -> None:
        self._rules = list(rules) if rules is not None else builtin_security_rules()
        self._frameworks = FrameworkDetector()

    def analyze_repository(self, repo_path: Path, file_paths: list[Path]) -> SecurityScanResult:
        from app.plugins import get_plugin_catalog

        languages = get_plugin_catalog().languages
        frameworks = self._frameworks.detect(repo_path, file_paths)
        observations: list[SecurityObservation] = []
        graphs: dict[str, SyntaxGraph] = {}
        used_languages: set[str] = set()
        analyzed = 0

        for file_path in file_paths:
            adapter = languages.for_path(file_path)
            if adapter is None or not adapter.supports(LanguageCapability.SECURITY_ANALYSIS):
                continue
            graph = self._parse(adapter, file_path)
            if graph is None:
                continue
            try:
                graph.file_path = to_relative_path(Path(graph.file_path), repo_path)
            except ValueError:
                graph.file_path = str(file_path)
            analyzed += 1
            used_languages.add(adapter.language_id)
            graphs[graph.file_path] = graph
            for rule in self._rules:
                try:
                    observations.extend(rule.check(graph, frameworks=frameworks))
                except Exception as exc:
                    logger.warning(
                        "Security rule %s failed on %s: %s", rule.rule_id, file_path, exc
                    )

        clusters = correlate_observations(observations)
        findings = findings_from_clusters(clusters)
        return SecurityScanResult(
            observations=observations,
            clusters=clusters,
            findings=findings,
            frameworks=frameworks,
            graphs=graphs,
            languages=sorted(used_languages),
            files_analyzed=analyzed,
        )

    def _parse(self, adapter: object, file_path: Path) -> SyntaxGraph | None:
        try:
            size = file_path.stat().st_size
        except OSError:
            return None
        if size > settings.max_file_size_bytes:
            return None
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        try:
            graph = adapter.syntax_graph(file_path, source)  # type: ignore[attr-defined]
        except Exception as exc:
            logger.debug("Security parse failed for %s: %s", file_path, exc)
            return None
        if not isinstance(graph, SyntaxGraph):
            return None
        return graph
