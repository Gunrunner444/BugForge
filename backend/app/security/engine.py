"""Language-neutral security analysis engine.

Parses files through the syntax registry, runs security rules, and emits
potential findings. Never labels a result as verified.
"""

from __future__ import annotations

import inspect
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from app.adapters.languages.base import LanguageAdapter
from app.analyzers.framework_detector import FrameworkDetector, FrameworkInfo
from app.core.config import settings
from app.core.paths import to_relative_path
from app.domain.findings import SecurityFinding
from app.domain.language import LanguageCapability
from app.parsing.model import SyntaxGraph
from app.parsing.solidity_compiler import (
    reset_compiler_cache,
    reset_compiler_type_hints,
    set_compiler_cache,
    set_compiler_type_hints,
)
from app.parsing.solidity_cross import reset_project_context, set_project_context
from app.parsing.solidity_defi import reset_defi_context, set_defi_context
from app.parsing.solidity_modifiers import (
    ModifierIndex,
    reset_modifier_index,
    set_modifier_index,
)
from app.parsing.solidity_project import (
    build_compiler_project,
    current_compiler_project,
    project_semantics,
    reset_compiler_project,
    reset_compiler_project_cache,
    set_compiler_project,
    set_compiler_project_cache,
    slice_semantics,
)
from app.parsing.solidity_proxy import reset_proxy_context, set_proxy_context
from app.parsing.solidity_storage import reset_storage_context, set_storage_context
from app.security.correlation import ObservationCluster
from app.security.finding_intelligence import semantic_clusters
from app.security.findings import findings_from_clusters
from app.security.rules.base import SecurityObservation, SecurityRule
from app.security.rules.catalog import builtin_security_rules

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AnalysisDiagnostic:
    kind: str
    message: str
    file_path: str
    language: str = ""
    parser_backend: str = ""
    parser_tier: str = ""
    rule_id: str = ""


@dataclass
class SecurityScanResult:
    observations: list[SecurityObservation] = field(default_factory=list)
    clusters: list[ObservationCluster] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)
    frameworks: list[FrameworkInfo] = field(default_factory=list)
    graphs: dict[str, SyntaxGraph] = field(default_factory=dict)
    languages: list[str] = field(default_factory=list)
    files_analyzed: int = 0
    diagnostics: list[AnalysisDiagnostic] = field(default_factory=list)
    # COMPLETED, PARTIAL, or TIMED_OUT. A timeout is not a clean scan.
    status: str = "COMPLETED"
    timings_ms: dict[str, int] = field(default_factory=dict)
    target_files: int = 0
    dependency_files: int = 0
    limitations: tuple[str, ...] = ()


DEFAULT_STATIC_DEADLINE_S = 180.0


@dataclass
class _ScanBudget:
    deadline_s: float
    started: float
    cancel: Callable[[], bool] | None = None
    status: str = "COMPLETED"
    limitations: list[str] = field(default_factory=list)

    def stop_reason(self) -> str:
        if self.cancel is not None and self.cancel():
            return "cancelled"
        if self.deadline_s >= 0 and (time.perf_counter() - self.started) > self.deadline_s:
            return "deadline"
        return ""

    def stop(self, reason: str, detail: str) -> None:
        if self.status == "COMPLETED":
            self.status = "TIMED_OUT" if reason == "deadline" else "PARTIAL"
        self.limitations.append(detail)


class SecurityAnalysisEngine:
    """Run registered security rules over parsed syntax graphs."""

    def __init__(self, rules: list[SecurityRule] | None = None) -> None:
        self._rules = list(rules) if rules is not None else builtin_security_rules()
        self._frameworks = FrameworkDetector()

    def analyze_repository(
        self,
        repo_path: Path,
        file_paths: list[Path],
        *,
        target_files: set[str] | None = None,
        deadline_s: float = DEFAULT_STATIC_DEADLINE_S,
        cancel: Callable[[], bool] | None = None,
    ) -> SecurityScanResult:
        from app.plugins import get_plugin_catalog

        started = time.perf_counter()
        budget = _ScanBudget(deadline_s=deadline_s, started=started, cancel=cancel)
        languages = get_plugin_catalog().languages
        frameworks = self._frameworks.detect(repo_path, file_paths)
        graphs: dict[str, SyntaxGraph] = {}
        used_languages: set[str] = set()
        analyzed = 0
        diagnostics: list[AnalysisDiagnostic] = []
        parse_started = time.perf_counter()
        ordered = sorted(file_paths, key=lambda path: path.as_posix())
        if target_files is not None:
            ordered.sort(
                key=lambda path: (
                    0 if _relative(repo_path, path) in target_files else 1,
                    path.as_posix(),
                )
            )

        for file_path in ordered:
            reason = budget.stop_reason()
            if reason:
                budget.stop(reason, f"parsing stopped ({reason}) after {analyzed} files")
                break
            adapter = languages.for_path(file_path)
            if adapter is None or not adapter.supports(LanguageCapability.SECURITY_ANALYSIS):
                continue
            graph, parse_diag = self._parse(adapter, file_path)
            if parse_diag is not None:
                diagnostics.append(parse_diag)
            if graph is None:
                continue
            try:
                graph.file_path = to_relative_path(Path(graph.file_path), repo_path)
            except ValueError:
                graph.file_path = str(file_path)
            analyzed += 1
            used_languages.add(adapter.language_id)
            graphs[graph.file_path] = graph
            if graph.diagnostics.truncated or graph.diagnostics.has_errors:
                diagnostics.append(
                    AnalysisDiagnostic(
                        kind="partial_analysis" if graph.diagnostics.truncated else "parser_error",
                        message=graph.diagnostics.message or "parse reported errors",
                        file_path=graph.file_path,
                        language=graph.language,
                        parser_backend=graph.parser_backend,
                        parser_tier=str(graph.parser_tier),
                    )
                )
        parse_ms = int((time.perf_counter() - parse_started) * 1000)
        result = self._rules_over_graphs(
            repo_path,
            graphs,
            diagnostics,
            frameworks,
            used_languages,
            analyzed,
            budget=budget,
            target_files=target_files,
        )
        result.timings_ms["parse"] = parse_ms
        result.timings_ms["total"] = int((time.perf_counter() - started) * 1000)
        if target_files is None:
            result.target_files = len(graphs)
            result.dependency_files = 0
        else:
            result.target_files = sum(1 for path in graphs if path in target_files)
            result.dependency_files = sum(1 for path in graphs if path not in target_files)
        return result

    def _rules_over_graphs(
        self,
        repo_path: Path,
        graphs: dict[str, SyntaxGraph],
        diagnostics: list[AnalysisDiagnostic],
        frameworks: list[FrameworkInfo],
        used_languages: set[str],
        analyzed: int,
        *,
        budget: _ScanBudget | None = None,
        target_files: set[str] | None = None,
    ) -> SecurityScanResult:
        if budget is None:
            budget = _ScanBudget(deadline_s=DEFAULT_STATIC_DEADLINE_S, started=time.perf_counter())
        token = set_modifier_index(ModifierIndex.from_graphs(graphs))
        defi_tokens = set_defi_context(graphs)
        storage_token = set_storage_context(graphs)
        proxy_token = set_proxy_context()
        project_token = set_project_context(graphs)
        compiler_token = set_compiler_cache()
        type_token = set_compiler_type_hints()
        project_cache_token = set_compiler_project_cache()
        compiler_project_token = set_compiler_project(None)
        try:
            project = build_compiler_project(repo_path, graphs)
            set_compiler_project(project)
            _overlay_compiler_layouts(graphs)
            return self._rules_over_indexed_graphs(
                repo_path,
                graphs,
                diagnostics,
                frameworks,
                used_languages,
                analyzed,
                budget=budget,
                target_files=target_files,
            )
        finally:
            reset_compiler_project(compiler_project_token)
            reset_compiler_project_cache(project_cache_token)
            reset_compiler_type_hints(type_token)
            reset_compiler_cache(compiler_token)
            reset_project_context(project_token)
            reset_proxy_context(proxy_token)
            reset_storage_context(storage_token)
            reset_defi_context(defi_tokens)
            reset_modifier_index(token)

    def _rules_over_indexed_graphs(
        self,
        repo_path: Path,
        graphs: dict[str, SyntaxGraph],
        diagnostics: list[AnalysisDiagnostic],
        frameworks: list[FrameworkInfo],
        used_languages: set[str],
        analyzed: int,
        *,
        budget: _ScanBudget | None = None,
        target_files: set[str] | None = None,
    ) -> SecurityScanResult:
        if budget is None:
            budget = _ScanBudget(deadline_s=DEFAULT_STATIC_DEADLINE_S, started=time.perf_counter())
        observations: list[SecurityObservation] = []
        rules_started = time.perf_counter()
        rule_paths = [
            path for path in sorted(graphs) if target_files is None or path in target_files
        ]
        for graph_path in rule_paths:
            graph = graphs[graph_path]
            for rule in self._rules:
                reason = budget.stop_reason()
                if reason:
                    budget.stop(
                        reason,
                        f"rule stage stopped ({reason}) at {graph_path} before {rule.rule_id}",
                    )
                    break
                try:
                    observations.extend(rule.check(graph, frameworks=frameworks))
                except Exception as exc:
                    logger.warning(
                        "Security rule %s failed on %s: %s", rule.rule_id, graph_path, exc
                    )
                    diagnostics.append(
                        AnalysisDiagnostic(
                            kind="analyzer_error",
                            message=f"{rule.rule_id}: {exc}",
                            file_path=graph.file_path,
                            language=graph.language,
                            parser_backend=graph.parser_backend,
                            parser_tier=str(graph.parser_tier),
                            rule_id=rule.rule_id,
                        )
                    )
            if budget.status != "COMPLETED":
                break

        clusters = semantic_clusters(observations)
        findings = findings_from_clusters(clusters)
        from app.security.cross_file import build_project

        project = None
        if budget.status == "COMPLETED":
            project = build_project(graphs, repo_root=repo_path)
        else:
            budget.limitations.append("cross-file stage was not run after the scan stopped")
        if project is not None:
            for item in project.diagnostics:
                diagnostics.append(
                    AnalysisDiagnostic(
                        kind=item.kind,
                        message=item.message,
                        file_path=item.file_path,
                    )
                )
        if project is not None and (project.incomplete or project.externals):
            # Re-run taint rules with project context. Other rules already ran
            # per file and do not depend on cross-file summaries.
            observations = [
                obs for obs in observations if not str(obs.rule_id).startswith("sec.taint.")
            ]
            stopped = False
            for graph_path in rule_paths:
                if stopped:
                    break
                graph = graphs[graph_path]
                for rule in self._rules:
                    if not str(rule.rule_id).startswith("sec.taint."):
                        continue
                    reason = budget.stop_reason()
                    if reason:
                        budget.stop(reason, f"taint stage stopped ({reason}) at {graph_path}")
                        stopped = True
                        break
                    try:
                        check = cast(Any, rule.check)
                        observations.extend(
                            check(graph, frameworks=frameworks, project=project)
                            if _accepts_project(rule)
                            else rule.check(graph, frameworks=frameworks)
                        )
                    except Exception as exc:
                        logger.warning(
                            "Security rule %s failed on %s: %s",
                            rule.rule_id,
                            graph_path,
                            exc,
                        )
                        diagnostics.append(
                            AnalysisDiagnostic(
                                kind="analyzer_error",
                                message=f"{rule.rule_id}: {exc}",
                                file_path=graph.file_path,
                                language=graph.language,
                                parser_backend=graph.parser_backend,
                                parser_tier=str(graph.parser_tier),
                                rule_id=rule.rule_id,
                            )
                        )
            clusters = semantic_clusters(observations)
            findings = findings_from_clusters(clusters)
        if target_files is not None:
            observations = [obs for obs in observations if obs.file_path in target_files]
            clusters = semantic_clusters(observations)
            findings = findings_from_clusters(clusters)
        return SecurityScanResult(
            observations=observations,
            clusters=clusters,
            findings=findings,
            frameworks=frameworks,
            graphs=graphs,
            languages=sorted(used_languages),
            files_analyzed=analyzed,
            diagnostics=sorted(
                diagnostics,
                key=lambda item: (item.file_path, item.kind, item.rule_id, item.message),
            ),
            status=budget.status,
            timings_ms={"rules": int((time.perf_counter() - rules_started) * 1000)},
            limitations=tuple(budget.limitations),
        )

    def _parse(
        self, adapter: LanguageAdapter, file_path: Path
    ) -> tuple[SyntaxGraph | None, AnalysisDiagnostic | None]:
        try:
            size = file_path.stat().st_size
        except OSError as exc:
            return None, AnalysisDiagnostic(
                kind="parser_error",
                message=str(exc),
                file_path=str(file_path),
                language=adapter.language_id,
            )
        if size > settings.max_file_size_bytes:
            return None, AnalysisDiagnostic(
                kind="parser_error",
                message="file exceeds max_file_size_bytes",
                file_path=str(file_path),
                language=adapter.language_id,
            )
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return None, AnalysisDiagnostic(
                kind="parser_error",
                message=str(exc),
                file_path=str(file_path),
                language=adapter.language_id,
            )
        try:
            graph = adapter.syntax_graph(file_path, source)
        except Exception as exc:
            logger.debug("Security parse failed for %s: %s", file_path, exc)
            return None, AnalysisDiagnostic(
                kind="parser_failure",
                message=str(exc),
                file_path=str(file_path),
                language=adapter.language_id,
                parser_backend=adapter.parser_backend(),
                parser_tier=str(adapter.parser_tier()),
            )
        if not isinstance(graph, SyntaxGraph):
            return None, AnalysisDiagnostic(
                kind="parser_failure",
                message="adapter did not return a SyntaxGraph",
                file_path=str(file_path),
                language=adapter.language_id,
            )
        return graph, None


def _overlay_compiler_layouts(graphs: dict[str, SyntaxGraph]) -> None:
    """Apply the scan project compiler model. A missing source is not compiled.

    The public graph path stays repository-relative. Source bytes come from
    the project bundle, which resolved those paths against the repository
    root. An unavailable or incomplete compiler does not invent slots, and a
    compiler slot never replaces the parser slot.
    """
    from app.parsing.solidity_compiler import reconcile_selectors, record_compiler_type_hints
    from app.parsing.solidity_storage import analyze_storage, apply_compiler_layout

    project = current_compiler_project()
    if project is None:
        return
    semantics = project_semantics(project)
    if semantics.status == "AVAILABLE":
        record_compiler_type_hints(semantics)
    for graph in graphs.values():
        if graph.language != "solidity" or graph.parser_tier.value == "profile_fallback":
            continue
        compiler = slice_semantics(semantics, graph.file_path)
        model = apply_compiler_layout(
            analyze_storage(graph),
            compiler,
            source_path=graph.file_path,
        )
        if compiler.status == "AVAILABLE":
            model.semantic_disagreements.extend(
                reconcile_selectors(_parser_selectors(graph), compiler.selectors)
            )


def _relative(repo_path: Path, file_path: Path) -> str:
    try:
        return file_path.resolve().relative_to(repo_path.resolve()).as_posix()
    except ValueError:
        return file_path.as_posix()


def _parser_selectors(graph: SyntaxGraph) -> list[dict[str, str]]:
    from app.parsing.solidity_links import overload_selectors

    return overload_selectors(graph)


def _accepts_project(rule: object) -> bool:
    try:
        return "project" in inspect.signature(getattr(rule, "check")).parameters
    except (TypeError, ValueError):
        return False
