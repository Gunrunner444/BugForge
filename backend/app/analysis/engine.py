"""Static analysis engine — orchestrates rules across files."""

from __future__ import annotations

import logging
from pathlib import Path

from app.analysis.base import AnalyzerRule
from app.analysis.finding import Finding
from app.analysis.python_analyzer import ALL_PYTHON_RULES
from app.core.config import settings
from app.core.paths import to_relative_path

logger = logging.getLogger(__name__)


class StaticAnalysisEngine:
    """Runs registered rules against every supported source file in a repository."""

    def __init__(self, rules: list[AnalyzerRule] | None = None) -> None:
        # Default to all built-in Python rules
        self._rules: list[AnalyzerRule] = rules if rules is not None else ALL_PYTHON_RULES

    def analyze_repository(self, repo_path: Path, file_paths: list[Path]) -> list[Finding]:
        """Run all rules over the supplied file paths. Returns findings with RELATIVE paths."""
        findings: list[Finding] = []
        python_files = [p for p in file_paths if p.suffix.lower() == ".py"]

        for file_path in python_files:
            for finding in self._analyze_file(file_path):
                # Convert to repo-relative path so stored findings are portable
                try:
                    finding.file_path = to_relative_path(Path(finding.file_path), repo_path)
                except ValueError:
                    pass
                findings.append(finding)

        logger.info(
            "Static analysis complete: %d findings across %d Python files",
            len(findings),
            len(python_files),
        )
        return findings

    def _analyze_file(self, file_path: Path) -> list[Finding]:
        try:
            size = file_path.stat().st_size
        except OSError:
            return []

        if size > settings.max_file_size_bytes:
            logger.debug("Skipping oversized file for static analysis: %s", file_path)
            return []

        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError) as exc:
            logger.warning("Cannot read %s for static analysis: %s", file_path, exc)
            return []

        findings: list[Finding] = []
        for rule in self._rules:
            try:
                findings.extend(rule.check_file(file_path, source))
            except Exception as exc:
                logger.warning("Rule %s failed on %s: %s", rule.RULE_ID, file_path, exc)

        return findings
