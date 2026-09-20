"""Profile-driven language adapters sharing the SyntaxGraph substrate.

These adapters implement parse, entity/import extraction, and security
analysis. Optional quality rules opt a language into STATIC_ANALYSIS.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path

from app.adapters.languages.base import LanguageAdapter
from app.analysis.base import AnalyzerRule
from app.analysis.finding import Finding
from app.domain.language import LanguageCapability
from app.domain.source import LanguageParseResult
from app.parsing.engine import parse_source
from app.parsing.model import SyntaxGraph

logger = logging.getLogger(__name__)

_ANALYSIS_CAPS = frozenset(
    {
        LanguageCapability.DETECTION,
        LanguageCapability.SOURCE,
        LanguageCapability.PARSE,
        LanguageCapability.ENTITY_EXTRACTION,
        LanguageCapability.IMPORT_EXTRACTION,
        LanguageCapability.SECURITY_ANALYSIS,
    }
)


class ProfileLanguageAdapter(LanguageAdapter):
    """Language adapter backed by a registered syntax-graph parser."""

    def __init__(
        self,
        language_id: str,
        display_name: str,
        extensions: frozenset[str],
        *,
        is_source: bool = True,
        rules: Sequence[AnalyzerRule] | None = None,
    ) -> None:
        self._language_id = language_id
        self._display_name = display_name
        self._extensions = extensions
        self._rules: list[AnalyzerRule] = list(rules or ())
        caps = set(_ANALYSIS_CAPS)
        if not is_source:
            caps.discard(LanguageCapability.SOURCE)
        if self._rules:
            caps.add(LanguageCapability.STATIC_ANALYSIS)
        self._capabilities = frozenset(caps)

    @property
    def language_id(self) -> str:
        return self._language_id

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def file_extensions(self) -> frozenset[str]:
        return self._extensions

    @property
    def capabilities(self) -> frozenset[LanguageCapability]:
        return self._capabilities

    def parse_file(self, file_path: Path, *, context: object | None = None) -> LanguageParseResult:
        del context
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return LanguageParseResult(
                file_path=str(file_path),
                language=self.language_id,
                errors=[str(exc)],
            )
        return self.syntax_graph(file_path, source).to_parse_result()

    def syntax_graph(self, file_path: Path, source: str) -> SyntaxGraph:
        return parse_source(self.language_id, file_path, source)

    def analyze_file(self, file_path: Path, source: str) -> list[Finding]:
        if not self._rules:
            return super().analyze_file(file_path, source)
        findings: list[Finding] = []
        for rule in self._rules:
            try:
                findings.extend(rule.check_file(file_path, source))
            except Exception as exc:
                logger.warning("Rule %s failed on %s: %s", rule.RULE_ID, file_path, exc)
        return findings

    def static_rules(self) -> Sequence[AnalyzerRule]:
        return tuple(self._rules)

    def with_static_rules(self, rules: Sequence[object]) -> ProfileLanguageAdapter:
        typed: list[AnalyzerRule] = []
        for rule in rules:
            if not isinstance(rule, AnalyzerRule):
                raise TypeError(
                    "Static-analysis rule overrides must be AnalyzerRule "
                    f"instances, got {type(rule)!r}"
                )
            typed.append(rule)
        return ProfileLanguageAdapter(
            self._language_id,
            self._display_name,
            self._extensions,
            is_source=LanguageCapability.SOURCE in self._capabilities,
            rules=typed,
        )
