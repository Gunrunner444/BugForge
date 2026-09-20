"""Profile-driven language adapters sharing the SyntaxGraph substrate.

These adapters implement parse, entity/import extraction, and security
analysis. They do not claim Python-style quality static analysis.
"""

from __future__ import annotations

from pathlib import Path

from app.adapters.languages.base import LanguageAdapter
from app.domain.language import LanguageCapability
from app.domain.source import LanguageParseResult
from app.parsing.engine import parse_source
from app.parsing.model import SyntaxGraph

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
    ) -> None:
        self._language_id = language_id
        self._display_name = display_name
        self._extensions = extensions
        caps = set(_ANALYSIS_CAPS)
        if not is_source:
            caps.discard(LanguageCapability.SOURCE)
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
