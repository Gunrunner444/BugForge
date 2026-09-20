"""Language adapter contract.

Core analysis looks up a :class:`LanguageAdapter` from the language registry
instead of branching on language names.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path

from app.analysis.finding import Finding
from app.analyzers.python.parser import ParseResult
from app.domain.language import LanguageCapability
from app.plugins.errors import UnsupportedCapabilityError


class LanguageAdapter(ABC):
    """Language-specific parse and static-analysis operations.

    Adapters that only support detection must not implement fake parsers.
    Calling :meth:`parse_file` or :meth:`analyze_file` without the matching
    capability raises :class:`UnsupportedCapabilityError`.
    """

    @property
    @abstractmethod
    def language_id(self) -> str:
        """Stable lowercase id, e.g. ``python``."""

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name, e.g. ``Python``."""

    @property
    @abstractmethod
    def file_extensions(self) -> frozenset[str]:
        """Lowercase extensions including the leading dot."""

    @property
    @abstractmethod
    def capabilities(self) -> frozenset[LanguageCapability]:
        """Capabilities this adapter actually implements."""

    def supports(self, capability: LanguageCapability) -> bool:
        return capability in self.capabilities

    def matches_path(self, path: Path) -> bool:
        return path.suffix.lower() in self.file_extensions

    def prepare_repository(self, repo_root: Path) -> object | None:
        """Optional per-repository context (local packages, module roots, ...)."""
        return None

    def parse_file(self, file_path: Path, *, context: object | None = None) -> ParseResult:
        raise UnsupportedCapabilityError(
            self.language_id,
            LanguageCapability.PARSE,
            detail=f"{self.display_name} parsing is not implemented in this phase.",
        )

    def analyze_file(self, file_path: Path, source: str) -> list[Finding]:
        raise UnsupportedCapabilityError(
            self.language_id,
            LanguageCapability.STATIC_ANALYSIS,
            detail=f"{self.display_name} static analysis is not implemented in this phase.",
        )

    def static_rules(self) -> Sequence[object]:
        return ()
