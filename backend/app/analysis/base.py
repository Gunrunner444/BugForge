"""Base rule interface for all static-analysis rules."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from app.analysis.finding import Finding


class AnalyzerRule(ABC):
    """A single self-contained analysis rule.

    Subclass this and implement `check_file()`.
    Every rule is responsible for exactly one concern.
    """

    #: Short identifier used in Finding.category (e.g. "mutable_default")
    RULE_ID: str
    #: Default severity for findings from this rule
    SEVERITY: str
    #: Default confidence for findings from this rule
    CONFIDENCE: str

    @abstractmethod
    def check_file(self, file_path: Path, source: str) -> list[Finding]:
        """Analyse a single source file and return findings (empty list = clean)."""
        ...
