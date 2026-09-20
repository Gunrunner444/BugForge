"""Language capability flags used by language adapters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


@dataclass
class LanguageStats:
    language: str
    file_count: int
    percentage: float


class LanguageCapability(StrEnum):
    """What a language adapter can actually do.

    Detection-only adapters are registered so repository language statistics
    stay accurate. They must not claim PARSE or STATIC_ANALYSIS until a real
    implementation exists.
    """

    DETECTION = "detection"
    SOURCE = "source"
    PARSE = "parse"
    STATIC_ANALYSIS = "static_analysis"
