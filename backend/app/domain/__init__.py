"""Vendor-neutral domain models for BugForge's extensible architecture.

This package must not import third-party tool SDKs (Burp, HackerOne, OpenAI, ZAP).
Adapters translate between those systems and these types.
"""

from app.domain.evidence import Evidence, EvidenceBundle, EvidenceKind, EvidenceSource
from app.domain.findings import (
    FindingStatus,
    HumanReviewState,
    SecurityFinding,
    SourceLocation,
)
from app.domain.http import HttpExchange, HttpHeader
from app.domain.language import LanguageCapability, LanguageStats
from app.domain.reports import SecurityReport
from app.domain.scope import ScopeConstraint

__all__ = [
    "Evidence",
    "EvidenceBundle",
    "EvidenceKind",
    "EvidenceSource",
    "FindingStatus",
    "HumanReviewState",
    "HttpExchange",
    "HttpHeader",
    "LanguageCapability",
    "LanguageStats",
    "ScopeConstraint",
    "SecurityFinding",
    "SecurityReport",
    "SourceLocation",
]
