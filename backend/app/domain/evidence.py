"""Evidence-first domain types.

A model-generated hypothesis is never evidence. Collectors convert tool output
and repository artifacts into :class:`Evidence` records that can later be
attached to a finding. Verification still requires independent executable
evidence — this module only models that requirement.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4


class EvidenceKind(StrEnum):
    STATIC_ANALYSIS = "static_analysis"
    SOURCE_CODE = "source_code"
    GENERATED_TEST = "generated_test"
    BROWSER = "browser"
    PROXY = "proxy"
    SCANNER = "scanner"
    FUZZING = "fuzzing"
    API_TEST = "api_test"
    REPRODUCTION = "reproduction"
    SCREENSHOT = "screenshot"
    LOG = "log"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    TEST_FAILURE = "test_failure"


@dataclass
class Evidence:
    """One independently collected piece of evidence."""

    kind: EvidenceKind
    source: str
    summary: str
    details: str = ""
    artifact_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.summary.strip():
            raise ValueError("Evidence summary must be non-empty")
        if not self.source.strip():
            raise ValueError("Evidence source must be non-empty")


@dataclass
class EvidenceSource:
    """Inputs available to evidence collectors.

    All fields are optional so collectors can ignore data they do not
    understand. This is intentionally not tied to Burp, browsers, or a
    particular AI vendor.
    """

    static_findings: Sequence[Any] = ()
    test_failures: Sequence[Any] = ()
    source_files: Sequence[Any] = ()
    generated_tests: Sequence[Any] = ()
    reproductions: Sequence[Any] = ()
    http_exchanges: Sequence[Any] = ()
    screenshots: Sequence[Any] = ()
    logs: Sequence[Any] = ()
    extra: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceBundle:
    """Combined evidence from one or more collectors."""

    items: tuple[Evidence, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def of_kind(self, kind: EvidenceKind) -> tuple[Evidence, ...]:
        return tuple(item for item in self.items if item.kind == kind)

    def extend(self, extra: Iterable[Evidence]) -> EvidenceBundle:
        return EvidenceBundle(items=self.items + tuple(extra))

    @classmethod
    def from_items(cls, items: Iterable[Evidence]) -> EvidenceBundle:
        return cls(items=tuple(items))
