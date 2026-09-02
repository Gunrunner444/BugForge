from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID, uuid4


@dataclass
class Finding:
    """A single static-analysis finding for a specific location in source code."""

    category: str
    severity: str  # info | low | medium | high | critical
    confidence: str  # low | medium | high
    file_path: str
    line: int
    end_line: int
    message: str
    explanation: str
    analyzer: str
    evidence: str = ""
    suggested_fix: str = ""
    column: int | None = None
    id: UUID = field(default_factory=uuid4)
