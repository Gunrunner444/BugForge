"""Project-scoped research memory. Credentials are never stored."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from app.security_testing.secrets import redact_text

_FORBIDDEN = ("password", "authorization", "cookie", "token", "secret", "api_key")


@dataclass
class MemoryEntry:
    kind: str
    summary: str
    extra: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid4().hex)

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "summary": self.summary,
            "extra": dict(self.extra),
        }


@dataclass
class ResearchMemory:
    project_id: str
    entries: list[MemoryEntry] = field(default_factory=list)

    def remember(self, kind: str, summary: str, extra: dict[str, Any] | None = None) -> MemoryEntry:
        clean = {
            key: redact_text(str(value))
            for key, value in (extra or {}).items()
            if key.lower() not in _FORBIDDEN
        }
        entry = MemoryEntry(kind=kind, summary=redact_text(summary), extra=clean)
        self.entries.append(entry)
        return entry

    def matching(self, kind: str) -> list[MemoryEntry]:
        return [item for item in self.entries if item.kind == kind]
