"""Discovery corpus. Every seed records provenance and never stores raw secrets."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256

from app.security_testing.secrets import redact_text


class SeedSource(StrEnum):
    INITIAL = "initial"
    STATIC_FINDING = "static_finding"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    LLM = "llm"
    COVERAGE = "coverage"
    CRASH = "crash"
    INTERESTING = "interesting"
    MINIMIZED = "minimized"


@dataclass(frozen=True)
class Seed:
    seed_id: str
    source: SeedSource
    reason: str
    content_sha256: str
    preview: str
    language: str = ""
    target: str = ""

    def snapshot(self) -> dict[str, str]:
        return {
            "seed_id": self.seed_id,
            "source": self.source.value,
            "reason": self.reason,
            "content_sha256": self.content_sha256,
            "preview": self.preview,
            "language": self.language,
            "target": self.target,
        }


@dataclass
class DiscoveryCorpus:
    seeds: list[Seed] = field(default_factory=list)

    def add(
        self,
        content: str,
        *,
        source: SeedSource,
        reason: str,
        language: str = "",
        target: str = "",
        seed_id: str = "",
    ) -> Seed:
        digest = sha256(content.encode("utf-8")).hexdigest()
        for existing in self.seeds:
            if (
                existing.content_sha256 == digest
                and existing.source is source
                and existing.target == target
            ):
                return existing
        redacted = redact_text(content)
        ident = seed_id or f"seed_{len(self.seeds) + 1:03d}"
        seed = Seed(
            seed_id=ident,
            source=source,
            reason=redact_text(reason)[:240],
            content_sha256=digest,
            preview=redacted[:180],
            language=language,
            target=target,
        )
        self.seeds.append(seed)
        return seed

    def by_source(self, source: SeedSource) -> tuple[Seed, ...]:
        return tuple(seed for seed in self.seeds if seed.source is source)

    def snapshot(self) -> dict[str, list[dict[str, str]]]:
        return {"seeds": [seed.snapshot() for seed in self.seeds]}

    @classmethod
    def from_snapshot(cls, payload: dict[str, list[dict[str, str]]] | None) -> DiscoveryCorpus:
        corpus = cls()
        for raw in () if not payload else payload.get("seeds", []):
            corpus.seeds.append(
                Seed(
                    seed_id=raw["seed_id"],
                    source=SeedSource(raw["source"]),
                    reason=raw.get("reason", ""),
                    content_sha256=raw["content_sha256"],
                    preview=raw.get("preview", ""),
                    language=raw.get("language", ""),
                    target=raw.get("target", ""),
                )
            )
        return corpus
