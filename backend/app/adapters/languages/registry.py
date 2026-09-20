"""Language-specific adapter registry with extension-based lookup."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from app.adapters.languages.base import LanguageAdapter
from app.domain.language import LanguageCapability, LanguageStats
from app.plugins.errors import AdapterConflictError
from app.plugins.registry import AdapterRegistry


class LanguageRegistry(AdapterRegistry[LanguageAdapter]):
    """Registry that can resolve a language adapter from a filesystem path."""

    def __init__(self) -> None:
        super().__init__("language")
        self._extension_index: dict[str, str] = {}
        self._instances: dict[str, LanguageAdapter] = {}

    def register_adapter(self, adapter: LanguageAdapter, *, replace: bool = False) -> None:
        language_id = adapter.language_id
        if not replace:
            for ext in adapter.file_extensions:
                owner = self._extension_index.get(ext)
                if owner is not None and owner != language_id:
                    raise AdapterConflictError(
                        f"Extension {ext!r} is already claimed by language {owner!r}"
                    )
        self.register(
            language_id,
            lambda instance=adapter: instance,
            description=adapter.display_name,
            replace=replace,
        )
        self._instances[language_id] = adapter
        for ext in adapter.file_extensions:
            self._extension_index[ext.lower()] = language_id

    def unregister(self, adapter_id: str) -> None:
        canonical = self._canonical_or_none(adapter_id)
        if canonical is not None:
            instance = self._instances.pop(canonical, None)
            if instance is not None:
                for ext in instance.file_extensions:
                    if self._extension_index.get(ext.lower()) == canonical:
                        del self._extension_index[ext.lower()]
        super().unregister(adapter_id)

    def get(self, adapter_id: str) -> LanguageAdapter:
        canonical = self.resolve_id(adapter_id)
        cached = self._instances.get(canonical)
        if cached is not None:
            return cached
        instance = self.create(canonical)
        self._instances[canonical] = instance
        return instance

    def all_adapters(self) -> list[LanguageAdapter]:
        return [self.get(adapter_id) for adapter_id in self.available_ids()]

    def analyzers(self) -> list[LanguageAdapter]:
        return [
            adapter
            for adapter in self.all_adapters()
            if adapter.supports(LanguageCapability.STATIC_ANALYSIS)
        ]

    def parsers(self) -> list[LanguageAdapter]:
        return [
            adapter for adapter in self.all_adapters() if adapter.supports(LanguageCapability.PARSE)
        ]

    def for_path(self, path: Path) -> LanguageAdapter | None:
        language_id = self.language_id_for_path(path)
        if language_id is None:
            return None
        return self.get(language_id)

    def language_id_for_path(self, path: Path) -> str | None:
        return self._extension_index.get(path.suffix.lower())

    def detect_languages(self, file_paths: Iterable[Path]) -> list[LanguageStats]:
        from collections import Counter

        counts: Counter[str] = Counter()
        for path in file_paths:
            language_id = self.language_id_for_path(path)
            if language_id:
                counts[language_id] += 1
        total = counts.total()
        return [
            LanguageStats(
                language=language,
                file_count=count,
                percentage=round(count / total * 100, 1) if total else 0.0,
            )
            for language, count in counts.most_common()
        ]
