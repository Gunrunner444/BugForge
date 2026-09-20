"""Generic adapter registry used by every plugin catalog.

Core orchestration looks up adapters by id (and optional aliases) instead of
branching on hard-coded language/provider names.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from app.plugins.errors import AdapterNotFoundError, DuplicateAdapterError


class AdapterRegistry[T]:
    """Register factories and create adapter instances by stable id.

    Factories may be zero-argument (stateless adapters) or accept keyword
    arguments such as ``settings=`` (AI providers). Callers pass through
    whatever the factory needs via :meth:`create`.
    """

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self._factories: dict[str, Callable[..., T]] = {}
        self._aliases: dict[str, str] = {}
        self._descriptions: dict[str, str] = {}

    def register(
        self,
        adapter_id: str,
        factory: Callable[..., T],
        *,
        aliases: Iterable[str] = (),
        description: str = "",
        replace: bool = False,
    ) -> None:
        canonical = _normalize(adapter_id)
        if not canonical:
            raise ValueError(f"{self.kind} id must be a non-empty string")
        if canonical in self._factories and not replace:
            raise DuplicateAdapterError(self.kind, canonical)
        self._remove_aliases_for(canonical)
        self._factories[canonical] = factory
        self._descriptions[canonical] = description
        for alias in aliases:
            alias_key = _normalize(alias)
            if not alias_key:
                continue
            existing = self._aliases.get(alias_key)
            if existing is not None and existing != canonical and alias_key in self._factories:
                raise DuplicateAdapterError(self.kind, alias_key)
            if alias_key in self._factories and alias_key != canonical:
                raise DuplicateAdapterError(self.kind, alias_key)
            self._aliases[alias_key] = canonical
        # An id is always an alias of itself so lookup is uniform.
        self._aliases[canonical] = canonical

    def unregister(self, adapter_id: str) -> None:
        canonical = self._canonical_or_none(adapter_id)
        if canonical is None:
            return
        self._factories.pop(canonical, None)
        self._descriptions.pop(canonical, None)
        self._remove_aliases_for(canonical)

    def has(self, adapter_id: str) -> bool:
        return self._canonical_or_none(adapter_id) is not None

    def resolve_id(self, adapter_id: str) -> str:
        canonical = self._canonical_or_none(adapter_id)
        if canonical is None:
            raise AdapterNotFoundError(self.kind, adapter_id, self.available_ids())
        return canonical

    def available_ids(self) -> list[str]:
        return sorted(self._factories)

    def description(self, adapter_id: str) -> str:
        return self._descriptions.get(self.resolve_id(adapter_id), "")

    def create(self, adapter_id: str, *args: Any, **kwargs: Any) -> T:
        canonical = self.resolve_id(adapter_id)
        return self._factories[canonical](*args, **kwargs)

    def _canonical_or_none(self, adapter_id: str) -> str | None:
        key = _normalize(adapter_id)
        if not key:
            return None
        if key in self._factories:
            return key
        mapped = self._aliases.get(key)
        if mapped is not None and mapped in self._factories:
            return mapped
        return None

    def _remove_aliases_for(self, canonical: str) -> None:
        stale = [alias for alias, target in self._aliases.items() if target == canonical]
        for alias in stale:
            del self._aliases[alias]


def _normalize(adapter_id: str) -> str:
    return adapter_id.strip().lower()
