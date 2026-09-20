"""Scope provider contract for authorized testing."""

from __future__ import annotations

from abc import ABC, abstractmethod
from urllib.parse import urlparse

from app.domain.scope import ScopeConstraint
from app.plugins.errors import AdapterNotImplementedError


class ScopeProvider(ABC):
    @property
    @abstractmethod
    def provider_id(self) -> str: ...

    @abstractmethod
    def get_scope(self) -> ScopeConstraint: ...

    def is_in_scope(self, target: str, *, method: str | None = None) -> bool:
        scope = self.get_scope()
        host = _host_from_target(target)
        if not scope.allows_host(host):
            return False
        if method is not None and not scope.allows_method(method):
            return False
        return True

    def fetch_remote_scope(self) -> ScopeConstraint:
        raise AdapterNotImplementedError(
            f"{self.provider_id} remote scope retrieval is reserved for a later phase."
        )


def _host_from_target(target: str) -> str:
    raw = target.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or "").lower()
    # host[:port] or bare hostname
    return raw.split("/", 1)[0].split(":", 1)[0].lower()
