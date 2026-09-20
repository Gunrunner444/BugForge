"""HTTP proxy adapter contract for ingesting captured traffic as evidence."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from app.domain.http import HttpExchange
from app.domain.scope import ScopeConstraint
from app.plugins.errors import AdapterNotImplementedError


class ProxyAdapter(ABC):
    @property
    @abstractmethod
    def adapter_id(self) -> str: ...

    @abstractmethod
    def is_available(self) -> bool: ...

    def fetch_exchanges(self, *, scope: ScopeConstraint | None = None) -> Sequence[HttpExchange]:
        """Return previously captured HTTP evidence. Must not send live requests."""
        raise AdapterNotImplementedError(
            f"{self.adapter_id} proxy ingestion is reserved for a later phase."
        )
