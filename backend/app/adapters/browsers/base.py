"""Browser adapter contract for future browser-based evidence collection.

This phase does not drive a real browser or perform security testing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from app.domain.http import HttpExchange
from app.plugins.errors import AdapterNotImplementedError


@dataclass
class BrowserSnapshot:
    url: str
    title: str | None = None
    dom: str | None = None
    screenshot_path: str | None = None
    console: tuple[str, ...] = ()
    cookies: tuple[str, ...] = ()
    local_storage: Mapping[str, str] = field(default_factory=dict)
    session_storage: Mapping[str, str] = field(default_factory=dict)
    network: Sequence[HttpExchange] = ()


class BrowserAdapter(ABC):
    @property
    @abstractmethod
    def adapter_id(self) -> str: ...

    @abstractmethod
    def is_available(self) -> bool: ...

    async def navigate(self, url: str) -> None:
        raise AdapterNotImplementedError(
            f"{self.adapter_id} browser navigation is reserved for a later phase."
        )

    async def snapshot(self) -> BrowserSnapshot:
        raise AdapterNotImplementedError(
            f"{self.adapter_id} page snapshots are reserved for a later phase."
        )
