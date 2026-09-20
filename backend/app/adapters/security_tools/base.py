"""Security tool adapter contract.

Live scanning of external targets is out of scope for this phase. Adapters
exist so a future security engine can collect evidence through one interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from enum import StrEnum

from app.domain.evidence import Evidence
from app.domain.scope import ScopeConstraint
from app.plugins.errors import UnsupportedCapabilityError


class SecurityToolCapability(StrEnum):
    PASSIVE_EVIDENCE = "passive_evidence"
    ACTIVE_SCAN = "active_scan"


class SecurityToolAdapter(ABC):
    """Vendor-neutral security tool boundary."""

    @property
    @abstractmethod
    def tool_id(self) -> str: ...

    @property
    @abstractmethod
    def display_name(self) -> str: ...

    @abstractmethod
    def is_available(self) -> bool:
        """Return True when the backing tool is installed and configured."""

    def capabilities(self) -> frozenset[SecurityToolCapability]:
        return frozenset()

    def collect_passive_evidence(self, *, scope: ScopeConstraint) -> Sequence[Evidence]:
        raise UnsupportedCapabilityError(
            self.tool_id,
            SecurityToolCapability.PASSIVE_EVIDENCE,
            detail="Passive evidence collection is not implemented in this phase.",
        )
