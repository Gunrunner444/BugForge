"""Fuzzing adapter contract.

No live fuzzing engine is implemented in this phase. Implementations must
honor a :class:`ScopeConstraint` before generating traffic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from enum import StrEnum

from app.domain.evidence import Evidence
from app.domain.scope import ScopeConstraint
from app.plugins.errors import UnsupportedCapabilityError


class FuzzingTarget(StrEnum):
    PARAMETER = "parameter"
    JSON_BODY = "json_body"
    HEADER = "header"
    PATH = "path"
    API = "api"


class FuzzingAdapter(ABC):
    @property
    @abstractmethod
    def adapter_id(self) -> str: ...

    def capabilities(self) -> frozenset[FuzzingTarget]:
        return frozenset()

    def fuzz(
        self,
        *,
        target: FuzzingTarget,
        scope: ScopeConstraint,
    ) -> Sequence[Evidence]:
        raise UnsupportedCapabilityError(
            self.adapter_id,
            target,
            detail="Live fuzzing is reserved for a later phase and must stay in-scope.",
        )
