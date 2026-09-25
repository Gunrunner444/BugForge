"""Deterministic attack-surface ordering. Not an AI ranker."""

from __future__ import annotations

from collections.abc import Sequence

_WEIGHTS = {
    "sol.sibling_auth": 8,
    "sol.accounting_desync": 8,
    "sol.storage_collision": 7,
    "sol.erc4626_inflation": 7,
    "sol.flash_spot": 6,
    "sol.reentrancy": 6,
    "sol.boundary": 4,
}


def priority_score(rule_id: str) -> int:
    return _WEIGHTS.get(rule_id, 1)


def prioritize(rule_ids: Sequence[str]) -> list[str]:
    return sorted(set(rule_ids), key=lambda item: (-priority_score(item), item))
