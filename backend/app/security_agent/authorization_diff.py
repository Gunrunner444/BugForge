"""Compare two identity-scoped HTTP observations. Never auto-declare a vulnerability."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class AuthorizationHypothesis:
    title: str
    target: str
    difference: str
    status_a: int | None
    status_b: int | None
    evidence_ids: tuple[str, ...] = ()
    security_expectation: str = ""
    is_vulnerability: bool = False

    def snapshot(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "target": self.target,
            "difference": self.difference,
            "status_a": self.status_a,
            "status_b": self.status_b,
            "evidence_ids": list(self.evidence_ids),
            "security_expectation": self.security_expectation,
            "is_vulnerability": False,
        }


def compare_authorization(
    exchange_a: dict[str, Any],
    exchange_b: dict[str, Any],
    *,
    expectation: str,
    evidence_ids: tuple[str, ...] = (),
) -> AuthorizationHypothesis:
    status_a = _status(exchange_a)
    status_b = _status(exchange_b)
    body_a = str((exchange_a.get("response") or {}).get("body") or "")
    body_b = str((exchange_b.get("response") or {}).get("body") or "")
    differences = []
    if status_a != status_b:
        differences.append(f"status {status_a} vs {status_b}")
    if body_a != body_b:
        differences.append("response body differs")
    owner_a = exchange_a.get("resource_id") or ""
    owner_b = exchange_b.get("resource_id") or ""
    if owner_a and owner_b and owner_a != owner_b:
        differences.append("resource identity differs")
    return AuthorizationHypothesis(
        title="authorization differential",
        target=str(exchange_a.get("url") or exchange_b.get("url") or ""),
        difference="; ".join(differences) or "no meaningful difference",
        status_a=status_a,
        status_b=status_b,
        evidence_ids=evidence_ids,
        security_expectation=expectation,
        is_vulnerability=False,
    )


def _status(exchange: dict[str, Any]) -> int | None:
    raw = exchange.get("status") or (exchange.get("response") or {}).get("status")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None
