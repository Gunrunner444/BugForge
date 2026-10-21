"""Target applicability of a local property result.

A local violation stays visible. It is a target-applicable candidate only when every
material assumption is confirmed by a structured fact. Applicability is never decided
by reading the human-readable explanation. A token name, symbol, or interface is not
evidence of how that token behaves.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

# Fixtures whose result depends on behavior a normal ERC-20 does not have.
MATERIAL_FIXTURES = frozenset({"fee_on_transfer", "false_return", "rebasing"})
_STANDARD = frozenset({"standard", "standard_erc20"})


@dataclass(frozen=True)
class Assumption:
    name: str
    value: str
    status: str  # confirmed | contradicted | unknown
    evidence: str
    material: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "status": self.status,
            "evidence": self.evidence,
            "material": self.material,
        }


@dataclass(frozen=True)
class Applicability:
    """``target_applicable`` | ``unconfirmed`` | ``fixture_only`` | ``not_applicable``."""

    disposition: str = "not_applicable"
    assumptions: tuple[Assumption, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition,
            "assumptions": [item.as_dict() for item in self.assumptions],
        }


def _disposition(assumptions: tuple[Assumption, ...], *, executable: bool) -> str:
    if not executable:
        return "not_applicable"
    material = [item for item in assumptions if item.material]
    if any(item.status == "contradicted" for item in material):
        if any(
            item.name == "token_behavior" and item.status == "contradicted" for item in material
        ):
            return "fixture_only"
        return "not_applicable"
    if any(item.status == "unknown" for item in material):
        return "unconfirmed"
    return "target_applicable"


def assess(
    *,
    token_fixture: str = "",
    facts: Mapping[str, str] | None = None,
    executable: bool = True,
    identity_status: str = "bound",
) -> Applicability:
    """Decide applicability from fixture, candidate facts, and identity. Deterministic."""
    facts = dict(facts or {})
    assumptions: list[Assumption] = []
    fixture = token_fixture or ""
    behavior = facts.get("token_behavior", "")
    if fixture in MATERIAL_FIXTURES:
        if behavior == fixture:
            assumptions.append(
                Assumption(
                    "token_behavior",
                    fixture,
                    "confirmed",
                    f"a candidate fact records token_behavior={behavior}",
                    True,
                )
            )
        elif behavior in _STANDARD:
            assumptions.append(
                Assumption(
                    "token_behavior",
                    fixture,
                    "contradicted",
                    f"candidate fact token_behavior={behavior} contradicts fixture {fixture}",
                    True,
                )
            )
        else:
            assumptions.append(
                Assumption(
                    "token_behavior",
                    fixture,
                    "unknown",
                    "no source fact establishes this nonstandard token behavior; "
                    "the fixture is a harness convenience",
                    True,
                )
            )
    elif fixture == "standard":
        assumptions.append(
            Assumption(
                "token_behavior",
                "standard",
                "confirmed",
                "the harness baseline is a standard token and this property does not "
                "depend on fee-on-transfer or rebasing behavior",
                False,
            )
        )
    role = facts.get("role_getter", "")
    if role:
        assumptions.append(
            Assumption(
                "privileged_actor",
                role,
                "confirmed",
                "the source compares the caller with this getter; the harness reads it "
                "and does not make the call unless it equals the deploying contract",
                True,
            )
        )
    if identity_status not in {"", "bound"}:
        assumptions.append(
            Assumption(
                "execution_identity",
                identity_status,
                "contradicted",
                "the source or execution identity is not bound to this run",
                True,
            )
        )
    frozen = tuple(assumptions)
    return Applicability(_disposition(frozen, executable=executable), frozen)


def reconcile_identity(applicability: Applicability, identity_status: str) -> Applicability:
    """A mismatched or missing identity blocks applicability. It does not change the verdict."""
    if identity_status in {"", "bound"}:
        return applicability
    kept = tuple(item for item in applicability.assumptions if item.name != "execution_identity")
    assumptions = kept + (
        Assumption(
            "execution_identity",
            identity_status or "unknown",
            "contradicted",
            "the source or execution identity is not bound to this run",
            True,
        ),
    )
    return Applicability(_disposition(assumptions, executable=True), assumptions)


def deny_unconfirmed_role(applicability: Applicability) -> Applicability:
    """The harness read the role getter and it was not the deploying contract.

    The source-level getter is not confirmation that this run's caller was authorized.
    """
    assumptions = tuple(
        replace(
            item,
            status="contradicted",
            evidence=(
                "the harness read the source role getter and it did not return "
                "the deploying contract"
            ),
        )
        if item.name == "privileged_actor"
        else item
        for item in applicability.assumptions
    )
    return Applicability(_disposition(assumptions, executable=True), assumptions)


def mark_not_applicable(applicability: Applicability, evidence: str) -> Applicability:
    assumptions = applicability.assumptions + (
        Assumption("execution_identity", "stale", "contradicted", evidence, True),
    )
    return replace(
        applicability,
        disposition="not_applicable",
        assumptions=assumptions,
    )
