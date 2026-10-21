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
# Older rows named these fixtures before applicability existed. An empty name is
# not in this set: a missing fixture is not proof that the token is standard.
LEGACY_APPLICABLE_FIXTURES = frozenset({"", "standard", "standard_erc20"})
# Strength is stricter than display. An absent fixture must be re-analyzed
# before a violation can be strong. An explicit standard fixture can stay eligible.
LEGACY_STRONG_FIXTURES = frozenset({"standard", "standard_erc20"})
_PROVEN = frozenset({"source", "validated_profile"})
_ROLE_PROVEN = frozenset({"runtime", "validated_profile"})


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
    behavior_evidence = facts.get("token_behavior_evidence", "")
    if fixture in MATERIAL_FIXTURES:
        if behavior == fixture and behavior_evidence in _PROVEN:
            assumptions.append(
                Assumption(
                    "token_behavior",
                    fixture,
                    "confirmed",
                    f"{behavior_evidence} evidence records token_behavior={behavior}",
                    True,
                )
            )
        elif behavior in _STANDARD and behavior_evidence in _PROVEN:
            assumptions.append(
                Assumption(
                    "token_behavior",
                    fixture,
                    "contradicted",
                    f"{behavior_evidence} evidence records token_behavior={behavior}, "
                    f"which contradicts fixture {fixture}",
                    True,
                )
            )
        else:
            assumptions.append(
                Assumption(
                    "token_behavior",
                    fixture,
                    "unknown",
                    "no source or validated-profile fact establishes this nonstandard "
                    "token behavior; a harness setting is not target evidence",
                    True,
                )
            )
    elif fixture in _STANDARD:
        assumptions.append(
            Assumption(
                "token_behavior",
                fixture,
                "confirmed",
                "the harness baseline is a standard token and this property does not "
                "depend on fee-on-transfer or rebasing behavior",
                False,
            )
        )
    elif fixture:
        assumptions.append(
            Assumption(
                "token_behavior",
                fixture,
                "unknown",
                "the fixture name is not a known token behavior and is not treated "
                "as target-applicable",
                True,
            )
        )
    role = facts.get("role_getter", "")
    if role:
        role_evidence = facts.get("role_evidence", "")
        if role_evidence in _ROLE_PROVEN:
            assumptions.append(
                Assumption(
                    "privileged_actor",
                    role,
                    "confirmed",
                    f"{role_evidence} evidence shows the caller matches {role}",
                    True,
                )
            )
        else:
            assumptions.append(
                Assumption(
                    "privileged_actor",
                    role,
                    "unknown",
                    "the source names a role getter; this run has not shown that the "
                    "caller holds that role",
                    True,
                )
            )
    if facts.get("report_scope") == "host":
        host = facts.get("reporting_host", "") or "unknown"
        host_evidence = facts.get("reporting_host_evidence", "")
        # A validated local host proves this replay's callback. It does not prove
        # that callback for every bounty deployment. Fee shares that use only
        # observed totals are not that assumption.
        if (
            facts.get("host_dependence") == "observed_inputs"
            and host_evidence == "validated_profile"
            and host != "unknown"
        ):
            assumptions.append(
                Assumption(
                    "reporting_host",
                    host,
                    "confirmed",
                    "fee inputs are observed totals, supply, and fee configuration; "
                    "this property does not assume the host callback matches a deployment",
                    False,
                )
            )
        elif host_evidence == "validated_profile" and host != "unknown":
            assumptions.append(
                Assumption(
                    "reporting_host",
                    host,
                    "unknown",
                    f"validated profile names {host} for this local replay; "
                    "that does not establish the host callback matches the bounty deployment",
                    True,
                )
            )
        else:
            assumptions.append(
                Assumption(
                    "reporting_host",
                    host,
                    "unknown",
                    "the report callback is host-scoped and no validated host profile was supplied",
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


def confirm_validated_role(
    applicability: Applicability, *, execution_id: str = "", property_id: str = ""
) -> Applicability:
    """Confirm the role for this execution only. The input object is not mutated."""
    bound = execution_id or "unbound"
    named = property_id or "unbound"
    evidence = (
        "the harness read the role getter and it returned the deploying contract "
        f"for execution {bound} and property {named}; another execution does not inherit this"
    )
    assumptions = tuple(
        replace(item, status="confirmed", evidence=evidence)
        if item.name == "privileged_actor"
        else item
        for item in applicability.assumptions
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


def apply_execution_applicability(
    applicability: Applicability,
    *,
    identity_status: str,
    reason_code: str,
    role_proven: bool,
    role_denied: bool,
    execution_id: str = "",
    property_id: str = "",
) -> Applicability:
    """Recompute applicability from this execution. A sibling record is left untouched."""
    updated = reconcile_identity(applicability, identity_status)
    if role_denied or reason_code == "role_unconfirmed":
        return deny_unconfirmed_role(updated)
    if role_proven:
        return confirm_validated_role(updated, execution_id=execution_id, property_id=property_id)
    return updated


_TOKEN_ORACLES = frozenset(
    {
        "credit_le_received",
        "credit_le_holdings",
        "credit_matches_reported",
        "balance_not_increased",
        "fee_shares_match",
    }
)
_ASSUMPTION_KEYS = frozenset({"name", "value", "status", "evidence", "material"})


def _assumption_from(raw: object) -> Assumption | None:
    if not isinstance(raw, Mapping):
        return None
    name = raw.get("name")
    status = raw.get("status")
    if not isinstance(name, str) or status not in {"confirmed", "contradicted", "unknown"}:
        return None
    evidence = raw.get("evidence", "")
    value = raw.get("value", "")
    material = raw.get("material", True)
    if (
        not isinstance(evidence, str)
        or not isinstance(value, str)
        or not isinstance(material, bool)
    ):
        return None
    return Assumption(name, value, status, evidence, material)


def applicability_is_strong(record: Mapping[str, Any]) -> bool:
    """True only when the stored applicability still recomputes to target_applicable.

    A stored disposition does not override contradictory assumptions, a missing
    token fixture on an accounting oracle, a role proof for a different execution,
    or a host-dependent callback.
    """
    raw = record.get("applicability")
    if not isinstance(raw, Mapping):
        return False
    items = raw.get("assumptions")
    if not isinstance(items, list):
        return False
    assumptions: list[Assumption] = []
    for item in items:
        parsed = _assumption_from(item)
        if parsed is None:
            return False
        if isinstance(item, Mapping) and set(item) - _ASSUMPTION_KEYS:
            return False
        assumptions.append(parsed)
    frozen = tuple(assumptions)
    recomputed = _disposition(frozen, executable=True)
    if raw.get("disposition") != recomputed or recomputed != "target_applicable":
        return False
    for item in frozen:
        if item.name == "reporting_host" and item.material:
            return False
        if item.material and item.status == "confirmed" and "harness setting" in item.evidence:
            return False
        if item.name == "token_behavior" and item.material and item.status == "confirmed":
            if not (
                item.evidence.startswith("source ")
                or item.evidence.startswith("validated_profile ")
            ):
                return False
        if item.name == "privileged_actor" and item.status == "confirmed":
            execution = str(record.get("sequence_id") or "")
            property_id = str(record.get("property_id") or "")
            if (
                not execution
                or not property_id
                or execution == "unbound"
                or property_id == "unbound"
            ):
                return False
            if (
                f"execution {execution}" not in item.evidence
                or f"property {property_id}" not in item.evidence
            ):
                return False
    fixture = str(record.get("token_fixture") or "")
    if str(record.get("oracle_kind") or "") in _TOKEN_ORACLES:
        if fixture in LEGACY_STRONG_FIXTURES:
            return True
        if fixture in MATERIAL_FIXTURES:
            match = next((item for item in frozen if item.name == "token_behavior"), None)
            return bool(
                match
                and match.status == "confirmed"
                and match.value == fixture
                and (
                    match.evidence.startswith("source ")
                    or match.evidence.startswith("validated_profile ")
                )
            )
        return False
    if fixture and fixture not in LEGACY_STRONG_FIXTURES | MATERIAL_FIXTURES:
        return False
    return True


def mark_not_applicable(applicability: Applicability, evidence: str) -> Applicability:
    assumptions = applicability.assumptions + (
        Assumption("execution_identity", "stale", "contradicted", evidence, True),
    )
    return replace(
        applicability,
        disposition="not_applicable",
        assumptions=assumptions,
    )
