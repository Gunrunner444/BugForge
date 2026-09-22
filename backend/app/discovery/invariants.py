"""Candidate invariants. A suggestion is not an executed property."""

from __future__ import annotations

from dataclasses import dataclass

from app.parsing.model import SyntaxGraph


@dataclass(frozen=True)
class InvariantCandidate:
    name: str
    statement: str
    reason: str
    status: str = "candidate"
    valid: bool = False


def suggest_invariants(graph: SyntaxGraph) -> list[InvariantCandidate]:
    if graph.language != "solidity":
        return []
    names = {entity.name for entity in graph.entities}
    state = {
        event.extra.split("name=", 1)[1].split("|", 1)[0]
        for event in graph.events
        if event.kind == "sol_state" and "name=" in event.extra
    }
    found: list[InvariantCandidate] = []
    if "totalSupply" in state or "totalSupply" in names:
        found.append(
            InvariantCandidate(
                name="supply_conservation",
                statement="sum of balances equals totalSupply",
                reason="The contract exposes total supply state.",
            )
        )
    if any(name.lower().startswith("balance") for name in state):
        found.append(
            InvariantCandidate(
                name="no_negative_balance",
                statement="balances do not go negative",
                reason="A balance mapping or variable is present.",
            )
        )
    if any(name.lower() in {"owner", "admin"} for name in state):
        found.append(
            InvariantCandidate(
                name="owner_authorized",
                statement="only an authorized role changes privileged configuration",
                reason="An owner or admin variable is present.",
            )
        )
    if any(entity.name == "initialize" for entity in graph.entities):
        found.append(
            InvariantCandidate(
                name="initialize_once",
                statement="initialize cannot succeed twice",
                reason="An initialize function is present.",
            )
        )
    return found
