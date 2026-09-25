"""Bounded state-transition and candidate-path analysis.

A candidate path is not an exploit and not verification. Unknown stays unknown.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.parsing.solidity_cross_dataflow import (
    analyze_authorization,
    analyze_delegatecall,
    analyze_reentrancy,
)
from app.parsing.solidity_dataflow import analyze_dataflow
from app.parsing.solidity_ir import SemanticProgram

MAX_TRANSITIONS = 64
MAX_PATHS = 16
MAX_DEPTH = 4


@dataclass(frozen=True)
class StateTransition:
    transition_id: str
    contract: str
    function_id: str
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    call_ids: tuple[str, ...]
    status: str
    incomplete_reason: str = ""


@dataclass(frozen=True)
class CandidatePath:
    path_id: str
    status: str
    steps: tuple[str, ...]
    function_ids: tuple[str, ...]
    call_ids: tuple[str, ...]
    operation_ids: tuple[str, ...]
    incomplete_reason: str = ""


@dataclass
class TransitionModel:
    status: str
    transitions: tuple[StateTransition, ...] = ()
    paths: tuple[CandidatePath, ...] = ()
    incomplete_reason: str = ""
    bounds: dict[str, int] = field(default_factory=dict)


def analyze_state_transitions(program: SemanticProgram) -> TransitionModel:
    if not program.functions:
        return TransitionModel("unavailable", incomplete_reason="no functions")
    transitions: list[StateTransition] = []
    reason = ""
    for function in program.functions:
        if len(transitions) >= MAX_TRANSITIONS:
            reason = "transition limit reached"
            break
        transitions.append(
            StateTransition(
                function.identity,
                function.contract,
                function.identity,
                function.reads,
                function.writes,
                tuple(site.call_id for site in function.call_sites),
                "candidate" if function.writes or function.call_sites else "unknown",
            )
        )
    status = "partial" if reason or program.incomplete_reason else "available"
    return TransitionModel(
        status,
        tuple(transitions),
        _paths(program, transitions),
        reason or program.incomplete_reason,
        {"transitions": MAX_TRANSITIONS, "paths": MAX_PATHS, "depth": MAX_DEPTH},
    )


def find_candidate_exploit_paths(program: SemanticProgram) -> tuple[CandidatePath, ...]:
    return analyze_state_transitions(program).paths


def analyze_accounting_transition(program: SemanticProgram, function_id: str) -> str:
    """Return a relation status. A name match alone is unknown."""
    flow = analyze_dataflow(program)
    summary = flow._summary(function_id)
    if summary is None:
        return "unknown"
    linked = any(
        edge.kind in {"local-to-state", "state-read-influences-write"} for edge in summary.edges
    )
    if not linked:
        return "unknown"
    return "potentially-violated" if summary.incomplete else "unknown"


def _paths(
    program: SemanticProgram, transitions: list[StateTransition]
) -> tuple[CandidatePath, ...]:
    found: list[CandidatePath] = []
    for item in transitions:
        if len(found) >= MAX_PATHS:
            break
        reentrancy = analyze_reentrancy(program, item.function_id)
        if reentrancy.status != "potential":
            continue
        authorization = analyze_authorization(program, item.function_id)
        found.append(
            CandidatePath(
                f"path:{item.function_id}",
                "candidate",
                (
                    item.function_id,
                    reentrancy.summary,
                    authorization.status,
                ),
                (item.function_id,),
                reentrancy.call_ids,
                reentrancy.dependencies,
            )
        )
        if any(site for site in item.call_ids):
            delegate = analyze_delegatecall(program, item.function_id)
            if delegate.status == "potential" and len(found) < MAX_PATHS:
                found.append(
                    CandidatePath(
                        f"delegate:{item.function_id}",
                        "candidate",
                        (item.function_id, delegate.summary),
                        (item.function_id,),
                        delegate.call_ids,
                        (),
                    )
                )
    return tuple(found)
