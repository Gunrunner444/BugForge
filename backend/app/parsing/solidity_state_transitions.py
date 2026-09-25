"""Bounded state transitions, candidate invariants, and exploit-path search.

A transition is an abstract step, not a symbolic execution. A candidate path
is not an exploit. A generated invariant is not proved. This module never
emits ``verified`` or ``reproduced``.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field

from app.parsing.comments import strip_comments
from app.parsing.solidity_cfg import node_at, node_ranges
from app.parsing.solidity_cross_dataflow import (
    analyze_operation_authorization,
    reentrancy_dependencies,
)
from app.parsing.solidity_dataflow import (
    DataflowModel,
    DependencyEdge,
    FunctionSummary,
    analyze_dataflow,
)
from app.parsing.solidity_ir import SemanticFunction, SemanticProgram, StateAccess
from app.parsing.solidity_value_flow import CallResolution, _path_in, resolve_call

MAX_TRANSITIONS = 64
MAX_PATHS = 16
MAX_DEPTH = 4
MAX_INVARIANTS = 32
_FORBIDDEN = frozenset({"verified", "reproduced", "safe"})
_ROLES = {
    "totalsupply": "supply",
    "_totalsupply": "supply",
    "totalassets": "assets",
    "_totalassets": "assets",
    "balances": "balance",
    "balance": "balance",
    "allowance": "allowance",
    "allowances": "allowance",
    "debt": "debt",
    "debts": "debt",
    "reserve": "reserve",
    "reserves": "reserve",
    "shares": "shares",
    "implementation": "implementation",
    "_implementation": "implementation",
    "paused": "paused",
    "_paused": "paused",
    "nonce": "nonce",
    "nonces": "nonce",
    "owner": "authority",
    "_owner": "authority",
}
_ASSET_CALLS = frozenset({"transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "send"})
_INFLOW = frozenset({"transferFrom", "safeTransferFrom"})


@dataclass(frozen=True)
class TransitionFact:
    fact_id: str
    kind: str
    relation: str
    subject: str
    value: str
    provenance: str
    operation_ids: tuple[str, ...] = ()
    call_ids: tuple[str, ...] = ()
    span: tuple[int, int, int, int] = (0, 0, 0, 0)


@dataclass(frozen=True)
class StateTransition:
    transition_id: str
    contract: str
    function_id: str
    pre_state: tuple[str, ...]
    inputs: tuple[str, ...]
    conditions: tuple[str, ...]
    computations: tuple[str, ...]
    external_calls: tuple[str, ...]
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    assets: tuple[str, ...]
    authorization: tuple[str, ...]
    post_state: tuple[str, ...]
    assumptions: tuple[str, ...]
    provenance: str
    spans: tuple[tuple[int, int, int, int], ...]
    status: str
    incomplete_reason: str = ""
    call_ids: tuple[str, ...] = ()
    resolutions: tuple[str, ...] = ()
    facts: tuple[TransitionFact, ...] = ()


@dataclass(frozen=True)
class PathStep:
    step_id: str
    transition_id: str
    function_id: str
    contract_id: str
    relation: str
    source_id: str
    sink_id: str
    call_ids: tuple[str, ...] = ()
    operation_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CandidatePath:
    path_id: str
    status: str
    depth: int
    steps: tuple[PathStep, ...]
    transition_ids: tuple[str, ...]
    function_ids: tuple[str, ...]
    contract_ids: tuple[str, ...]
    call_ids: tuple[str, ...]
    operation_ids: tuple[str, ...]
    conditions: tuple[str, ...]
    assumptions: tuple[str, ...]
    bound: str
    completeness: str
    incomplete_reason: str = ""
    reason: str = ""
    invariant_id: str = ""


@dataclass(frozen=True)
class CandidateInvariant:
    invariant_id: str
    category: str
    relation: str
    operations: tuple[str, ...]
    state_variables: tuple[str, ...]
    preconditions: tuple[str, ...]
    postconditions: tuple[str, ...]
    source: str
    status: str
    confidence: str
    assumptions: tuple[str, ...]


@dataclass(frozen=True)
class InvariantCheck:
    invariant_id: str
    transition_id: str
    status: str
    reason: str


@dataclass(frozen=True)
class AccountingAssessment:
    status: str
    reason: str
    relation: str = ""
    operation_ids: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()


@dataclass
class TransitionModel:
    status: str
    transitions: tuple[StateTransition, ...] = ()
    paths: tuple[CandidatePath, ...] = ()
    invariants: tuple[CandidateInvariant, ...] = ()
    checks: tuple[InvariantCheck, ...] = ()
    incomplete_reason: str = ""
    bounds: dict[str, int] = field(default_factory=dict)
    compiler_version: str = ""
    compiler_ir_status: str = ""
    origin: str = "parser"


def analyze_state_transitions(
    program: SemanticProgram,
    *,
    also: Sequence[SemanticProgram] = (),
    limits: dict[str, int] | None = None,
) -> TransitionModel:
    programs = (program, *tuple(also))
    functions = [item for item in _functions(programs)]
    if not functions:
        return TransitionModel(
            "unavailable", incomplete_reason="no functions", bounds=_bounds(limits)
        )
    caps = _bounds(limits)
    flow = analyze_dataflow(program)
    for extra in also:
        _merge_flow(flow, analyze_dataflow(extra))
    reason = program.incomplete_reason
    if len(functions) > caps["transitions"]:
        functions = functions[: caps["transitions"]]
        reason = _join_reason(reason, "transition limit reached")
    transitions = tuple(_transition(programs, flow, item, caps) for item in functions)
    invariants = _invariants(programs, caps)
    checks = _checks(programs, transitions, invariants, flow, caps)
    paths, path_reason = _paths(programs, flow, transitions, checks, invariants, caps)
    reason = _join_reason(reason, path_reason)
    status = "partial" if reason else "available"
    model = TransitionModel(
        status,
        transitions,
        paths,
        invariants,
        checks,
        reason,
        {**caps, "transitions_emitted": len(transitions), "paths_emitted": len(paths)},
        _compiler_version(programs),
        program.compiler_ir_status,
        "parser",
    )
    _reject_forbidden(model)
    return model


def find_candidate_exploit_paths(
    program: SemanticProgram,
    *,
    also: Sequence[SemanticProgram] = (),
    limits: dict[str, int] | None = None,
) -> tuple[CandidatePath, ...]:
    return analyze_state_transitions(program, also=also, limits=limits).paths


def analyze_accounting_transition(
    program: SemanticProgram, function_id: str, flow: DataflowModel | None = None
) -> AccountingAssessment:
    """Classify an accounting relation. An asset transfer alone is observed."""
    if not program.functions:
        return AccountingAssessment("unavailable", "no functions")
    flow = flow or analyze_dataflow(program)
    summary = flow._summary(function_id)
    function = _function(program, function_id)
    if summary is None or function is None:
        return AccountingAssessment("unknown", "function was not resolved")
    if summary.incomplete:
        return AccountingAssessment(
            "incomplete",
            summary.incomplete_reason or "function summary is incomplete",
        )
    return _accounting(program, function, summary)


def _bounds(limits: dict[str, int] | None) -> dict[str, int]:
    defaults = {
        "transitions": MAX_TRANSITIONS,
        "paths": MAX_PATHS,
        "depth": MAX_DEPTH,
        "invariants": MAX_INVARIANTS,
    }
    if not limits:
        return defaults
    bounded = {}
    for key, default in defaults.items():
        requested = int(limits.get(key, default))
        bounded[key] = max(1, min(requested, default))
    return bounded


def _functions(programs: Sequence[SemanticProgram]) -> list[SemanticFunction]:
    found: list[SemanticFunction] = []
    for program in programs:
        found.extend(program.functions)
    found.sort(key=lambda item: (item.contract, item.line, item.name, item.identity))
    return found


def _transition(
    programs: Sequence[SemanticProgram],
    flow: DataflowModel,
    function: SemanticFunction,
    caps: dict[str, int],
) -> StateTransition:
    del caps
    summary = flow._summary(function.identity)
    reads = tuple(item.operation_id for item in function.access_sites if item.kind != "write")
    writes = tuple(item.operation_id for item in function.access_sites if item.kind != "read")
    external = tuple(site.call_id for site in function.call_sites if site.external)
    assumptions: list[str] = []
    resolutions: list[str] = []
    for site in function.call_sites:
        resolution = _resolve_site(programs, function, site)
        resolutions.append(f"{site.call_id}:{resolution.status}:{resolution.reason}")
        if resolution.status != "resolved":
            assumptions.append(f"{site.call_id} {resolution.reason}".strip())
    if summary is not None and summary.placement_gaps:
        assumptions.append("CFG placement incomplete")
    conditions, condition_gap = _conditions(function)
    if condition_gap:
        assumptions.append(condition_gap)
    authorization = tuple(
        f"{item.operation_id}:{item.guard_status}"
        for item in function.access_sites
        if item.kind != "read"
    )
    assets = tuple(
        f"{item.source}->{item.destination}:{item.amount}"
        for item in (summary.asset_flows if summary else ())
    )
    computations = tuple(
        value.identity
        for value in (summary.values if summary else ())
        if value.kind in {"local", "join", "internal-return", "external-return"}
    )
    incomplete = bool(summary and summary.incomplete)
    reason = summary.incomplete_reason if summary and summary.incomplete else ""
    status = (
        "incomplete" if incomplete else "observed" if (reads or writes or external) else "unknown"
    )
    facts = _facts(function, summary)
    return StateTransition(
        function.identity,
        function.contract,
        function.identity,
        reads,
        function.parameters,
        conditions,
        computations,
        external,
        reads,
        writes,
        assets,
        authorization,
        writes,
        tuple(dict.fromkeys(assumptions)),
        "parser",
        tuple(_span(item) for item in function.access_sites),
        status,
        reason,
        tuple(site.call_id for site in function.call_sites),
        tuple(resolutions),
        tuple(facts),
    )


def _facts(function: SemanticFunction, summary: FunctionSummary | None) -> list[TransitionFact]:
    found: list[TransitionFact] = []
    for item in function.access_sites:
        found.append(
            TransitionFact(
                item.operation_id,
                "read" if item.kind == "read" else "write",
                item.kind,
                item.path,
                item.symbol,
                "state",
                (item.operation_id,),
                span=_span(item),
            )
        )
    for site in function.call_sites:
        if not site.external:
            continue
        found.append(
            TransitionFact(
                site.call_id,
                "external",
                site.call_type or "external",
                site.target,
                site.callee,
                "external",
                call_ids=(site.call_id,),
                span=(
                    site.span.start_byte,
                    site.span.end_byte,
                    site.span.start_line,
                    site.span.end_line,
                ),
            )
        )
    if summary is not None:
        for flow_item in summary.asset_flows:
            found.append(
                TransitionFact(
                    f"asset:{flow_item.function}:{flow_item.amount[:40]}",
                    "asset",
                    "moves-assets",
                    flow_item.source,
                    flow_item.destination,
                    "observed",
                    call_ids=(),
                )
            )
    return found


def _conditions(function: SemanticFunction) -> tuple[tuple[str, ...], str]:
    source = function.source or ""
    cfg, _ranges = node_ranges(source)
    if not cfg.known:
        return (), "control flow is unknown"
    texts = tuple(
        node.text.strip()[:180]
        for node in cfg.nodes
        if node.kind in {"require", "if"} and node.text.strip()
    )
    return texts, ""


def _accounting(
    program: SemanticProgram, function: SemanticFunction, summary: FunctionSummary
) -> AccountingAssessment:
    found = _relation_findings(program, function, summary)
    for item in found:
        if item.status == "potential":
            return item
    for item in found:
        if item.status == "observed":
            return item
    if found:
        return found[-1]
    return AccountingAssessment("unknown", "no accounting relation was established")


def _relation_findings(
    program: SemanticProgram, function: SemanticFunction, summary: FunctionSummary
) -> tuple[AccountingAssessment, ...]:
    """Every accounting relation this function supports. The first is not the only one."""
    roles = _declared_roles(program)
    assumption = ("variable role is a name heuristic, not a type proof",)
    writes = [item for item in function.access_sites if item.kind != "read"]
    found: list[AccountingAssessment] = []
    supply_writes = [item for item in writes if _role(item.symbol) == "supply"]
    share_writes = [item for item in writes if _role(item.symbol) == "shares"]
    asset_symbols = {name for name, role in roles.items() if role == "assets"}
    balance_symbols = {name for name, role in roles.items() if role == "balance"}
    assets_written = any(_role(item.symbol) == "assets" for item in writes)
    balances_written = any(_role(item.symbol) == "balance" for item in writes)
    influenced = {edge.sink for edge in summary.edges if edge.kind == "state-read-influences-write"}
    increased = [
        item
        for item in (*supply_writes, *share_writes)
        if item.operation_id in influenced and _direction(function, item) == "increase"
    ]
    if increased and asset_symbols and not assets_written and not _has_inflow(function):
        found.append(
            AccountingAssessment(
                "potential",
                "supply or shares increase without a modeled asset inflow",
                "supply-increased-without-asset-inflow",
                tuple(item.operation_id for item in increased),
                assumption,
            )
        )
    supply_increased = [
        item
        for item in supply_writes
        if item.operation_id in influenced and _direction(function, item) == "increase"
    ]
    if supply_increased and balance_symbols and not balances_written and not _has_inflow(function):
        found.append(
            AccountingAssessment(
                "potential",
                "total supply increases without a modeled balance update",
                "supply-increased-without-balance-update",
                tuple(item.operation_id for item in supply_increased),
                assumption,
            )
        )
    debt_writes = [
        item
        for item in writes
        if _role(item.symbol) == "debt"
        and item.operation_id in influenced
        and _direction(function, item) == "decrease"
        and not _has_inflow(function)
    ]
    if debt_writes:
        found.append(
            AccountingAssessment(
                "potential",
                "debt decreases without a modeled repayment",
                "debt-reduced-without-repayment",
                tuple(item.operation_id for item in debt_writes),
                assumption,
            )
        )
    allowance_hits = _allowance_unconsumed(function, summary)
    if allowance_hits:
        found.append(
            AccountingAssessment(
                "potential",
                "an allowance value reaches transferFrom and allowance is not written",
                "allowance-not-consumed",
                tuple(item.operation_id for item in allowance_hits),
                assumption,
            )
        )
    if summary.asset_flows and not any(
        _role(item.symbol) in {"supply", "assets", "shares"} for item in writes
    ):
        found.append(
            AccountingAssessment(
                "observed",
                "asset transfer observed",
                "asset-transfer",
                assumptions=assumption,
            )
        )
    if balances_written:
        found.append(
            AccountingAssessment(
                "observed",
                "balance movement observed",
                "balance-movement",
                tuple(item.operation_id for item in writes if _role(item.symbol) == "balance"),
                assumption,
            )
        )
    if supply_writes and assets_written:
        found.append(
            AccountingAssessment(
                "observed",
                "supply and assets are both written; conservation is not proved",
                "supply-and-assets-updated",
                tuple(
                    item.operation_id
                    for item in (
                        *supply_writes,
                        *[item for item in writes if _role(item.symbol) == "assets"],
                    )
                ),
                assumption,
            )
        )
    if not found:
        found.append(
            AccountingAssessment(
                "unknown", "no accounting relation was established", assumptions=assumption
            )
        )
    return tuple(found)


def _allowance_unconsumed(
    function: SemanticFunction, summary: FunctionSummary
) -> tuple[StateAccess, ...]:
    spends = [site for site in function.call_sites if site.callee in _INFLOW]
    reads = [
        item
        for item in function.access_sites
        if _role(item.symbol) == "allowance" and item.kind != "write"
    ]
    writes = [
        item
        for item in function.access_sites
        if _role(item.symbol) == "allowance" and item.kind != "read"
    ]
    if not spends or not reads or writes:
        return ()
    hits: list[StateAccess] = []
    for item in reads:
        if any(_read_reaches_arguments(summary, item, site.arguments) for site in spends):
            hits.append(item)
    return tuple(hits)


def _read_reaches_arguments(summary: FunctionSummary, access: StateAccess, arguments: str) -> bool:
    if _path_in(access.path, arguments):
        return True
    seen: set[str] = set()
    stack = [access.operation_id]
    reached: set[str] = set()
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for edge in summary.edges:
            if edge.source != current:
                continue
            reached.add(edge.sink)
            stack.append(edge.sink)
    for value in summary.values:
        if value.identity not in reached:
            continue
        slug = value.identity.rsplit(":", 1)[-1]
        if slug and _name_in(slug, arguments):
            return True
    return False


def _name_in(name: str, text: str) -> bool:
    for match in re.finditer(rf"\b{re.escape(name)}\b", text):
        del match
        return True
    return False


def _invariants(
    programs: Sequence[SemanticProgram], caps: dict[str, int]
) -> tuple[CandidateInvariant, ...]:
    roles: dict[str, str] = {}
    for program in programs:
        roles.update(_declared_roles(program))
    by_role: dict[str, list[str]] = defaultdict(list)
    for name, role in sorted(roles.items()):
        by_role[role].append(name)
    specs: list[tuple[str, str, str, tuple[str, ...]]] = []
    if by_role["supply"] and by_role["balance"]:
        specs.append(
            (
                "supply-balance",
                "sum(balance) == totalSupply",
                "equality",
                tuple(by_role["supply"] + by_role["balance"]),
            )
        )
    if by_role["assets"] and (by_role["supply"] or by_role["shares"]):
        specs.append(
            (
                "asset-share",
                "shares correspond to assets",
                "asset-share",
                tuple(by_role["assets"] + by_role["supply"] + by_role["shares"]),
            )
        )
    if by_role["authority"]:
        specs.append(
            (
                "authorization",
                "only authorized actors may modify authority state",
                "authorization",
                tuple(by_role["authority"]),
            )
        )
    if by_role["nonce"]:
        specs.append(("nonce", "nonce advances on use", "monotonicity", tuple(by_role["nonce"])))
    if by_role["implementation"]:
        specs.append(
            (
                "upgrade",
                "implementation changes require an authorized transition",
                "upgrade",
                tuple(by_role["implementation"]),
            )
        )
    if by_role["paused"]:
        specs.append(
            (
                "pause",
                "paused implies sensitive operations are unavailable",
                "pause",
                tuple(by_role["paused"]),
            )
        )
    if by_role["debt"]:
        specs.append(
            ("debt", "debt is reduced only with modeled repayment", "debt", tuple(by_role["debt"]))
        )
    if by_role["reserve"]:
        specs.append(
            (
                "reserve",
                "reserve changes track modeled inflow and outflow",
                "reserve",
                tuple(by_role["reserve"]),
            )
        )
    if by_role["allowance"]:
        specs.append(
            (
                "allowance",
                "transferFrom consumes allowance",
                "allowance",
                tuple(by_role["allowance"]),
            )
        )
    found: list[CandidateInvariant] = []
    for category, relation, kind, variables in specs:
        if len(found) >= caps["invariants"]:
            break
        found.append(
            CandidateInvariant(
                f"inv:{category}:{','.join(variables)}",
                kind,
                relation,
                (),
                variables,
                (),
                (),
                "name-heuristic",
                "candidate",
                "low",
                (
                    "candidate invariant, not a proof",
                    "variable role is a name heuristic, not a type proof",
                ),
            )
        )
    return tuple(found)


def _checks(
    programs: Sequence[SemanticProgram],
    transitions: tuple[StateTransition, ...],
    invariants: tuple[CandidateInvariant, ...],
    flow: DataflowModel,
    caps: dict[str, int],
) -> tuple[InvariantCheck, ...]:
    del caps
    found: list[InvariantCheck] = []
    for transition in transitions:
        summary = flow._summary(transition.function_id)
        function = _function_in(programs, transition.function_id)
        findings: tuple[AccountingAssessment, ...] | None = None
        for invariant in invariants:
            if summary is None or function is None:
                status, reason = "unknown", "function summary is unavailable"
            elif summary.incomplete or transition.status == "incomplete":
                status, reason = (
                    "incomplete",
                    transition.incomplete_reason or "transition is incomplete",
                )
            else:
                if findings is None:
                    program = _program_containing(programs, transition.function_id)
                    findings = (
                        _relation_findings(program, function, summary)
                        if program is not None
                        else (AccountingAssessment("unknown", "function was not resolved"),)
                    )
                status, reason = _judge(
                    transition, invariant, findings, function, summary, programs
                )
            found.append(
                InvariantCheck(invariant.invariant_id, transition.transition_id, status, reason)
            )
    return tuple(found)


def _judge(
    transition: StateTransition,
    invariant: CandidateInvariant,
    findings: tuple[AccountingAssessment, ...],
    function: SemanticFunction,
    summary: FunctionSummary,
    programs: Sequence[SemanticProgram],
) -> tuple[str, str]:
    touched = any(
        item.symbol in invariant.state_variables and item.kind != "read"
        for item in function.access_sites
    )
    external = bool(transition.external_calls)
    for item in findings:
        if item.status == "potential" and _relation_matches(item.relation, invariant.category):
            return "potential", item.reason
    if invariant.category in {"authorization", "upgrade"}:
        verdict = _guard_verdict(function, invariant)
        if verdict is not None:
            return verdict
    if not touched and not external and summary.placement_gaps == 0:
        if _internal_might_touch(programs, function, invariant, frozenset()):
            return "unknown", "an internal call may update the invariant variables"
        return "preserved", "this transition does not write the invariant variables"
    if not touched and external:
        return "unknown", "an external call may update the invariant variables"
    return "unknown", "the transition touches the invariant but no violation was established"


def _guard_verdict(
    function: SemanticFunction, invariant: CandidateInvariant
) -> tuple[str, str] | None:
    relevant = [
        item
        for item in function.access_sites
        if item.kind != "read" and item.symbol in invariant.state_variables
    ]
    if not relevant:
        return None
    if any(item.guard_status == "unguarded" for item in relevant):
        if invariant.category == "upgrade":
            return "potential", "implementation is written without a dominating guard"
        return "potential", "authority state is written without a dominating guard"
    if any(item.guard_status != "guarded" for item in relevant):
        return "unknown", "a guard does not dominate every write of this variable"
    return None


def _internal_might_touch(
    programs: Sequence[SemanticProgram],
    function: SemanticFunction,
    invariant: CandidateInvariant,
    seen: frozenset[str],
) -> bool:
    if function.identity in seen or len(seen) > 4:
        return True
    for site in function.call_sites:
        if site.external:
            continue
        resolution = _resolve_site(programs, function, site)
        if resolution.status != "resolved" or not resolution.function_id:
            return True
        callee = _function_in(programs, resolution.function_id)
        if callee is None:
            return True
        if any(
            item.symbol in invariant.state_variables and item.kind != "read"
            for item in callee.access_sites
        ):
            return True
        if _internal_might_touch(programs, callee, invariant, seen | {function.identity}):
            return True
    return False


def _paths(
    programs: Sequence[SemanticProgram],
    flow: DataflowModel,
    transitions: tuple[StateTransition, ...],
    checks: tuple[InvariantCheck, ...],
    invariants: tuple[CandidateInvariant, ...],
    caps: dict[str, int],
) -> tuple[tuple[CandidatePath, ...], str]:
    by_id = {item.transition_id: item for item in transitions}
    found: list[CandidatePath] = []
    reason = ""
    for transition in transitions:
        if len(found) >= caps["paths"]:
            reason = "path limit reached"
            break
        _single_paths(programs, flow, transition, checks, invariants, found, caps)
    edges = _resolved_edges(programs, transitions)
    if len(found) < caps["paths"]:
        _multi_paths(by_id, edges, checks, found, caps)
    if len(found) > caps["paths"]:
        found = found[: caps["paths"]]
        reason = "path limit reached"
    for item in found:
        if item.status in _FORBIDDEN:
            raise RuntimeError(item.status)
    if any(item.completeness == "partial" for item in found):
        reason = _join_reason(reason, "depth bound reached")
    return tuple(found), reason


def _single_paths(
    programs: Sequence[SemanticProgram],
    flow: DataflowModel,
    transition: StateTransition,
    checks: tuple[InvariantCheck, ...],
    invariants: tuple[CandidateInvariant, ...],
    found: list[CandidatePath],
    caps: dict[str, int],
) -> None:
    if len(found) >= caps["paths"] or transition.status == "incomplete":
        return
    home = _program_containing(programs, transition.function_id) or programs[0]
    for call, read_id, write_id in reentrancy_dependencies(home, transition.function_id, flow):
        if len(found) >= caps["paths"]:
            return
        found.append(
            _path(
                f"reentrancy:{transition.function_id}:{call}:{write_id}",
                transition,
                (
                    _step(transition, "reads-from", read_id, call, (read_id,), (call,)),
                    _step(
                        transition, "depends-on", read_id, write_id, (read_id, write_id), (call,)
                    ),
                    _step(
                        transition, "externally-calls", call, write_id, (read_id, write_id), (call,)
                    ),
                    _step(transition, "writes-to", write_id, write_id, (write_id,), (call,)),
                ),
                "state read reaches a write after an external call",
                depth=1,
            )
        )
    summary = flow._summary(transition.function_id)
    function = _function_in(programs, transition.function_id)
    program = home
    if summary is not None and function is not None and not summary.incomplete:
        for accounting in _relation_findings(program, function, summary):
            if accounting.status != "potential" or len(found) >= caps["paths"]:
                continue
            invariant = _matching_invariant(
                invariants, checks, transition.transition_id, accounting.relation
            )
            found.append(
                _path(
                    f"accounting:{transition.function_id}:{accounting.relation}",
                    transition,
                    (
                        _step(
                            transition,
                            "violates-candidate-invariant",
                            accounting.relation,
                            invariant or accounting.relation,
                            accounting.operation_ids,
                            (),
                        ),
                    ),
                    accounting.reason,
                    depth=1,
                    invariant_id=invariant,
                )
            )
        _oracle_paths(transition, function, summary, found, caps)
        _delegate_paths(program, flow, transition, function, found, caps)
        _authority_paths(program, transition, function, found, caps)


def _oracle_paths(
    transition: StateTransition,
    function: SemanticFunction,
    summary: FunctionSummary,
    found: list[CandidatePath],
    caps: dict[str, int],
) -> None:
    sensitive_ids = {
        item.operation_id
        for item in function.access_sites
        if item.kind != "read"
        and _role(item.symbol) in {"assets", "supply", "debt", "balance", "shares", "reserve"}
    }
    ordered_writes = [
        item.operation_id for item in function.access_sites if item.operation_id in sensitive_ids
    ]
    for site in function.call_sites:
        if site.call_type != "oracle" or len(found) >= caps["paths"]:
            continue
        return_id = f"{function.identity}:return:{site.call_id}"
        reached = [
            write_id for write_id in ordered_writes if _forward(summary.edges, return_id, write_id)
        ]
        if not reached:
            continue
        write_id = reached[0]
        found.append(
            _path(
                f"oracle:{site.call_id}",
                transition,
                (
                    _step(
                        transition, "externally-calls", site.call_id, return_id, (), (site.call_id,)
                    ),
                    _step(
                        transition, "depends-on", return_id, write_id, (write_id,), (site.call_id,)
                    ),
                    _step(
                        transition, "writes-to", write_id, write_id, (write_id,), (site.call_id,)
                    ),
                ),
                "oracle return reaches a security-sensitive write",
                depth=1,
                assumptions=("no oracle validation was established",),
            )
        )


def _delegate_paths(
    program: SemanticProgram,
    flow: DataflowModel,
    transition: StateTransition,
    function: SemanticFunction,
    found: list[CandidatePath],
    caps: dict[str, int],
) -> None:
    from app.parsing.solidity_cross_dataflow import analyze_delegatecall

    for site in function.call_sites:
        if site.call_type != "delegatecall" or len(found) >= caps["paths"]:
            continue
        result = analyze_delegatecall(program, function.identity, site.call_id, flow)
        if result.status != "potential":
            continue
        found.append(
            _path(
                f"delegate:{site.call_id}",
                transition,
                (
                    _step(
                        transition,
                        "externally-calls",
                        site.target,
                        site.call_id,
                        (),
                        (site.call_id,),
                    ),
                ),
                result.summary,
                depth=1,
                assumptions=(f"target provenance is {result.provenance}",),
            )
        )


def _authority_paths(
    program: SemanticProgram,
    transition: StateTransition,
    function: SemanticFunction,
    found: list[CandidatePath],
    caps: dict[str, int],
) -> None:
    for item in function.access_sites:
        if item.kind == "read" or len(found) >= caps["paths"]:
            continue
        role = _role(item.symbol)
        if role not in {"authority", "implementation"}:
            continue
        result = analyze_operation_authorization(program, function.identity, item.operation_id)
        if result.status != "potential":
            continue
        relation = "changes-authority" if role == "authority" else "changes-implementation"
        found.append(
            _path(
                f"{relation}:{item.operation_id}",
                transition,
                (
                    _step(
                        transition, relation, item.operation_id, item.path, (item.operation_id,), ()
                    ),
                ),
                result.summary,
                depth=1,
            )
        )


def _multi_paths(
    by_id: dict[str, StateTransition],
    edges: list[dict[str, str]],
    checks: tuple[InvariantCheck, ...],
    found: list[CandidatePath],
    caps: dict[str, int],
) -> None:
    children: dict[str, list[dict[str, str]]] = defaultdict(list)
    for edge in edges:
        children[edge["caller"]].append(edge)
    for key in children:
        children[key].sort(key=lambda item: item["call_id"])
    property_ids = {check.transition_id for check in checks if check.status == "potential"}
    property_ids.update(
        item.transition_id
        for path in found
        if path.completeness == "complete" and path.depth == 1
        for item in (by_id.get(path.function_ids[0]),)
        if item is not None
    )

    def walk(chain: list[tuple[str, str]]) -> None:
        if len(found) >= caps["paths"]:
            return
        current = chain[-1][0]
        if len(chain) >= 2 and current in property_ids:
            _emit_chain(by_id, chain, checks, found, caps, complete=True, reason="")
        if len(chain) >= caps["depth"]:
            if children.get(current) and len(found) < caps["paths"]:
                _emit_chain(
                    by_id,
                    chain,
                    checks,
                    found,
                    caps,
                    complete=False,
                    reason="depth bound reached",
                )
            return
        for edge in children.get(current, []):
            if edge["callee"] in {item[0] for item in chain}:
                continue
            walk([*chain, (edge["callee"], edge["call_id"])])

    for origin in sorted(by_id):
        if len(found) >= caps["paths"]:
            break
        if children.get(origin):
            walk([(origin, "")])


def _emit_chain(
    by_id: dict[str, StateTransition],
    chain: list[tuple[str, str]],
    checks: tuple[InvariantCheck, ...],
    found: list[CandidatePath],
    caps: dict[str, int],
    *,
    complete: bool,
    reason: str,
) -> None:
    if len(found) >= caps["paths"]:
        return
    steps: list[PathStep] = []
    for index, (function_id, call_id) in enumerate(chain[1:], start=1):
        previous = chain[index - 1][0]
        transition = by_id.get(previous)
        if transition is None:
            return
        steps.append(
            _step(
                transition,
                "invokes",
                previous,
                function_id,
                (),
                (call_id,) if call_id else (),
            )
        )
    last = by_id.get(chain[-1][0])
    first = by_id.get(chain[0][0])
    if last is None or first is None:
        return
    if complete:
        violated = [
            check.invariant_id
            for check in checks
            if check.transition_id == last.transition_id and check.status == "potential"
        ]
        if len(violated) == 1:
            steps.append(
                _step(
                    last,
                    "violates-candidate-invariant",
                    violated[0],
                    last.function_id,
                    last.writes,
                    (),
                )
            )
    path_id = "chain:" + ">".join(item[0] for item in chain)
    if any(item.path_id == path_id for item in found):
        return
    status = "candidate" if complete else "incomplete"
    found.append(
        CandidatePath(
            path_id,
            status,
            len(chain),
            tuple(steps),
            tuple(item[0] for item in chain),
            tuple(item[0] for item in chain),
            tuple(by_id[item[0]].contract for item in chain if item[0] in by_id),
            tuple(item[1] for item in chain if item[1]),
            last.writes,
            first.conditions,
            last.assumptions,
            f"depth<={caps['depth']}",
            "complete" if complete else "partial",
            "" if complete else reason,
            "resolved call chain reaches a candidate property" if complete else reason,
        )
    )


def _resolved_edges(
    programs: Sequence[SemanticProgram], transitions: tuple[StateTransition, ...]
) -> list[dict[str, str]]:
    known = {item.function_id for item in transitions}
    edges: list[dict[str, str]] = []
    for program in programs:
        for function in program.functions:
            if function.identity not in known:
                continue
            for site in sorted(function.call_sites, key=lambda item: item.span.start_byte):
                resolution = _resolve_site(programs, function, site)
                if resolution.status == "resolved" and resolution.function_id in known:
                    edges.append(
                        {
                            "caller": function.identity,
                            "callee": resolution.function_id,
                            "call_id": site.call_id,
                            "status": resolution.status,
                        }
                    )
    edges.sort(key=lambda item: (item["caller"], item["call_id"], item["callee"]))
    return edges


def _resolve_site(
    programs: Sequence[SemanticProgram], function: SemanticFunction, site: object
) -> CallResolution:
    home = _program_containing(programs, function.identity)
    resolution = (
        resolve_call(home, function, site)
        if home is not None
        else CallResolution("unknown", reason="function program was not found")
    )
    if resolution.status == "resolved":
        return resolution
    target = str(getattr(site, "target", "") or "").strip()
    callee = str(getattr(site, "callee", "") or "")
    if not target:
        return resolution
    facts = [fact for program in programs for fact in program.contracts if fact.name == target]
    if any(fact.kind == "interface" for fact in facts):
        return CallResolution("unknown", reason="interface call is not an implementation")
    named = [
        item
        for program in programs
        for item in program.functions
        if item.contract == target and item.name == callee
    ]
    if len(named) == 1:
        return CallResolution("resolved", named[0].identity, "contract-typed")
    if len(named) > 1:
        return CallResolution("unknown", reason="external callee is ambiguous")
    return resolution


def _path(
    path_id: str,
    transition: StateTransition,
    steps: tuple[PathStep, ...],
    reason: str,
    *,
    depth: int,
    invariant_id: str = "",
    assumptions: tuple[str, ...] = (),
) -> CandidatePath:
    return CandidatePath(
        path_id,
        "candidate",
        depth,
        steps,
        (transition.transition_id,),
        (transition.function_id,),
        (transition.contract,),
        tuple(dict.fromkeys(call for step in steps for call in step.call_ids)),
        tuple(dict.fromkeys(op for step in steps for op in step.operation_ids)),
        transition.conditions,
        tuple(dict.fromkeys((*transition.assumptions, *assumptions))),
        f"depth<={MAX_DEPTH}",
        "complete",
        "",
        reason,
        invariant_id,
    )


def _step(
    transition: StateTransition,
    relation: str,
    source: str,
    sink: str,
    operations: tuple[str, ...],
    calls: tuple[str, ...],
) -> PathStep:
    return PathStep(
        f"{transition.transition_id}:{relation}:{source}:{sink}",
        transition.transition_id,
        transition.function_id,
        transition.contract,
        relation,
        source,
        sink,
        calls,
        operations,
    )


def _direction(function: SemanticFunction, access: StateAccess) -> str:
    text = _statement_for(function, access.span.start_byte)
    path = access.path
    increased = (
        f"{path} +=",
        f"{path}=",
    )
    if "+=" in text and path in text.split("+=", 1)[0]:
        return "increase"
    if "-=" in text and path in text.split("-=", 1)[0]:
        return "decrease"
    if f"{path} = {path} +" in text or f"{path}={path}+" in text.replace(" ", ""):
        return "increase"
    if f"{path} = {path} -" in text or f"{path}={path}-" in text.replace(" ", ""):
        return "decrease"
    del increased
    return "unknown"


def _statement_for(function: SemanticFunction, start_byte: int) -> str:
    source = function.source or ""
    cfg, ranges = node_ranges(source)
    base = function.span[0] if function.span else 0
    node_id = node_at(ranges, start_byte - base)
    if node_id is None:
        return ""
    for node in cfg.nodes:
        if node.node_id == node_id:
            return node.text
    return ""


def _has_inflow(function: SemanticFunction) -> bool:
    source = strip_comments(
        function.source or "",
        line_comment="//",
        block_comment=("/*", "*/"),
    )
    if "msg.value" in source:
        return True
    return any(site.callee in _INFLOW or bool(site.value) for site in function.call_sites)


def _declared_roles(program: SemanticProgram) -> dict[str, str]:
    return {item.symbol: role for item in program.declarations if (role := _role(item.symbol))}


def _role(symbol: str) -> str:
    return _ROLES.get(symbol.lower(), "")


def _relation_matches(relation: str, category: str) -> bool:
    pairs = {
        "supply-increased-without-asset-inflow": {"asset-share"},
        "supply-increased-without-balance-update": {"equality"},
        "debt-reduced-without-repayment": {"debt"},
        "allowance-not-consumed": {"allowance"},
    }
    return category in pairs.get(relation, set())


def _matching_invariant(
    invariants: tuple[CandidateInvariant, ...],
    checks: tuple[InvariantCheck, ...],
    transition_id: str,
    relation: str,
) -> str:
    by_id = {item.invariant_id: item for item in invariants}
    found: list[str] = []
    for check in checks:
        invariant = by_id.get(check.invariant_id)
        if invariant is None or check.transition_id != transition_id:
            continue
        if check.status == "potential" and _relation_matches(relation, invariant.category):
            found.append(check.invariant_id)
    if len(found) == 1:
        return found[0]
    return ""


def _forward(edges: tuple[DependencyEdge, ...], source: str, sink: str) -> bool:
    seen: set[str] = set()
    stack = [source]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        if current == sink and current != source:
            return True
        stack.extend(edge.sink for edge in edges if edge.source == current)
    return False


def _span(item: StateAccess) -> tuple[int, int, int, int]:
    return (item.span.start_byte, item.span.end_byte, item.span.start_line, item.span.end_line)


def _function(program: SemanticProgram, function_id: str) -> SemanticFunction | None:
    exact = [item for item in program.functions if item.identity == function_id]
    if len(exact) == 1:
        return exact[0]
    named = [item for item in program.functions if item.name == function_id]
    if len(named) == 1:
        return named[0]
    return None


def _function_in(programs: Sequence[SemanticProgram], function_id: str) -> SemanticFunction | None:
    exact = [
        item for program in programs for item in program.functions if item.identity == function_id
    ]
    if len(exact) == 1:
        return exact[0]
    if len(programs) == 1:
        return _function(programs[0], function_id)
    return None


def _program_containing(
    programs: Sequence[SemanticProgram], identity: str
) -> SemanticProgram | None:
    matches = [
        program
        for program in programs
        if any(item.identity == identity for item in program.functions)
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _compiler_version(programs: Sequence[SemanticProgram]) -> str:
    versions = [item.compiler_version for item in programs if item.compiler_version]
    unique = tuple(dict.fromkeys(versions))
    if not unique:
        return ""
    if len(unique) == 1:
        return unique[0]
    return "mixed"


def _join_reason(left: str, right: str) -> str:
    parts = [part for part in (left, right) if part]
    return "; ".join(dict.fromkeys(parts))


def _merge_flow(target: DataflowModel, extra: DataflowModel) -> None:
    target.summaries.update(extra.summaries)
    target.values.update(extra.values)
    target.edges = tuple([*target.edges, *extra.edges])[
        : extra.edges.__len__() + target.edges.__len__()
    ]
    if extra.incomplete_reason:
        target.incomplete_reason = _join_reason(target.incomplete_reason, extra.incomplete_reason)
        target.status = "partial"


def _reject_forbidden(model: TransitionModel) -> None:
    for path in model.paths:
        if path.status in _FORBIDDEN:
            raise RuntimeError(path.status)
    for check in model.checks:
        if check.status in _FORBIDDEN:
            raise RuntimeError(check.status)
    for transition in model.transitions:
        if transition.status in _FORBIDDEN:
            raise RuntimeError(transition.status)
