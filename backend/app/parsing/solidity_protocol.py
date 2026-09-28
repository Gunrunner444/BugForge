"""Bounded protocol interaction graph.

Edges exist only when a call, storage link, or implementation link is
established. Similar names do not connect contracts. A path is a candidate,
not a verification, a reproduction, or proof of safety.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.discovery.sequences import (
    MAX_EXECUTIONS,
    ExplorationBounds,
    PlannedCall,
    PlannedSequence,
    clamp_bounds,
    describe_call,
)
from app.parsing.solidity_economics import AssetDelta, EconomicResult, OracleStatus
from app.parsing.solidity_identity import canonical_function_key
from app.parsing.solidity_ir import SemanticCall, SemanticFunction, SemanticProgram
from app.parsing.solidity_spec import function_signature

MAX_PROTOCOL_CONTRACTS = 8
MAX_PROTOCOL_EDGES = 24
MAX_PROTOCOL_EXPANSION = 16
MAX_CALLBACK_DEPTH = 2

_FORBIDDEN = frozenset({"verified", "proved", "reproduced", "confirmed", "safe", "exploited"})
_RESOLVED = frozenset({"resolved", "interface"})
_CALLBACKS = frozenset(
    {
        "ontokenreceived",
        "tokensreceived",
        "onerc721received",
        "onerc1155received",
        "onerc1155batchreceived",
    }
)
_PRIORITY = {
    "storage_dependency": 0,
    "asset_movement": 1,
    "token_transfer": 1,
    "transfer_from": 1,
    "oracle_read": 2,
    "price_dependency": 2,
    "callback": 3,
    "authorization_dependency": 4,
    "delegatecall": 5,
    "proxy_implementation": 5,
    "approval": 6,
    "permit": 6,
    "staticcall": 7,
    "external_call": 8,
    "internal_call": 9,
    "event_state": 9,
}


@dataclass(frozen=True)
class ProtocolBounds:
    max_contracts: int = MAX_PROTOCOL_CONTRACTS
    max_edges: int = MAX_PROTOCOL_EDGES
    max_expansion: int = MAX_PROTOCOL_EXPANSION
    max_callback_depth: int = MAX_CALLBACK_DEPTH


@dataclass(frozen=True)
class StorageLink:
    declaration_id: str
    writer_function: str
    reader_function: str
    provenance: str
    source_file: str


@dataclass(frozen=True)
class ImplementationLink:
    proxy: str
    implementation: str
    provenance: str
    proxy_file: str
    implementation_file: str
    compiler_configuration: str = ""


@dataclass(frozen=True)
class EventLink:
    event: str
    function_identity: str
    declaration_id: str
    provenance: str


@dataclass(frozen=True)
class ContractNode:
    node_id: str
    project: str
    source_snapshot: str
    compiler_configuration: str
    source_file: str
    contract: str
    kind: str
    span: tuple[int, ...]
    address: str
    provenance: str
    roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class FunctionNode:
    function_id: str
    node_id: str
    contract: str
    name: str
    signature: str
    source_file: str
    line: int
    span: tuple[int, ...]
    authorization: str = "unknown"


@dataclass(frozen=True)
class InteractionEdge:
    edge_id: str
    source: str
    target: str
    kind: str
    provenance: str
    function_id: str
    call_id: str


@dataclass(frozen=True)
class UnresolvedCall:
    function_id: str
    call_id: str
    callee: str
    reason: str


@dataclass(frozen=True)
class ProtocolHypothesis:
    kind: str
    status: str
    summary: str
    contracts: tuple[str, ...]
    functions: tuple[str, ...]
    edges: tuple[str, ...]
    assumptions: tuple[str, ...]
    uncertainty: str
    project: str
    source_snapshot: str
    compiler_configuration: str


@dataclass(frozen=True)
class ProtocolGraph:
    nodes: tuple[ContractNode, ...]
    functions: tuple[FunctionNode, ...]
    edges: tuple[InteractionEdge, ...]
    unresolved: tuple[UnresolvedCall, ...]
    hypotheses: tuple[ProtocolHypothesis, ...]
    incomplete: bool
    limit_reason: str
    project: str
    source_snapshot: str
    compiler_configuration: str


@dataclass(frozen=True)
class ProtocolPath:
    path_id: str
    nodes: tuple[str, ...]
    edges: tuple[str, ...]
    kinds: tuple[str, ...]
    status: str


@dataclass(frozen=True)
class FlowStep:
    kind: str
    identity: str
    contract: str


@dataclass(frozen=True)
class CrossFlow:
    steps: tuple[FlowStep, ...]
    status: str
    provenance: str


@dataclass(frozen=True)
class ModalityCorrelation:
    static_id: str
    runtime_event: str
    transition_id: str
    economic_status: str
    executable_input: str
    status: str
    assumptions: tuple[str, ...]


@dataclass(frozen=True)
class ProtocolEvidence:
    project: str
    source_snapshot: str
    compiler_configuration: str
    contracts: tuple[str, ...]
    functions: tuple[str, ...]
    edges: tuple[str, ...]
    path: str
    sequence_id: str
    actors: tuple[str, ...]
    locations: tuple[str, ...]
    engines: tuple[str, ...]
    environment: str
    assumptions: tuple[str, ...]
    uncertainty: str
    status: str


def clamp_protocol_bounds(requested: ProtocolBounds | None) -> ProtocolBounds:
    """A planner may only tighten these caps."""
    if requested is None:
        return ProtocolBounds()
    return ProtocolBounds(
        max_contracts=_cap(requested.max_contracts, MAX_PROTOCOL_CONTRACTS),
        max_edges=_cap(requested.max_edges, MAX_PROTOCOL_EDGES),
        max_expansion=_cap(requested.max_expansion, MAX_PROTOCOL_EXPANSION),
        max_callback_depth=_cap(requested.max_callback_depth, MAX_CALLBACK_DEPTH),
    )


def same_storage(
    left_declaration: str, right_declaration: str, left_symbol: str, right_symbol: str
) -> bool:
    """Shared variable names are not aliasing."""
    del left_symbol, right_symbol
    return bool(left_declaration) and left_declaration == right_declaration


def actor_privilege(actor: str, authorization: str) -> str:
    """A label is not a privilege. Only established semantic evidence counts."""
    del actor
    if authorization == "established":
        return "established"
    return "unknown"


def candidate_status(status: str) -> str:
    if status in _FORBIDDEN:
        return "candidate"
    if status in {"candidate", "unknown", "unsupported", "incomplete", "reachable"}:
        return status
    return "unknown"


def build_protocol_graph(
    programs: tuple[SemanticProgram, ...],
    *,
    project: str,
    source_snapshot: str,
    compiler_configuration: str,
    sources: dict[str, str] | None = None,
    bounds: ProtocolBounds | None = None,
    addresses: dict[tuple[str, str], str] | None = None,
    storage_links: tuple[StorageLink, ...] = (),
    implementation_links: tuple[ImplementationLink, ...] = (),
    event_links: tuple[EventLink, ...] = (),
) -> ProtocolGraph:
    active = clamp_protocol_bounds(bounds)
    texts = sources or {}
    nodes, functions = _nodes(
        programs,
        project=project,
        source_snapshot=source_snapshot,
        compiler_configuration=compiler_configuration,
        sources=texts,
        addresses=addresses or {},
        limit=active.max_contracts,
    )
    incomplete = len(_contract_rows(programs)) > len(nodes)
    reason = "contract cap" if incomplete else ""
    edges, unresolved = _edges(programs, nodes, functions, texts)
    edges.extend(_storage_edges(storage_links, functions))
    edges.extend(_proxy_edges(implementation_links, nodes, compiler_configuration))
    edges.extend(_event_edges(event_links, functions))
    edges.extend(_price_edges(edges))
    edges.sort(key=lambda item: (_PRIORITY.get(item.kind, 10), item.edge_id))
    if len(edges) > active.max_edges:
        edges = edges[: active.max_edges]
        incomplete = True
        reason = reason or "edge cap"
    roles = _roles(nodes, edges)
    hypotheses = _hypotheses(
        edges,
        functions,
        project=project,
        source_snapshot=source_snapshot,
        compiler_configuration=compiler_configuration,
    )
    return ProtocolGraph(
        tuple(roles),
        tuple(functions),
        tuple(edges),
        tuple(unresolved),
        hypotheses,
        incomplete,
        reason,
        project,
        source_snapshot,
        compiler_configuration,
    )


def expand_paths(
    graph: ProtocolGraph, bounds: ProtocolBounds | None = None
) -> tuple[ProtocolPath, ...]:
    """Deterministic expansion. Stronger edge kinds are tried first."""
    active = clamp_protocol_bounds(bounds)
    by_source: dict[str, list[InteractionEdge]] = {}
    for edge in graph.edges:
        by_source.setdefault(edge.source, []).append(edge)
    for items in by_source.values():
        items.sort(key=lambda item: (_PRIORITY.get(item.kind, 10), item.edge_id))
    found: list[ProtocolPath] = []
    for origin in sorted(graph.nodes, key=lambda item: item.node_id):
        queue: list[tuple[str, ...]] = [(origin.node_id,)]
        seen: set[tuple[str, ...]] = {(origin.node_id,)}
        while queue and len(found) < active.max_expansion:
            current = queue.pop(0)
            if len(current) - 1 >= active.max_edges:
                continue
            depth = _callback_depth(current, by_source)
            for edge in by_source.get(current[-1], ()):
                if edge.kind == "callback" and depth + 1 > active.max_callback_depth:
                    continue
                nxt = (*current, edge.target)
                if nxt in seen or len(set(nxt)) > active.max_contracts:
                    continue
                if len(nxt) - 1 > active.max_edges:
                    continue
                seen.add(nxt)
                kinds = _kinds(nxt, by_source)
                found.append(
                    ProtocolPath(
                        "->".join(nxt),
                        nxt,
                        tuple(item.edge_id for item in _path_edges(nxt, by_source)),
                        kinds,
                        "candidate",
                    )
                )
                queue.append(nxt)
                if len(found) >= active.max_expansion:
                    break
    found.sort(key=lambda item: item.path_id)
    return tuple(found[: active.max_expansion])


def cross_flows(
    graph: ProtocolGraph, bounds: ProtocolBounds | None = None
) -> tuple[CrossFlow, ...]:
    active = clamp_protocol_bounds(bounds)
    flows: list[CrossFlow] = []
    for edge in graph.edges:
        if len(flows) >= active.max_edges:
            break
        if edge.kind in {"unresolved", "internal_call"}:
            continue
        flows.append(
            CrossFlow(
                (
                    FlowStep(edge.kind, edge.function_id or edge.edge_id, edge.source),
                    FlowStep(edge.kind, edge.call_id or edge.edge_id, edge.target),
                ),
                "candidate",
                edge.provenance,
            )
        )
    return tuple(flows)


def plan_protocol_calls(
    steps: tuple[tuple[str, str], ...],
    program: SemanticProgram | None,
    source: str,
    *,
    exploration: ExplorationBounds | None = None,
    protocol: ProtocolBounds | None = None,
) -> tuple[PlannedCall, ...] | None:
    """Build calls only from established signatures. Missing arguments reject the plan."""
    active = clamp_bounds(exploration)
    caps = clamp_protocol_bounds(protocol)
    if not steps or len(steps) > active.max_sequence_length:
        return None
    if len({contract for contract, _name in steps}) > caps.max_contracts:
        return None
    if active.max_executions > MAX_EXECUTIONS:
        return None
    if program is None:
        return None
    calls: list[PlannedCall] = []
    for contract, name in steps:
        call = describe_call(program, source, contract, name)
        needs_arguments = _requires_arguments(source, contract, name, program)
        if call is None or (call.arguments == () and needs_arguments):
            return None
        fact = function_signature(source, contract, name, program)
        identity = str(fact.get("identity", "")) if fact else ""
        calls.append(
            PlannedCall(
                call.function,
                call.actor,
                call.arguments,
                call.value,
                call.direction,
                call.assumptions,
                call.score,
                contract,
                identity,
            )
        )
    return tuple(calls)


def protocol_sequences(
    steps: tuple[tuple[str, str], ...],
    program: SemanticProgram | None,
    source: str,
    *,
    exploration: ExplorationBounds | None = None,
    protocol: ProtocolBounds | None = None,
    project: str = "",
    target: str = "",
) -> tuple[PlannedSequence, ...]:
    calls = plan_protocol_calls(steps, program, source, exploration=exploration, protocol=protocol)
    if calls is None:
        return ()
    active = clamp_bounds(exploration)
    sequence = PlannedSequence(
        "protocol:" + "|".join(f"{item.contract}.{item.function}" for item in calls),
        "protocol",
        calls,
        "planned",
        ("a protocol sequence is not a finding", "an actor is not authorization"),
        "protocol",
        project,
        target,
    )
    return (sequence,)[: active.max_executions]


def separate_asset_deltas(deltas: tuple[AssetDelta, ...]) -> EconomicResult:
    """Keep actors and tokens apart. A balance change is not profit or a vulnerability."""
    seen: set[tuple[str, str, str]] = set()
    for delta in deltas:
        key = (delta.actor, delta.token, delta.kind)
        if key in seen:
            return EconomicResult(
                OracleStatus.UNKNOWN.value,
                "two observations of the same actor and token were not merged",
            )
        seen.add(key)
    tokens = {item.token for item in deltas}
    if len(tokens) > 1:
        return EconomicResult(
            OracleStatus.UNKNOWN.value,
            "cross-asset comparison requires an explicit conversion",
            ("no price was invented",),
        )
    return EconomicResult(
        OracleStatus.INCOMPLETE.value,
        "actor-separated balances are observations",
        ("a positive delta is not profit", "a loss is not a vulnerability"),
    )


def correlate_modalities(
    *,
    static_id: str,
    runtime_event: str,
    transition_id: str,
    economic_status: str,
    trace: str,
) -> ModalityCorrelation:
    """Keep static, runtime, transition, and economic modalities separate."""
    assumptions = (
        "an event name is not proof",
        "a static relationship is not a runtime observation",
        "a runtime event is not source-code proof",
        "a caller-supplied trace is not executable input",
    )
    if not static_id and not runtime_event and not transition_id:
        status = "unknown"
    elif runtime_event and not static_id:
        status = "incomplete"
    else:
        status = "incomplete"
    return ModalityCorrelation(
        static_id,
        runtime_event,
        transition_id,
        candidate_status(economic_status) if economic_status else "unknown",
        "",
        status,
        assumptions if trace or runtime_event or static_id else ("modalities stay separate",),
    )


def protocol_evidence(
    graph: ProtocolGraph,
    *,
    path: str = "",
    sequence_id: str = "",
    actors: tuple[str, ...] = (),
    engines: tuple[str, ...] = (),
    environment: str = "local",
    uncertainty: str = "candidate",
) -> ProtocolEvidence:
    return ProtocolEvidence(
        graph.project,
        graph.source_snapshot,
        graph.compiler_configuration,
        tuple(item.contract for item in graph.nodes),
        tuple(item.function_id for item in graph.functions),
        tuple(item.edge_id for item in graph.edges),
        path,
        sequence_id,
        actors,
        tuple(item.source_file for item in graph.nodes),
        engines,
        environment,
        ("a cross-contract candidate is not verification",),
        uncertainty,
        "candidate",
    )


def _cap(requested: int, limit: int) -> int:
    return max(1, min(int(requested), limit))


def _contract_rows(programs: tuple[SemanticProgram, ...]) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for program in programs:
        if program.contracts:
            for item in program.contracts:
                rows.append((program.file, item.name, item.kind or "contract"))
        else:
            for name in sorted({item.contract for item in program.functions if item.contract}):
                rows.append((program.file, name, "contract"))
    return rows


def _nodes(
    programs: tuple[SemanticProgram, ...],
    *,
    project: str,
    source_snapshot: str,
    compiler_configuration: str,
    sources: dict[str, str],
    addresses: dict[tuple[str, str], str],
    limit: int,
) -> tuple[list[ContractNode], list[FunctionNode]]:
    nodes: list[ContractNode] = []
    functions: list[FunctionNode] = []
    for source_file, contract, kind in _contract_rows(programs):
        if len(nodes) >= limit:
            break
        if kind not in {"contract", "interface", "library"}:
            kind = "contract"
        span = _contract_span(programs, source_file, contract)
        node_id = f"{source_file}::{contract}::{','.join(str(part) for part in span)}"
        nodes.append(
            ContractNode(
                node_id,
                project,
                source_snapshot,
                compiler_configuration,
                source_file,
                contract,
                kind,
                span,
                addresses.get((source_file, contract), ""),
                "parser-contract",
            )
        )
        program = next(item for item in programs if item.file == source_file)
        text = sources.get(source_file, "")
        for function in program.functions:
            if function.contract != contract:
                continue
            types = _types(text, contract, function, program)
            functions.append(
                FunctionNode(
                    canonical_function_key(
                        function,
                        source_file=source_file,
                        parameter_types=types,
                        project=project,
                        source_snapshot=source_snapshot,
                        compiler_configuration=compiler_configuration,
                    ),
                    node_id,
                    contract,
                    function.name,
                    f"{function.name}({','.join(types)})",
                    source_file,
                    function.line,
                    function.span,
                    function.authorization,
                )
            )
    return nodes, functions


def _types(
    source: str, contract: str, function: SemanticFunction, program: SemanticProgram
) -> tuple[str, ...]:
    if (
        sum(
            1
            for item in program.functions
            if item.contract == contract and item.name == function.name
        )
        != 1
    ):
        return ()
    fact = function_signature(source, contract, function.name, program) if source else None
    types = fact.get("parameter_types") if fact else ()
    if isinstance(types, tuple):
        return tuple(str(item) for item in types)
    return ()


def _contract_span(
    programs: tuple[SemanticProgram, ...], source_file: str, contract: str
) -> tuple[int, ...]:
    for program in programs:
        if program.file != source_file:
            continue
        spans = [item.span for item in program.functions if item.contract == contract and item.span]
        if spans:
            return spans[0]
    return (0, 0, 0, 0)


def _edges(
    programs: tuple[SemanticProgram, ...],
    nodes: list[ContractNode],
    functions: list[FunctionNode],
    sources: dict[str, str],
) -> tuple[list[InteractionEdge], list[UnresolvedCall]]:
    del sources
    edges: list[InteractionEdge] = []
    unresolved: list[UnresolvedCall] = []
    by_contract = _unique_nodes(nodes)
    for program in programs:
        for function in program.functions:
            caller = _function_node(functions, program.file, function)
            if caller is None:
                continue
            for site in function.call_sites:
                kind = _edge_kind(site, function, by_contract)
                target = _target_node(site, by_contract, function, functions)
                if kind is None or target is None:
                    unresolved.append(
                        UnresolvedCall(
                            caller.function_id,
                            site.call_id,
                            site.callee,
                            "unresolved" if site.resolution not in _RESOLVED else "callee-unknown",
                        )
                    )
                    continue
                edges.append(
                    InteractionEdge(
                        f"{caller.function_id}:{site.call_id}:{kind}",
                        caller.node_id,
                        target,
                        kind,
                        site.call_id or site.resolution,
                        caller.function_id,
                        site.call_id,
                    )
                )
                if _authorization_edge(function, site, functions, target):
                    edges.append(
                        InteractionEdge(
                            f"{caller.function_id}:{site.call_id}:authorization",
                            caller.node_id,
                            target,
                            "authorization_dependency",
                            "callee authorization is established; caller authorization is not",
                            caller.function_id,
                            site.call_id,
                        )
                    )
    return edges, unresolved


def _edge_kind(
    site: SemanticCall,
    function: SemanticFunction,
    nodes: dict[str, ContractNode],
) -> str | None:
    del function
    if site.resolution not in _RESOLVED and site.call_type != "delegatecall":
        return None
    if site.call_type == "delegatecall":
        return "delegatecall" if site.resolution == "resolved" and site.target in nodes else None
    if site.call_type == "staticcall":
        return "staticcall" if site.target in nodes else None
    if site.call_type == "internal":
        return "internal_call"
    if site.callee.lower() in _CALLBACKS:
        return "callback" if site.target in nodes else None
    if site.call_type == "token" and site.callee == "transferFrom":
        return "transfer_from" if site.target in nodes else None
    if site.call_type == "token" and site.callee in {"approve"}:
        return "approval" if site.target in nodes else None
    if site.call_type == "token" and site.callee == "permit":
        return "permit" if site.target in nodes else None
    if site.call_type == "token":
        return "token_transfer" if site.target in nodes else None
    if site.call_type == "oracle":
        return "oracle_read" if site.target in nodes else None
    if site.call_type in {"contract-typed", "external"} and site.target in nodes:
        return "external_call"
    return None


def _target_node(
    site: SemanticCall,
    nodes: dict[str, ContractNode],
    function: SemanticFunction,
    functions: list[FunctionNode],
) -> str | None:
    if site.call_type == "internal":
        matches = [
            item
            for item in functions
            if item.contract == function.contract and item.name == site.callee
        ]
        if len(matches) != 1:
            return None
        return matches[0].node_id
    node = nodes.get(site.target)
    if node is None:
        return None
    if site.call_type == "delegatecall":
        return node.node_id
    if site.call_type == "staticcall" and _named_function(functions, node.contract, site.callee):
        return node.node_id
    if site.callee.lower() in _CALLBACKS and _named_function(functions, node.contract, site.callee):
        return node.node_id
    if site.call_type in {"token", "oracle", "contract-typed", "external"}:
        if _named_function(functions, node.contract, site.callee) is None:
            return None
        return node.node_id
    return None


def _named_function(functions: list[FunctionNode], contract: str, name: str) -> FunctionNode | None:
    matches = [item for item in functions if item.contract == contract and item.name == name]
    if len(matches) != 1:
        return None
    return matches[0]


def _authorization_edge(
    function: SemanticFunction,
    site: SemanticCall,
    functions: list[FunctionNode],
    target: str,
) -> bool:
    if site.resolution not in _RESOLVED or function.authorization == "established":
        return False
    callee = [
        item
        for item in functions
        if item.node_id == target
        and item.name == site.callee
        and item.contract != function.contract
    ]
    return len(callee) == 1 and _callee_authorized(callee[0], functions)


def _callee_authorized(node: FunctionNode, functions: list[FunctionNode]) -> bool:
    del functions
    return node.authorization == "established"


def _unique_nodes(nodes: list[ContractNode]) -> dict[str, ContractNode]:
    counts: dict[str, int] = {}
    for node in nodes:
        counts[node.contract] = counts.get(node.contract, 0) + 1
    return {node.contract: node for node in nodes if counts[node.contract] == 1}


def _function_node(
    functions: list[FunctionNode], source_file: str, function: SemanticFunction
) -> FunctionNode | None:
    matches = [
        item
        for item in functions
        if item.source_file == source_file
        and item.contract == function.contract
        and item.name == function.name
        and item.line == function.line
        and item.span == function.span
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _storage_edges(
    links: tuple[StorageLink, ...], functions: list[FunctionNode]
) -> list[InteractionEdge]:
    by_id = {item.function_id: item for item in functions}
    edges: list[InteractionEdge] = []
    for link in links:
        if not link.declaration_id or not link.provenance:
            continue
        writer = by_id.get(link.writer_function)
        reader = by_id.get(link.reader_function)
        if writer is None or reader is None or writer.function_id == reader.function_id:
            continue
        if writer.source_file != link.source_file and reader.source_file != link.source_file:
            continue
        edges.append(
            InteractionEdge(
                f"storage:{link.declaration_id}:{writer.function_id}:{reader.function_id}",
                writer.node_id,
                reader.node_id,
                "storage_dependency",
                link.provenance,
                writer.function_id,
                link.declaration_id,
            )
        )
    return edges


def _proxy_edges(
    links: tuple[ImplementationLink, ...],
    nodes: list[ContractNode],
    compiler_configuration: str,
) -> list[InteractionEdge]:
    edges: list[InteractionEdge] = []
    for link in links:
        if not link.provenance or not link.implementation:
            continue
        if link.compiler_configuration and link.compiler_configuration != compiler_configuration:
            continue
        proxy = _node_by(nodes, link.proxy_file, link.proxy)
        implementation = _node_by(nodes, link.implementation_file, link.implementation)
        if proxy is None or implementation is None:
            continue
        edges.append(
            InteractionEdge(
                f"proxy:{proxy.node_id}:{implementation.node_id}",
                proxy.node_id,
                implementation.node_id,
                "proxy_implementation",
                link.provenance,
                "",
                "",
            )
        )
    return edges


def _event_edges(
    links: tuple[EventLink, ...], functions: list[FunctionNode]
) -> list[InteractionEdge]:
    by_id = {item.function_id: item for item in functions}
    edges: list[InteractionEdge] = []
    for link in links:
        function = by_id.get(link.function_identity)
        if function is None or not link.event or not link.declaration_id or not link.provenance:
            continue
        edges.append(
            InteractionEdge(
                f"event:{link.event}:{function.function_id}:{link.declaration_id}",
                function.node_id,
                function.node_id,
                "event_state",
                link.provenance,
                function.function_id,
                link.declaration_id,
            )
        )
    return edges


def _price_edges(edges: list[InteractionEdge]) -> list[InteractionEdge]:
    oracle = [item for item in edges if item.kind == "oracle_read"]
    assets = [
        item for item in edges if item.kind in {"token_transfer", "transfer_from", "asset_movement"}
    ]
    found: list[InteractionEdge] = []
    for left in oracle:
        for right in assets:
            if left.function_id and left.function_id == right.function_id:
                found.append(
                    InteractionEdge(
                        f"price:{left.edge_id}:{right.edge_id}",
                        left.target,
                        right.target,
                        "price_dependency",
                        "same-function oracle read and asset call",
                        left.function_id,
                        left.call_id,
                    )
                )
    return found


def _roles(nodes: list[ContractNode], edges: list[InteractionEdge]) -> list[ContractNode]:
    role_for = {
        "token_transfer": "token",
        "transfer_from": "token",
        "oracle_read": "oracle",
        "proxy_implementation": "proxy",
        "delegatecall": "proxy",
        "callback": "callback",
    }
    updated: list[ContractNode] = []
    for node in nodes:
        roles = {
            role_for[item.kind]
            for item in edges
            if item.kind in role_for and item.target == node.node_id
        }
        if any(
            item.kind == "proxy_implementation" and item.source == node.node_id for item in edges
        ):
            roles.add("proxy")
        if any(
            item.kind == "proxy_implementation" and item.target == node.node_id for item in edges
        ):
            roles.add("implementation")
        updated.append(
            ContractNode(
                node.node_id,
                node.project,
                node.source_snapshot,
                node.compiler_configuration,
                node.source_file,
                node.contract,
                node.kind,
                node.span,
                node.address,
                node.provenance,
                tuple(sorted(roles)),
            )
        )
    return updated


def _hypotheses(
    edges: list[InteractionEdge],
    functions: list[FunctionNode],
    *,
    project: str,
    source_snapshot: str,
    compiler_configuration: str,
) -> tuple[ProtocolHypothesis, ...]:
    del functions
    mapping = {
        "callback": "unsafe callback sequencing",
        "delegatecall": "delegatecall storage/authorization consequences",
        "proxy_implementation": "proxy/implementation semantic mismatch",
        "oracle_read": "oracle dependency leading to asset-sensitive behavior",
        "price_dependency": "reserve/price dependency crossing contracts",
        "token_transfer": "token accounting mismatch across contracts",
        "transfer_from": "allowance/approval misuse across components",
        "approval": "allowance/approval misuse across components",
        "permit": "permit misuse across components",
        "authorization_dependency": "cross-contract authorization confusion",
        "storage_dependency": "cross-contract state transition inconsistencies",
        "event_state": "event/state disagreement",
    }
    found: list[ProtocolHypothesis] = []
    seen: set[tuple[str, str]] = set()
    for edge in edges:
        kind = mapping.get(edge.kind)
        if kind is None or (kind, edge.edge_id) in seen:
            continue
        seen.add((kind, edge.edge_id))
        found.append(
            ProtocolHypothesis(
                kind,
                "candidate",
                kind,
                (edge.source, edge.target),
                (edge.function_id,) if edge.function_id else (),
                (edge.edge_id,),
                ("a hypothesis is not verification", "an edge is not an exploit"),
                "candidate",
                project,
                source_snapshot,
                compiler_configuration,
            )
        )
    return tuple(found)


def _node_by(nodes: list[ContractNode], source_file: str, contract: str) -> ContractNode | None:
    matches = [
        item for item in nodes if item.source_file == source_file and item.contract == contract
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _callback_depth(nodes: tuple[str, ...], by_source: dict[str, list[InteractionEdge]]) -> int:
    return sum(1 for item in _path_edges(nodes, by_source) if item.kind == "callback")


def _path_edges(
    nodes: tuple[str, ...], by_source: dict[str, list[InteractionEdge]]
) -> list[InteractionEdge]:
    found: list[InteractionEdge] = []
    for left, right in zip(nodes, nodes[1:], strict=False):
        match = next((item for item in by_source.get(left, ()) if item.target == right), None)
        if match is not None:
            found.append(match)
    return found


def _kinds(nodes: tuple[str, ...], by_source: dict[str, list[InteractionEdge]]) -> tuple[str, ...]:
    return tuple(item.kind for item in _path_edges(nodes, by_source))


def _requires_arguments(source: str, contract: str, name: str, program: SemanticProgram) -> bool:
    fact = function_signature(source, contract, name, program)
    types = fact.get("parameter_types") if fact else ()
    return isinstance(types, tuple) and bool(types)
