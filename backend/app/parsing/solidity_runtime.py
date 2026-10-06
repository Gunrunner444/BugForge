"""Runtime, fork, and differential observations.

Missing fields stay unknown. A runtime result is evidence, not verification,
and a difference between two runs is not a vulnerability.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from app.discovery.sequences import MAX_EXECUTIONS
from app.parsing.solidity_economics import AssetDelta
from app.parsing.solidity_protocol import InteractionEdge, ProtocolGraph

SCHEMA = "bugforge-runtime-v1"
_CALL_TYPES = frozenset(
    {"CALL", "STATICCALL", "DELEGATECALL", "CREATE", "CREATE2", "RETURN", "REVERT"}
)
_MAX_DEPTH = 8
_MAX_FRAMES = 32
_MAX_EVENTS = 32
_MAX_STORAGE = 32
_ASSET_KINDS = frozenset({"erc20", "share", "debt", "reserve", "fee", "native"})


@dataclass(frozen=True)
class ForkIdentity:
    chain_id: str = ""
    fork_source: str = ""
    block_number: str = ""
    state_snapshot: str = ""
    compiler_configuration: str = ""
    project: str = ""
    target: str = ""
    deployments: tuple[str, ...] = ()
    configured: bool = False

    @property
    def deterministic(self) -> bool:
        if not self.configured or not self.fork_source or not self.state_snapshot:
            return False
        if not self.chain_id or not self.block_number.isdigit():
            return False
        return self.block_number != "latest"


@dataclass(frozen=True)
class StateIdentity:
    chain_id: str = ""
    block_number: str = ""
    state_snapshot: str = ""
    runtime_configuration: str = ""
    compiler_configuration: str = ""
    source_snapshot: str = ""
    targets: tuple[str, ...] = ()
    sequence_id: str = ""
    actors: tuple[str, ...] = ()
    project: str = ""


@dataclass(frozen=True)
class TraceFrame:
    caller: str = ""
    callee: str = ""
    selector: str = ""
    function_identity: str = ""
    depth: int = 0
    call_input: str = ""
    output: str = ""
    success: str = ""
    value: str = ""
    gas: str = ""
    source_mapping: str = ""
    call_type: str = "unknown"
    children: tuple[TraceFrame, ...] = ()


@dataclass(frozen=True)
class NormalizedEvent:
    address: str = ""
    contract_identity: str = ""
    topic: str = ""
    transaction_index: str = ""
    log_index: str = ""
    decoded: str = ""
    raw: str = ""
    source_identity: str = ""
    name: str = ""


@dataclass(frozen=True)
class StorageChange:
    address: str = ""
    contract_identity: str = ""
    slot: str = ""
    before: str = ""
    after: str = ""
    transaction_index: str = ""
    execution_context: str = ""
    source_identity: str = ""
    layout_established: bool = False


@dataclass(frozen=True)
class RuntimeObservation:
    project: str = ""
    source_snapshot: str = ""
    compiler_configuration: str = ""
    runtime_environment: str = ""
    sequence_id: str = ""
    transaction_index: str = ""
    actor: str = ""
    contract: str = ""
    function_identity: str = ""
    success: str = ""
    return_data: str = ""
    revert_reason: str = ""
    gas_used: str = ""
    events: tuple[NormalizedEvent, ...] = ()
    storage_changes: tuple[StorageChange, ...] = ()
    trace: tuple[TraceFrame, ...] = ()
    call_type: str = ""
    block_number: str = ""
    block_timestamp: str = ""
    chain_id: str = ""
    state_snapshot: str = ""
    duration: str = ""
    tool: str = ""
    tool_version: str = ""
    status: str = "incomplete"
    deployment_address: str = ""
    selector: str = ""
    runtime_configuration: str = ""
    fork: ForkIdentity | None = None
    execution_id: str = ""


@dataclass(frozen=True)
class DifferentialReport:
    status: str
    classification: str
    differences: tuple[str, ...]
    assumptions: tuple[str, ...]
    left_execution: str
    right_execution: str
    vulnerability: str = "unknown"


def clamp_runtime_executions(requested: int) -> int:
    """A planner may only tighten the shared execution cap."""
    return max(1, min(int(requested), MAX_EXECUTIONS))


def local_command() -> list[str]:
    """Pinned local runtime inside the sandbox. No public endpoint is included."""
    return [
        "bugforge-runtime",
        "--mode",
        "local",
        "--chain-id",
        "31337",
        "--block",
        "1",
        "--timestamp",
        "0",
        "--output",
        "/bugforge-output/runtime.json",
    ]


def network_allowed(
    *, mode: str, fork_enabled: bool, deterministic: bool, requested_network: str
) -> bool:
    """Request text cannot turn the network on."""
    del requested_network
    return mode == "fork" and fork_enabled and deterministic


def fork_identity(
    *,
    configured: bool,
    fork_source: str,
    chain_id: str,
    block_number: str,
    state_snapshot: str,
    compiler_configuration: str = "",
    project: str = "",
    target: str = "",
    deployments: tuple[str, ...] = (),
) -> ForkIdentity:
    return ForkIdentity(
        chain_id=chain_id,
        fork_source=fork_source if configured else "",
        block_number=block_number,
        state_snapshot=state_snapshot,
        compiler_configuration=compiler_configuration,
        project=project,
        target=target,
        deployments=deployments,
        configured=configured and bool(fork_source),
    )


def same_state(left: StateIdentity, right: StateIdentity) -> bool:
    """Comparable runs share one complete starting state. Empty identity does not match."""
    if left != right:
        return False
    required = (
        left.chain_id,
        left.block_number,
        left.state_snapshot,
        left.runtime_configuration,
        left.source_snapshot,
        left.sequence_id,
        left.project,
    )
    return all(required) and bool(left.targets) and bool(left.actors)


def state_of(observation: RuntimeObservation) -> StateIdentity:
    fork = observation.fork
    targets = (observation.deployment_address,) if observation.deployment_address else ()
    actors = (observation.actor,) if observation.actor else ()
    return StateIdentity(
        chain_id=observation.chain_id or (fork.chain_id if fork else ""),
        block_number=observation.block_number or (fork.block_number if fork else ""),
        state_snapshot=observation.state_snapshot or (fork.state_snapshot if fork else ""),
        runtime_configuration=observation.runtime_configuration,
        compiler_configuration=observation.compiler_configuration,
        source_snapshot=observation.source_snapshot,
        targets=targets,
        sequence_id=observation.sequence_id,
        actors=actors,
        project=observation.project,
    )


def parse_runtime_document(text: str) -> tuple[RuntimeObservation, ...] | None:
    """Parse the sandbox schema. Unrecognized text produces no observation."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        return None
    shared = {key: _text(payload.get(key)) for key in _SHARED}
    transactions = payload.get("transactions")
    if not isinstance(transactions, list):
        return None
    deployments = _deployments(payload.get("deployments"))
    observations: list[RuntimeObservation] = []
    for index, row in enumerate(transactions[:MAX_EXECUTIONS]):
        if not isinstance(row, dict):
            continue
        observations.append(_observation(shared, row, deployments, index))
    if not observations:
        return (
            RuntimeObservation(
                project=shared["project"],
                source_snapshot=shared["source_snapshot"],
                compiler_configuration=shared["compiler_configuration"],
                runtime_environment=shared["runtime_environment"],
                chain_id=shared["chain_id"],
                block_number=shared["block_number"],
                block_timestamp=shared["block_timestamp"],
                state_snapshot=shared["state_snapshot"],
                tool=shared["tool"],
                tool_version=shared["tool_version"],
                duration=shared["duration"],
                runtime_configuration=shared["runtime_configuration"],
                status="incomplete",
            ),
        )
    return tuple(observations)


def normalize_trace(
    rows: object, *, depth: int = 0, remaining: list[int] | None = None
) -> tuple[TraceFrame, ...]:
    """Keep nesting and call type. A selector is not a source function."""
    if depth > _MAX_DEPTH or not isinstance(rows, list):
        return ()
    budget = remaining if remaining is not None else [_MAX_FRAMES]
    frames: list[TraceFrame] = []
    for row in rows:
        if budget[0] <= 0 or not isinstance(row, dict):
            break
        budget[0] -= 1
        established = row.get("identity_established") is True
        identity = _text(row.get("function_identity")) if established else ""
        call_type = _text(row.get("call_type"))
        frames.append(
            TraceFrame(
                caller=_text(row.get("caller")),
                callee=_text(row.get("callee")),
                selector=_text(row.get("selector")),
                function_identity=identity,
                depth=depth,
                call_input=_text(row.get("input")),
                output=_text(row.get("output")),
                success=_text(row.get("success")),
                value=_text(row.get("value")),
                gas=_text(row.get("gas")),
                source_mapping=_text(row.get("source_mapping")),
                call_type=call_type if call_type in _CALL_TYPES else "unknown",
                children=normalize_trace(row.get("children"), depth=depth + 1, remaining=budget),
            )
        )
    return tuple(frames)


def event_proves_asset(event: NormalizedEvent) -> bool:
    """A Transfer or Swap name is not an asset, a token, or an AMM."""
    del event
    return False


def slots_equivalent(left: StorageChange, right: StorageChange) -> bool:
    """Numerical slots match only inside one established layout and contract."""
    if not left.layout_established or not right.layout_established:
        return False
    if not left.contract_identity or left.contract_identity != right.contract_identity:
        return False
    if not left.address or left.address != right.address:
        return False
    return bool(left.slot) and left.slot == right.slot


def bind_protocol_edge(
    graph: ProtocolGraph,
    *,
    contract_identity: str,
    function_identity: str,
    edge_id: str,
) -> str:
    """Bind a runtime call only when contract, function, and edge identities match."""
    if not contract_identity or not function_identity or not edge_id:
        return ""
    edge = next((item for item in graph.edges if item.edge_id == edge_id), None)
    if edge is None or edge.function_id != function_identity:
        return ""
    function = next(
        (item for item in graph.functions if item.function_id == function_identity), None
    )
    node = next((item for item in graph.nodes if item.node_id == edge.source), None)
    if function is None or node is None:
        return ""
    if function.node_id != node.node_id or node.contract != contract_identity:
        return ""
    if function.signature in {"", "unresolved"}:
        return ""
    return edge.edge_id


def bind_state_transition(
    *,
    runtime_contract: str,
    runtime_function: str,
    runtime_storage: str,
    transition_contract: str,
    transition_function: str,
    transition_storage: str,
    transition_id: str,
) -> str:
    """Map a storage change onto a Phase 41 transition only when every id matches."""
    if not all(
        (
            runtime_contract,
            runtime_function,
            runtime_storage,
            transition_contract,
            transition_function,
            transition_storage,
            transition_id,
        )
    ):
        return ""
    if runtime_contract != transition_contract:
        return ""
    if runtime_function != transition_function:
        return ""
    if runtime_storage != transition_storage:
        return ""
    return transition_id


def runtime_balance(
    *,
    actor: str,
    token: str,
    kind: str,
    before: int | None,
    after: int | None,
    transaction_index: int | None,
    snapshot: str,
    contract: str,
    source: str,
    provenance: str,
) -> AssetDelta | None:
    """Caller-supplied numbers are not runtime evidence."""
    if provenance != "runtime-execution":
        return None
    if kind not in _ASSET_KINDS or not actor or not token or not snapshot or not contract:
        return None
    if transaction_index is None or before is None or after is None:
        return None
    return AssetDelta(
        kind,
        token,
        "token",
        actor,
        before,
        after,
        after - before,
        "runtime",
        transaction_index,
        snapshot,
        contract,
        source,
    )


def compare_executions(
    left: RuntimeObservation, right: RuntimeObservation, *, reset: bool
) -> DifferentialReport:
    """Compare two runs of one sequence. Equality is not safety and divergence is not an exploit."""
    assumptions = (
        "a differential result is not verification",
        "equality does not prove safety",
        "divergence is not a vulnerability",
        "a revert is not a bug",
    )
    if not reset:
        return DifferentialReport(
            "unknown",
            "state-dependent divergence",
            ("starting-state",),
            (*assumptions, "the starting state was not reset"),
            left.execution_id,
            right.execution_id,
        )
    if not same_state(state_of(left), state_of(right)):
        kind = _mismatch_kind(left, right)
        return DifferentialReport(
            "unknown",
            kind,
            (kind,),
            assumptions,
            left.execution_id,
            right.execution_id,
        )
    differences = _differences(left, right)
    if differences:
        return DifferentialReport(
            "candidate",
            "deterministic divergence",
            differences,
            assumptions,
            left.execution_id,
            right.execution_id,
        )
    return DifferentialReport(
        "candidate",
        "deterministic same result",
        (),
        assumptions,
        left.execution_id,
        right.execution_id,
    )


def classify_replay(
    left: RuntimeObservation, right: RuntimeObservation, *, reset: bool
) -> DifferentialReport:
    report = compare_executions(left, right, reset=reset)
    if report.classification not in {"deterministic same result", "deterministic divergence"}:
        return report
    if not left.success or not right.success:
        return DifferentialReport(
            "incomplete",
            "incomplete comparison",
            report.differences or ("missing-result",),
            report.assumptions,
            left.execution_id,
            right.execution_id,
        )
    return report


def metamorphic_expectation(kind: str, *, established: bool) -> str:
    """Similar-looking transformations are not equivalent unless semantics say so."""
    allowed = {"abi-encoding", "repeated-call", "reorder-independent", "same-snapshot"}
    if not established or kind not in allowed:
        return "unknown"
    return "expected-equivalent"


def failure_is_vulnerability(success: str) -> bool:
    """A revert or a failed run does not establish a vulnerability."""
    del success
    return False


def edge_sequence(
    path_edges: tuple[str, ...], edges: tuple[InteractionEdge, ...]
) -> tuple[str, ...]:
    """Return the supplied edge ids when each one exists. Do not search by endpoints."""
    known = {item.edge_id for item in edges}
    if any(item not in known for item in path_edges):
        return ()
    return path_edges


_SHARED = (
    "project",
    "source_snapshot",
    "compiler_configuration",
    "runtime_environment",
    "chain_id",
    "block_number",
    "block_timestamp",
    "state_snapshot",
    "tool",
    "tool_version",
    "duration",
    "runtime_configuration",
    "sequence_id",
)


def _observation(
    shared: dict[str, str],
    row: dict[str, object],
    deployments: dict[str, tuple[str, str]],
    index: int,
) -> RuntimeObservation:
    address = _text(row.get("address"))
    contract, source = deployments.get(address, ("", ""))
    established = row.get("identity_established") is True
    identity = _text(row.get("function_identity")) if established else ""
    if contract and _text(row.get("contract")) not in {"", contract}:
        contract = ""
    elif not contract:
        contract = ""
    success = _text(row.get("success"))
    complete = bool(success) and bool(shared["state_snapshot"])
    return RuntimeObservation(
        project=shared["project"],
        source_snapshot=shared["source_snapshot"],
        compiler_configuration=shared["compiler_configuration"],
        runtime_environment=shared["runtime_environment"],
        sequence_id=_text(row.get("sequence_id")) or shared["sequence_id"],
        transaction_index=_text(row.get("index")) or str(index),
        actor=_text(row.get("actor")),
        contract=contract,
        function_identity=identity,
        success=success,
        return_data=_text(row.get("return_data")),
        revert_reason=_text(row.get("revert_reason")),
        gas_used=_text(row.get("gas_used")),
        events=_events(row.get("events"), contract),
        storage_changes=_storage(row.get("storage"), contract),
        trace=normalize_trace(row.get("trace")),
        call_type=_call(_text(row.get("call_type"))),
        block_number=shared["block_number"],
        block_timestamp=shared["block_timestamp"],
        chain_id=shared["chain_id"],
        state_snapshot=shared["state_snapshot"],
        duration=shared["duration"],
        tool=shared["tool"],
        tool_version=shared["tool_version"],
        status="observed" if complete else "incomplete",
        deployment_address=address,
        selector=_text(row.get("selector")),
        runtime_configuration=shared["runtime_configuration"],
        execution_id=_text(row.get("execution_id")) or f"{shared['state_snapshot']}:{index}",
    )


def _deployments(value: object) -> dict[str, tuple[str, str]]:
    found: dict[str, tuple[str, str]] = {}
    if not isinstance(value, list):
        return found
    for row in value:
        if not isinstance(row, dict):
            continue
        address = _text(row.get("address"))
        identity = _text(row.get("identity")) or _text(row.get("contract"))
        source = _text(row.get("source"))
        if address and identity and address not in found:
            found[address] = (identity, source)
    return found


def _events(value: object, contract: str) -> tuple[NormalizedEvent, ...]:
    if not isinstance(value, list):
        return ()
    found: list[NormalizedEvent] = []
    for row in value[:_MAX_EVENTS]:
        if not isinstance(row, dict):
            continue
        established = (
            row.get("identity_established") is True and _text(row.get("contract")) == contract
        )
        found.append(
            NormalizedEvent(
                address=_text(row.get("address")),
                contract_identity=contract if established else "",
                topic=_text(row.get("topic")),
                transaction_index=_text(row.get("transaction_index")),
                log_index=_text(row.get("log_index")),
                decoded=_text(row.get("decoded")) if row.get("decoded_ok") is True else "",
                raw=_text(row.get("raw")),
                source_identity=_text(row.get("source_identity")) if established else "",
                name=_text(row.get("name")),
            )
        )
    return tuple(found)


def _storage(value: object, contract: str) -> tuple[StorageChange, ...]:
    if not isinstance(value, list):
        return ()
    found: list[StorageChange] = []
    for row in value[:_MAX_STORAGE]:
        if not isinstance(row, dict):
            continue
        layout = row.get("layout_established") is True
        found.append(
            StorageChange(
                address=_text(row.get("address")),
                contract_identity=contract if layout else "",
                slot=_text(row.get("slot")),
                before=_text(row.get("before")),
                after=_text(row.get("after")),
                transaction_index=_text(row.get("transaction_index")),
                execution_context=_text(row.get("execution_context")),
                source_identity=_text(row.get("source_identity")) if layout else "",
                layout_established=layout and bool(contract),
            )
        )
    return tuple(found)


def _differences(left: RuntimeObservation, right: RuntimeObservation) -> tuple[str, ...]:
    found: list[str] = []
    pairs = (
        ("success", left.success, right.success),
        ("return_data", left.return_data, right.return_data),
        ("events", _event_key(left), _event_key(right)),
        ("trace", _trace_key(left.trace), _trace_key(right.trace)),
        ("storage", _storage_key(left), _storage_key(right)),
        ("gas", left.gas_used, right.gas_used),
    )
    for name, first, second in pairs:
        if first != second:
            found.append(name)
    return tuple(found)


def _event_key(observation: RuntimeObservation) -> tuple[tuple[str, ...], ...]:
    return tuple(
        (item.address, item.topic, item.transaction_index, item.log_index, item.raw)
        for item in observation.events
    )


def _storage_key(observation: RuntimeObservation) -> tuple[tuple[str, ...], ...]:
    return tuple(
        (item.address, item.contract_identity, item.slot, item.before, item.after)
        for item in observation.storage_changes
    )


def _trace_key(frames: tuple[TraceFrame, ...]) -> tuple[tuple[str, ...], ...]:
    found: list[tuple[str, ...]] = []
    for frame in frames:
        found.append((frame.call_type, frame.caller, frame.callee, frame.selector, frame.success))
        found.extend(_trace_key(frame.children))
    return tuple(found)


def _mismatch_kind(left: RuntimeObservation, right: RuntimeObservation) -> str:
    if left.block_number != right.block_number or left.chain_id != right.chain_id:
        return "incomplete comparison"
    if left.deployment_address != right.deployment_address:
        return "incomplete comparison"
    if left.runtime_configuration != right.runtime_configuration:
        return "environmental divergence"
    return "incomplete comparison"


def _call(value: str) -> str:
    return value if value in _CALL_TYPES else ("unknown" if value else "")


def _text(value: object) -> str:
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return ""
