"""Bounded Solidity dataflow over the semantic IR.

Unknown provenance propagates. An incomplete model is not a proof of safety.
This is deterministic program analysis, not a planner and not verification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.parsing.solidity_ir import SemanticFunction, SemanticProgram

MAX_FUNCTIONS = 200
MAX_BLOCKS = 80
MAX_DEPTH = 4
MAX_ITERATIONS = 3
MAX_VALUES = 400
MAX_EDGES = 800


@dataclass(frozen=True)
class FlowValue:
    identity: str
    kind: str
    provenance: str
    dependencies: tuple[str, ...]
    type_name: str
    origin: str
    span: tuple[int, int, int, int] = (0, 0, 0, 0)


@dataclass(frozen=True)
class DependencyEdge:
    source: str
    sink: str
    kind: str


@dataclass(frozen=True)
class AssetFlow:
    function: str
    source: str
    destination: str
    amount: str
    dependencies: tuple[str, ...]


@dataclass
class FunctionSummary:
    identity: str
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    calls: tuple[str, ...]
    values: tuple[FlowValue, ...]
    edges: tuple[DependencyEdge, ...]
    authorization: str
    asset_flows: tuple[AssetFlow, ...]
    cyclic: bool = False
    incomplete: bool = False
    incomplete_reason: str = ""
    ordered_reads: tuple[tuple[int, str], ...] = ()
    ordered_writes: tuple[tuple[int, str], ...] = ()
    ordered_calls: tuple[tuple[int, str, str], ...] = ()


@dataclass
class DataflowModel:
    status: str
    summaries: dict[str, FunctionSummary] = field(default_factory=dict)
    values: dict[str, FlowValue] = field(default_factory=dict)
    edges: tuple[DependencyEdge, ...] = ()
    incomplete_reason: str = ""
    profile: str = "normal"
    iterations: int = 0

    def origin(self, value_id: str) -> str:
        value = self.values.get(value_id)
        return value.provenance if value else "unknown"

    def dependencies(self, value_id: str) -> tuple[str, ...]:
        value = self.values.get(value_id)
        return value.dependencies if value else ()

    def value_reaches(self, value_id: str, sink: str) -> bool:
        if value_id == sink:
            return True
        seen: set[str] = set()
        stack = [value_id]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            if current == sink:
                return True
            stack.extend(edge.sink for edge in self.edges if edge.source == current)
        return False

    def reads_before(self, function: str, call: str) -> tuple[str, ...]:
        return self.reads_before_call(function, call)

    def writes_after(self, function: str, call: str) -> tuple[str, ...]:
        return self.writes_after_call(function, call)

    def reads_before_call(self, function: str, call_id: str) -> tuple[str, ...]:
        summary = self._summary(function)
        order = self._call_order(summary, call_id)
        if summary is None or order is None:
            return ()
        return tuple(path for index, path in summary.ordered_reads if index < order)

    def writes_after_call(self, function: str, call_id: str) -> tuple[str, ...]:
        summary = self._summary(function)
        order = self._call_order(summary, call_id)
        if summary is None or order is None:
            return ()
        return tuple(path for index, path in summary.ordered_writes if index > order)

    def target_provenance(self, function: str, call_id: str = "") -> str:
        summary = self._summary(function)
        if summary is None:
            return "unknown"
        matches = [
            value
            for value in summary.values
            if value.kind == "delegatecall-target" and (not call_id or call_id in value.identity)
        ]
        if len(matches) == 1:
            return matches[0].provenance
        return "unknown"

    def _call_order(self, summary: FunctionSummary | None, call_id: str) -> int | None:
        if summary is None or not call_id:
            return None
        found = [
            index for index, callee, ident in summary.ordered_calls if call_id in {callee, ident}
        ]
        if len(found) != 1:
            return None
        return found[0]

    def authorization_path(self, function: str) -> str:
        summary = self._summary(function)
        return summary.authorization if summary else "unknown"

    def asset_flow(self, function: str) -> tuple[AssetFlow, ...]:
        summary = self._summary(function)
        return summary.asset_flows if summary else ()

    def state_dependency(self, function: str) -> tuple[DependencyEdge, ...]:
        summary = self._summary(function)
        if summary is None:
            return ()
        return tuple(
            edge for edge in summary.edges if "state" in edge.kind or "calldata" in edge.kind
        )

    def reachable_functions(self, function: str) -> tuple[str, ...]:
        summary = self._summary(function)
        if summary is None:
            return ()
        return summary.calls

    def possible_callbacks(self, function: str) -> tuple[str, ...]:
        summary = self._summary(function)
        if summary is None:
            return ()
        return tuple(
            value.identity
            for value in summary.values
            if value.kind in {"external-return", "callback"}
        )

    def _summary(self, function: str) -> FunctionSummary | None:
        if function in self.summaries:
            return self.summaries[function]
        exact = [item for item in self.summaries.values() if item.identity == function]
        if len(exact) == 1:
            return exact[0]
        named = [
            item
            for item in self.summaries.values()
            if item.identity.split(":")[0].rsplit(".", 1)[-1] == function
        ]
        if len(named) == 1:
            return named[0]
        return None


def analyze_dataflow(program: SemanticProgram, *, profile: str = "normal") -> DataflowModel:
    limits = _limits(profile)
    model = DataflowModel(status="partial", profile=profile)
    if program.status == "unavailable" and not program.functions:
        model.status = "unavailable"
        model.incomplete_reason = "no semantic functions"
        return model
    reasons: list[str] = []
    if program.incomplete_reason:
        reasons.append(program.incomplete_reason)
    stack: list[str] = []
    for function in program.functions[: limits["functions"]]:
        _summarize(program, function, model, stack, limits, 0)
    if len(program.functions) > limits["functions"]:
        reasons.append("dataflow function limit reached")
    if len(model.values) >= limits["values"]:
        reasons.append("semantic node limit reached")
    if len(model.edges) >= limits["edges"]:
        reasons.append("dependency edge limit reached")
    model.incomplete_reason = "; ".join(dict.fromkeys(reasons))
    model.status = (
        "partial" if model.incomplete_reason or program.status == "partial" else "partial"
    )
    return model


def _limits(profile: str) -> dict[str, int]:
    if profile == "fast":
        return {
            "functions": 40,
            "blocks": 20,
            "depth": 2,
            "iterations": 1,
            "values": 120,
            "edges": 200,
        }
    if profile == "deep":
        return {
            "functions": MAX_FUNCTIONS,
            "blocks": MAX_BLOCKS * 2,
            "depth": MAX_DEPTH + 2,
            "iterations": MAX_ITERATIONS + 1,
            "values": MAX_VALUES * 2,
            "edges": MAX_EDGES * 2,
        }
    return {
        "functions": MAX_FUNCTIONS,
        "blocks": MAX_BLOCKS,
        "depth": MAX_DEPTH,
        "iterations": MAX_ITERATIONS,
        "values": MAX_VALUES,
        "edges": MAX_EDGES,
    }


def _summarize(
    program: SemanticProgram,
    function: SemanticFunction,
    model: DataflowModel,
    stack: list[str],
    limits: dict[str, int],
    depth: int,
) -> FunctionSummary:
    if function.identity in model.summaries and function.identity not in stack:
        return model.summaries[function.identity]
    model.iterations += 1
    if model.iterations > limits["iterations"] * max(1, limits["functions"]):
        incomplete_summary = FunctionSummary(
            function.identity,
            function.reads,
            function.writes,
            (),
            (),
            (),
            "unknown",
            (),
            incomplete=True,
            incomplete_reason="fixed-point iteration limit reached",
        )
        model.summaries[function.identity] = incomplete_summary
        return incomplete_summary
    cyclic = function.identity in stack
    incomplete = depth > limits["depth"] or cyclic
    reason = ""
    if cyclic:
        reason = "cyclic call"
    elif depth > limits["depth"]:
        reason = "call depth limit reached"
    values: list[FlowValue] = []
    edges: list[DependencyEdge] = []
    if len(function.access_sites) > limits["blocks"]:
        incomplete = True
        reason = reason or "CFG block limit reached"
    if not incomplete:
        values, edges = _intraprocedural(function, limits)
    ordered_reads = tuple(
        (item.span.start_byte, item.path) for item in function.access_sites if item.kind != "write"
    )
    ordered_writes = tuple(
        (item.span.start_byte, item.path) for item in function.access_sites if item.kind != "read"
    )
    ordered_calls = tuple(
        (site.span.start_byte, site.callee, site.call_id) for site in function.call_sites
    )
    for site in function.call_sites:
        if site.external:
            returned = FlowValue(
                f"{function.identity}:return:{site.callee}",
                "external-return",
                "oracle" if site.call_type == "oracle" else "external",
                (site.target or site.callee,),
                "",
                function.identity,
                (
                    site.span.start_byte,
                    site.span.end_byte,
                    site.span.start_line,
                    site.span.end_line,
                ),
            )
            values.append(returned)
            if site.callback_potential:
                values.append(
                    FlowValue(
                        f"{function.identity}:callback:{site.callee}",
                        "callback",
                        "external",
                        (returned.identity,),
                        "",
                        function.identity,
                    )
                )
            if site.call_type == "delegatecall":
                provenance = _delegate_provenance(function, site.target)
                values.append(
                    FlowValue(
                        f"{function.identity}:delegate-target:{site.call_id}",
                        "delegatecall-target",
                        provenance,
                        (site.target,),
                        "",
                        function.identity,
                    )
                )
        elif depth < limits["depth"]:
            callee = _resolve_internal(program, function, site.callee)
            if callee is not None:
                stack.append(function.identity)
                child = _summarize(program, callee, model, stack, limits, depth + 1)
                stack.pop()
                edges.append(DependencyEdge(function.identity, child.identity, "internal-call"))
                if child.cyclic or child.incomplete:
                    incomplete = True
                    reason = child.incomplete_reason or reason
    assets = _assets(function, values)
    for value in values:
        if len(model.values) >= limits["values"]:
            incomplete = True
            reason = reason or "semantic node limit reached"
            break
        model.values[value.identity] = value
    if len(edges) > limits["edges"]:
        edges = edges[: limits["edges"]]
        incomplete = True
        reason = reason or "dependency edge limit reached"
    summary = FunctionSummary(
        function.identity,
        function.reads,
        function.writes,
        tuple(site.callee for site in function.call_sites),
        tuple(values),
        tuple(edges),
        function.authorization,
        tuple(assets),
        cyclic=cyclic,
        incomplete=incomplete or bool(program.incomplete_reason),
        incomplete_reason=reason or program.incomplete_reason,
        ordered_reads=ordered_reads,
        ordered_writes=ordered_writes,
        ordered_calls=ordered_calls,
    )
    model.summaries[function.identity] = summary
    model.edges = tuple([*model.edges, *edges])[: limits["edges"]]
    return summary


def _intraprocedural(
    function: SemanticFunction, limits: dict[str, int]
) -> tuple[list[FlowValue], list[DependencyEdge]]:
    values: list[FlowValue] = []
    edges: list[DependencyEdge] = []
    for access in function.access_sites[: limits["blocks"]]:
        provenance = "state"
        kind = access.domain
        value = FlowValue(
            f"{function.identity}:{access.path}",
            kind,
            provenance,
            (access.declaration_id,),
            "",
            function.identity,
            (
                access.span.start_byte,
                access.span.end_byte,
                access.span.start_line,
                access.span.end_line,
            ),
        )
        values.append(value)
        if access.kind == "write":
            edges.append(DependencyEdge(access.declaration_id, value.identity, "state-write"))
        else:
            edges.append(DependencyEdge(access.declaration_id, value.identity, "state-read"))
    for name in function.read_write_same_operation:
        edges.append(
            DependencyEdge(
                f"{function.identity}:read:{name}",
                f"{function.identity}:write:{name}",
                "state-read-influences-write",
            )
        )
    for name in function.writes:
        if any(item in name.lower() for item in ("balance", "share", "supply", "asset", "debt")):
            edges.append(DependencyEdge(name, function.identity, "state-read-influences-write"))
    sender = FlowValue(
        f"{function.identity}:msg.sender",
        "msg.sender",
        "attacker",
        (),
        "address",
        function.identity,
    )
    value_msg = FlowValue(
        f"{function.identity}:msg.value", "msg.value", "attacker", (), "uint256", function.identity
    )
    values.extend((sender, value_msg))
    if function.authorization == "guarded":
        edges.append(DependencyEdge(sender.identity, function.identity, "authority"))
    return values, edges


def _delegate_provenance(function: SemanticFunction, target: str) -> str:
    base = re.match(r"([A-Za-z_]\w*)", target.strip())
    name = base.group(1) if base else ""
    if "?" in target:
        return "unknown"
    if target.strip().endswith(")"):
        return "derived"
    if name in function.parameters or name in {"msg", "tx"}:
        return "attacker" if name != "msg" else "attacker"
    if name in function.reads or name in function.writes:
        return "state"
    if re.fullmatch(r"0x[0-9a-fA-F]+", target.strip()):
        return "trusted_constant"
    return "unknown"


def _resolve_internal(
    program: SemanticProgram, function: SemanticFunction, name: str
) -> SemanticFunction | None:
    matches = [
        item
        for item in program.functions
        if item.name == name
        and item.contract == function.contract
        and item.identity != function.identity
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _assets(function: SemanticFunction, values: list[FlowValue]) -> list[AssetFlow]:
    flows: list[AssetFlow] = []
    for site in function.call_sites:
        if site.call_type not in {"transfer", "token", "low-level-call", "send"} and not site.value:
            continue
        source = "contract"
        destination = "external" if site.external else "internal"
        if site.value:
            source = "contract"
            destination = site.target or "external"
        flows.append(
            AssetFlow(
                function.identity,
                source,
                destination,
                site.value or site.arguments[:80],
                tuple(
                    value.identity
                    for value in values
                    if value.provenance in {"attacker", "state", "asset"}
                ),
            )
        )
    return flows
