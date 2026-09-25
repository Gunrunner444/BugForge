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
    may_read_before: tuple[tuple[str, str], ...] = ()
    may_write_after: tuple[tuple[str, str], ...] = ()
    cfg_iterations: int = 0


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
        if summary is None or not call_id:
            return ()
        return tuple(path for call, path in summary.may_read_before if call == call_id)

    def writes_after_call(self, function: str, call_id: str) -> tuple[str, ...]:
        summary = self._summary(function)
        if summary is None or not call_id:
            return ()
        return tuple(path for call, path in summary.may_write_after if call == call_id)

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
    model.status = "partial" if model.incomplete_reason else "available"
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
    cyclic = function.identity in stack
    incomplete = depth > limits["depth"] or cyclic
    reason = ""
    if cyclic:
        reason = "cyclic call"
    elif depth > limits["depth"]:
        reason = "call depth limit reached"
    values: list[FlowValue] = []
    edges: list[DependencyEdge] = []
    cfg_iterations = 0
    may_read_before: tuple[tuple[str, str], ...] = ()
    may_write_after: tuple[tuple[str, str], ...] = ()
    if not incomplete:
        values, edges, may_read_before, may_write_after, cfg_iterations = _intraprocedural(
            function, limits
        )
        if cfg_iterations < 0:
            incomplete = True
            reason = reason or "CFG block limit reached"
        elif cfg_iterations >= limits["iterations"] and _has_loop(function):
            incomplete = True
            reason = reason or "fixed-point iteration limit reached"
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
                provenance = _delegate_provenance(program, function, site.target)
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
        may_read_before=may_read_before,
        may_write_after=may_write_after,
        cfg_iterations=cfg_iterations,
    )
    model.summaries[function.identity] = summary
    model.edges = tuple([*model.edges, *edges])[: limits["edges"]]
    return summary


def _intraprocedural(
    function: SemanticFunction, limits: dict[str, int]
) -> tuple[
    list[FlowValue],
    list[DependencyEdge],
    tuple[tuple[str, str], ...],
    tuple[tuple[str, str], ...],
    int,
]:
    from app.parsing.solidity_cfg import build_function_cfg

    values: list[FlowValue] = []
    edges: list[DependencyEdge] = []
    known: set[str] = set()
    cfg = build_function_cfg(function.source or "")
    if len(cfg.nodes) > limits["blocks"]:
        return values, edges, (), (), -1
    environments: dict[int, dict[str, str]] = {node.node_id: {} for node in cfg.nodes}
    iterations = 0
    for iterations in range(1, limits["iterations"] + 1):
        changed = False
        for node in cfg.nodes:
            incoming: dict[str, str] = {}
            for src, dst, _label in cfg.edges:
                if dst == node.node_id:
                    incoming.update(environments.get(src, {}))
            outgoing = dict(incoming)
            for match in re.finditer(
                r"(?:uint\d*|int\d*|address|bool)\s+([A-Za-z_]\w*)\s*=\s*([^;]+)",
                node.text,
            ):
                local, expr = match.group(1), match.group(2)
                identity = f"{function.identity}:local:{local}:{node.node_id}"
                names = re.findall(r"\b([A-Za-z_]\w*)\b", expr)
                deps = tuple(incoming[name] for name in names if name in incoming)
                state_deps = tuple(
                    item.operation_id
                    for item in function.access_sites
                    if item.kind != "write" and item.symbol in names and item.path in expr
                )
                deps = tuple(dict.fromkeys((*deps, *state_deps)))
                _add_value(
                    values,
                    known,
                    identity,
                    "local",
                    _join_provenance(deps, values, expr, function),
                    deps,
                    function,
                )
                for dep in deps:
                    edges.append(DependencyEdge(dep, identity, "local-dependency"))
                outgoing[local] = identity
            store = re.search(
                r"\b([A-Za-z_]\w*(?:\[[^\]]+\])?(?:\.\w+)?)\s*=\s*([A-Za-z_]\w*)\s*;",
                node.text,
            )
            if store and store.group(2) in outgoing:
                for item in function.access_sites:
                    if item.kind != "read" and item.path == store.group(1):
                        edges.append(
                            DependencyEdge(
                                outgoing[store.group(2)],
                                item.operation_id,
                                "local-to-state",
                            )
                        )
            if outgoing != environments[node.node_id]:
                environments[node.node_id] = outgoing
                changed = True
        if not changed:
            break
    for access in function.access_sites:
        if len(values) >= limits["values"]:
            break
        _add_value(
            values,
            known,
            access.operation_id,
            access.kind,
            "state",
            (access.declaration_id,),
            function,
            (
                access.span.start_byte,
                access.span.end_byte,
                access.span.start_line,
                access.span.end_line,
            ),
        )
        _add_value(values, known, access.declaration_id, "declaration", "state", (), function)
        kind = "state-write" if access.kind != "read" else "state-read"
        edges.append(DependencyEdge(access.declaration_id, access.operation_id, kind))
    by_path: dict[str, list[str]] = {}
    for access in function.access_sites:
        by_path.setdefault(access.path, []).append(access.operation_id)
    for access in function.access_sites:
        if access.kind == "read":
            continue
        reads = [
            item.operation_id
            for item in function.access_sites
            if item.path == access.path
            and item.kind != "write"
            and item.operation_id != access.operation_id
        ]
        for read_id in reads:
            if abs(int(read_id.rsplit(":", 1)[-1] or 0) - access.span.start_byte) < 200:
                edges.append(
                    DependencyEdge(read_id, access.operation_id, "state-read-influences-write")
                )
    sender = f"{function.identity}:msg.sender:{function.line}"
    _add_value(values, known, sender, "msg.sender", "attacker", (), function)
    if function.authorization == "guarded":
        guard = f"{function.identity}:authority:{function.line}"
        _add_value(values, known, guard, "authority", "authority", (sender,), function)
        edges.append(DependencyEdge(sender, guard, "authority"))
    may_read: list[tuple[str, str]] = []
    may_write: list[tuple[str, str]] = []
    if cfg.known:
        for site in function.call_sites:
            call_node = _node_for_offset(cfg, function, site.span.start_byte)
            if call_node is None:
                continue
            before = {
                node.node_id for node in cfg.nodes if call_node in cfg.reachable_from(node.node_id)
            }
            after = cfg.reachable_from(call_node)
            for access in function.access_sites:
                home = _cfg_home(cfg, access.path, access.kind)
                if home is None:
                    continue
                if access.kind != "write" and home in before and home != call_node:
                    may_read.append((site.call_id, access.path))
                if access.kind != "read" and home in after and home != call_node:
                    may_write.append((site.call_id, access.path))
    edges = [edge for edge in edges if edge.source in known and edge.sink in known]
    del by_path
    return values, edges, tuple(may_read), tuple(may_write), iterations


def _add_value(
    values: list[FlowValue],
    known: set[str],
    identity: str,
    kind: str,
    provenance: str,
    deps: tuple[str, ...],
    function: SemanticFunction,
    span: tuple[int, int, int, int] = (0, 0, 0, 0),
) -> None:
    if identity in known:
        return
    known.add(identity)
    values.append(FlowValue(identity, kind, provenance, deps, "", function.identity, span))


def _expr_provenance(expr: str, function: SemanticFunction) -> str:
    del expr, function
    return "derived"


def _join_provenance(
    deps: tuple[str, ...], values: list[FlowValue], expr: str, function: SemanticFunction
) -> str:
    del expr, function
    known = {item.identity: item.provenance for item in values}
    found = {known[item] for item in deps if item in known}
    if not found:
        return "unknown" if deps else "derived"
    if "attacker" in found:
        return "attacker"
    if "unknown" in found:
        return "unknown"
    if len(found) == 1:
        return next(iter(found))
    return "derived"


def _node_for_offset(cfg: object, function: SemanticFunction, start_byte: int) -> int | None:
    source = function.source or ""
    base = function.span[0] if function.span else 0
    local = start_byte - base
    cursor = 0
    for node in getattr(cfg, "nodes", []):
        text = str(node.text).strip()
        if not text:
            continue
        at = source.find(text, cursor)
        if at < 0:
            continue
        if at <= local < at + len(text) + 2:
            return int(node.node_id)
        cursor = at
    return None


def _cfg_home(cfg: object, path: str, kind: str) -> int | None:
    nodes = getattr(cfg, "nodes", [])
    candidates = [node for node in nodes if path in node.text]
    assignment = re.compile(rf"{re.escape(path)}\s*(?:=|\+=|-=)")
    if kind != "read":
        writers = [node for node in candidates if assignment.search(node.text)]
        if len(writers) == 1:
            return int(writers[0].node_id)
    readers = [node for node in candidates if not assignment.search(node.text)]
    if len(readers) == 1:
        return int(readers[0].node_id)
    if len(candidates) == 1:
        return int(candidates[0].node_id)
    return None


def _has_loop(function: SemanticFunction) -> bool:
    return bool(re.search(r"\b(for|while|do)\b", function.source))


def _delegate_provenance(program: SemanticProgram, function: SemanticFunction, target: str) -> str:
    base = re.match(r"([A-Za-z_]\w*)", target.strip())
    name = base.group(1) if base else ""
    if "?" in target:
        return "unknown"
    if target.strip().endswith(")"):
        callee = _resolve_internal(program, function, name) if name else None
        returned = re.search(r"return\s+([A-Za-z_]\w*)", callee.source) if callee else None
        if (
            callee is not None
            and returned
            and returned.group(1) in set(callee.reads) | set(callee.writes)
        ):
            return "state"
        return "derived" if callee else "unknown"
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
        relevant = f"{site.target} {site.value}"
        flows.append(
            AssetFlow(
                function.identity,
                source,
                destination,
                site.value or site.arguments[:80],
                tuple(
                    value.identity
                    for value in values
                    if value.identity in relevant
                    or any(part and part in relevant for part in value.identity.split(":"))
                )[:8],
            )
        )
    return flows
