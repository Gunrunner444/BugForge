"""Project-level security properties over semantic dataflow.

Results are static observations. They do not verify findings. Unknown and
incomplete stay unknown. A property that finds nothing is not proof of safety.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.parsing.solidity_dataflow import DataflowModel, analyze_dataflow
from app.parsing.solidity_ir import SemanticFunction, SemanticProgram


@dataclass(frozen=True)
class PropertyResult:
    status: str
    confidence: str
    summary: str
    provenance: str = "unknown"
    spans: tuple[tuple[int, int], ...] = ()
    dependencies: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()
    incomplete_reason: str = ""
    function_ids: tuple[str, ...] = ()
    call_ids: tuple[str, ...] = ()


def analyze_reentrancy(program: SemanticProgram, function_id: str) -> PropertyResult:
    flow = analyze_dataflow(program)
    summary = flow._summary(function_id)
    if summary is None:
        return PropertyResult(
            "unknown", "low", "function was not resolved", function_ids=(function_id,)
        )
    if summary.incomplete:
        return PropertyResult(
            "incomplete",
            "low",
            "reentrancy analysis is incomplete",
            incomplete_reason=summary.incomplete_reason,
            function_ids=(summary.identity,),
        )
    hits = _dependent_reentrancy(flow, summary)
    if not hits:
        return PropertyResult(
            "unknown",
            "low",
            "no state read was shown to reach a later write through a call",
            function_ids=(summary.identity,),
        )
    call, read_id, write_id = hits[0]
    return PropertyResult(
        "potential",
        "medium",
        "a state read reaches a write after an external call",
        provenance="state",
        dependencies=(read_id, write_id),
        function_ids=(summary.identity,),
        call_ids=(call,),
    )


def analyze_authorization(program: SemanticProgram, function_id: str) -> PropertyResult:
    function = _one(program, function_id)
    if function is None:
        return PropertyResult("unknown", "low", "function was not resolved")
    writes = [item for item in function.access_sites if item.kind != "read"]
    if not writes:
        return PropertyResult(
            "unknown", "low", "no sensitive store was identified", function_ids=(function.identity,)
        )
    statuses = {item.guard_status for item in writes}
    if statuses == {"guarded"}:
        status = "satisfied"
    elif "unguarded" in statuses:
        status = "potential"
    else:
        status = "unknown"
    return PropertyResult(
        status,
        "medium" if status == "potential" else "low",
        f"authorization is {function.authorization}",
        provenance="authority",
        function_ids=(function.identity,),
    )


def analyze_delegatecall(
    program: SemanticProgram, function_id: str, call_id: str = ""
) -> PropertyResult:
    flow = analyze_dataflow(program)
    provenance = flow.target_provenance(function_id, call_id)
    if provenance == "unknown":
        return PropertyResult(
            "unknown", "low", "delegatecall target was not resolved", provenance=provenance
        )
    status = "potential" if provenance == "attacker" else "unknown"
    return PropertyResult(
        status,
        "medium" if status == "potential" else "low",
        f"delegatecall target provenance is {provenance}",
        provenance=provenance,
        function_ids=(_identity(flow, function_id),),
    )


def analyze_asset_flow(program: SemanticProgram, function_id: str) -> PropertyResult:
    flow = analyze_dataflow(program)
    summary = flow._summary(function_id)
    if summary is None or not summary.asset_flows:
        return PropertyResult("unknown", "low", "no asset flow was resolved")
    flow_item = summary.asset_flows[0]
    return PropertyResult(
        "unknown",
        "low",
        f"asset flow observed from {flow_item.source} to {flow_item.destination}",
        dependencies=flow_item.dependencies,
        function_ids=(summary.identity,),
    )


def _dependent_reentrancy(flow: DataflowModel, summary: object) -> list[tuple[str, str, str]]:
    reads = getattr(summary, "may_read_before", ())
    writes = getattr(summary, "may_write_after", ())
    found: list[tuple[str, str, str]] = []
    for call, write_path in writes:
        read_paths = {path for item_call, path in reads if item_call == call}
        read_ids = _ops(flow, {"read", "read-modify-write"}, read_paths)
        write_ids = _ops(flow, {"write", "read-modify-write"}, {write_path})
        for read_id in read_ids:
            if _reaches(flow, read_id, set(write_ids)):
                found.append((call, read_id, next(iter(write_ids))))
                break
    return found


def _ops(flow: DataflowModel, kinds: set[str], paths: set[str]) -> list[str]:
    found: list[str] = []
    for value in flow.values.values():
        if value.kind not in kinds:
            continue
        if any(f"::{path}:" in value.identity for path in paths):
            found.append(value.identity)
    return found


def _reaches(flow: DataflowModel, source: str, sinks: set[str]) -> bool:
    seen: set[str] = set()
    stack = [source]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        if current in sinks and current != source:
            return True
        stack.extend(edge.sink for edge in flow.edges if edge.source == current)
    return False


def graph_edges_are_connected(flow: DataflowModel) -> bool:
    known = set(flow.values)
    return all(edge.source in known and edge.sink in known for edge in flow.edges)


def _one(program: SemanticProgram, function_id: str) -> SemanticFunction | None:
    exact = [item for item in program.functions if item.identity == function_id]
    if len(exact) == 1:
        return exact[0]
    named = [item for item in program.functions if item.name == function_id]
    if len(named) == 1:
        return named[0]
    return None


def _identity(flow: DataflowModel, function_id: str) -> str:
    summary = flow._summary(function_id)
    return summary.identity if summary else function_id
