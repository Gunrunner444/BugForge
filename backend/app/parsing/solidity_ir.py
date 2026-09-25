"""Solidity semantic IR.

Built from the Tree-sitter syntax graph. Compiler IR is attached only when a
compiler profile says it is available. This model is analysis data. It does
not verify findings. Partial coverage stays partial.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.parsing.model import SyntaxEvent, SyntaxGraph

SCHEMA_VERSION = "phase37.1"
_WRITE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\+=|-=|=)")
_READ = re.compile(r"\b([A-Za-z_]\w*)\b")
_SENDER = re.compile(r"\bmsg\.sender\b")
_LOW = frozenset({"call", "delegatecall", "staticcall", "transfer", "send"})


@dataclass(frozen=True)
class SourceSpanRef:
    file: str
    line: int
    end_line: int = 0


@dataclass(frozen=True)
class SemanticFunction:
    contract: str
    name: str
    line: int
    visibility: str
    mutability: str
    modifiers: tuple[str, ...]
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    calls: tuple[str, ...]
    authorization: str
    origin: str = "parser"
    conditional: bool = False

    @property
    def identity(self) -> str:
        return f"{self.contract}.{self.name}:{self.line}"


@dataclass
class SemanticProgram:
    schema_version: str
    file: str
    status: str
    functions: tuple[SemanticFunction, ...]
    state_variables: tuple[str, ...]
    compiler_ir: str
    compiler_ir_status: str
    notes: tuple[str, ...] = ()

    def functions_named(self, name: str, contract: str = "") -> tuple[SemanticFunction, ...]:
        return tuple(
            item
            for item in self.functions
            if item.name == name and (not contract or item.contract == contract)
        )

    def state_writes(self, function: SemanticFunction) -> tuple[str, ...]:
        return function.writes

    def external_calls(self, function: SemanticFunction) -> tuple[str, ...]:
        return function.calls

    def authorization(self, function: SemanticFunction) -> str:
        return function.authorization


def build_semantic_program(
    graph: SyntaxGraph, *, compiler_ir: str = "", compiler_ir_status: str = "unavailable"
) -> SemanticProgram:
    if graph.language != "solidity":
        return SemanticProgram(
            SCHEMA_VERSION, graph.file_path, "unavailable", (), (), "", "unavailable"
        )
    state = _state_names(graph)
    functions = _functions(graph, state)
    status = "partial" if functions else "unavailable"
    ir_status = (
        compiler_ir_status
        if compiler_ir_status
        in {
            "unavailable",
            "available",
            "partial",
            "truncated",
            "failed",
        }
        else "unavailable"
    )
    notes: list[str] = []
    if ir_status != "available":
        notes.append("compiler IR is not available; function facts are parser-originated")
    return SemanticProgram(
        SCHEMA_VERSION,
        graph.file_path,
        status,
        tuple(functions),
        tuple(sorted(state)),
        compiler_ir if ir_status == "available" else "",
        ir_status,
        tuple(notes),
    )


def render_snapshot(program: SemanticProgram) -> str:
    lines = [f"file {program.file}", f"status {program.status}", f"schema {program.schema_version}"]
    by_contract: dict[str, list[SemanticFunction]] = {}
    for item in program.functions:
        by_contract.setdefault(item.contract or "?", []).append(item)
    for contract in sorted(by_contract):
        lines.append(f"Contract {contract}")
        for item in by_contract[contract]:
            lines.append(f"  Function {item.name} line {item.line}")
            lines.append(f"    authorization: {item.authorization}")
            lines.append(f"    reads: {', '.join(item.reads) or '-'}")
            lines.append(f"    writes: {', '.join(item.writes) or '-'}")
            lines.append(f"    calls: {', '.join(item.calls) or '-'}")
            lines.append(f"    origin: {item.origin}")
    lines.append(f"compiler_ir {program.compiler_ir_status}")
    return "\n".join(lines)


def _state_names(graph: SyntaxGraph) -> set[str]:
    names: set[str] = set()
    for event in graph.events:
        if event.kind != "sol_state":
            continue
        name = _extra(event).get("name", "")
        if name:
            names.add(name)
    return names


def _functions(graph: SyntaxGraph, state: set[str]) -> list[SemanticFunction]:
    found: list[SemanticFunction] = []
    for event in graph.events:
        if event.kind != "sol_function" or len(found) >= 200:
            continue
        fields = _extra(event)
        name = _function_name(event)
        if not name:
            continue
        writes = tuple(sorted(name for name in _WRITE.findall(event.text) if name in state))
        reads = tuple(
            sorted(
                name
                for name in set(_READ.findall(event.text))
                if name in state and name not in writes
            )
        )
        calls = tuple(item for item in sorted(_LOW) if re.search(rf"\.{item}\s*\(", event.text))
        modifiers = tuple(
            part.strip() for part in fields.get("modifiers", "").split(",") if part.strip()
        )
        authorization = "unknown"
        if any(part.lower().startswith("only") for part in modifiers):
            authorization = "guarded"
        elif _SENDER.search(event.text) and re.search(r"\brequire\s*\(", event.text):
            authorization = "guarded"
        elif fields.get("visibility") in {"public", "external"}:
            authorization = "unguarded"
        found.append(
            SemanticFunction(
                contract=fields.get("contract", ""),
                name=name,
                line=event.line,
                visibility=fields.get("visibility", ""),
                mutability=fields.get("mutability", ""),
                modifiers=modifiers,
                reads=reads,
                writes=writes,
                calls=calls,
                authorization=authorization,
                conditional="if " in event.text or "require" in event.text,
            )
        )
    return found


def _function_name(event: SyntaxEvent) -> str:
    match = re.search(r"function\s+([A-Za-z_]\w*)", event.text)
    return match.group(1) if match else ""


def _extra(event: SyntaxEvent) -> dict[str, str]:
    fields: dict[str, str] = {}
    raw = event.extra if isinstance(event.extra, str) else ""
    for part in raw.split("|"):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    return fields
