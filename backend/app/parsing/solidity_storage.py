"""Parser storage layout, with an optional compiler overlay.

Slots computed here follow Solidity's packing rules only when every type and
every base is known. Ambiguous inheritance, an unknown type, or a missing
imported base leaves the slot unknown. A compiler layout is evidence from
that compiler. It does not replace the parser layout, and a disagreement is
kept rather than silently resolved. Nothing here is a compiler proof.
"""

from __future__ import annotations

import re
from contextvars import ContextVar, Token
from dataclasses import dataclass, field

from app.parsing.model import SyntaxGraph
from app.parsing.solidity_cfg import _consume_parens
from app.parsing.solidity_compiler import CompilerSemantics

_CTX: ContextVar[_StorageContext | None] = ContextVar("bugforge_storage_context", default=None)
_ELEM = {
    "bool": 1,
    "byte": 1,
    "address": 20,
    "uint": 32,
    "int": 32,
    "string": None,
    "bytes": None,
}


@dataclass(frozen=True)
class StorageVariable:
    contract: str
    name: str
    type_name: str
    slot: int | None
    offset: int | None
    packing_group: int | None
    visibility: str
    mutability: str
    origin: str
    key_type: str = ""
    value_type: str = ""
    members: tuple[str, ...] = ()
    uncertain: bool = False


@dataclass(frozen=True)
class YulAccess:
    contract: str
    function: str
    op: str
    expression: str
    known: bool
    literal: str = ""
    constant: str = ""


@dataclass(frozen=True)
class LayoutDisagreement:
    contract: str
    name: str
    parser_slot: str
    compiler_slot: str


@dataclass
class StorageModel:
    variables: list[StorageVariable] = field(default_factory=list)
    order: dict[str, tuple[str, ...]] = field(default_factory=dict)
    uncertain: dict[str, str] = field(default_factory=dict)
    yul: list[YulAccess] = field(default_factory=list)
    disagreements: list[LayoutDisagreement] = field(default_factory=list)
    compiler_status: str = ""
    overlaps: list[str] = field(default_factory=list)


@dataclass
class _ContractFacts:
    file_path: str
    bases: list[str]
    variables: list[tuple[str, str, str, str]]
    structs: dict[str, tuple[str, ...]]


@dataclass
class _StorageContext:
    facts: dict[str, _ContractFacts]
    ambiguous: set[str]
    cache: dict[int, StorageModel]


def set_storage_context(graphs: dict[str, SyntaxGraph]) -> Token[_StorageContext | None]:
    facts: dict[str, _ContractFacts] = {}
    ambiguous: set[str] = set()
    for graph in graphs.values():
        if graph.language != "solidity":
            continue
        for name, fact in _facts(graph).items():
            if name in facts:
                ambiguous.add(name)
            else:
                facts[name] = fact
    for name in ambiguous:
        facts.pop(name, None)
    return _CTX.set(_StorageContext(facts, ambiguous, {}))


def reset_storage_context(token: Token[_StorageContext | None]) -> None:
    _CTX.reset(token)


def storage_context_active() -> bool:
    return _CTX.get() is not None


def analyze_storage(graph: SyntaxGraph) -> StorageModel:
    """Return the parser layout for ``graph``.

    A scan-level cache is used when the engine has installed one. Direct
    calls recompute. Compiler facts are not invented here.
    """
    ctx = _CTX.get()
    if ctx is not None and id(graph) in ctx.cache:
        return ctx.cache[id(graph)]
    model = _analyze(graph, ctx)
    if ctx is not None:
        ctx.cache[id(graph)] = model
    return model


def apply_compiler_layout(model: StorageModel, compiler: CompilerSemantics) -> StorageModel:
    """Record compiler slots beside the parser layout.

    Unavailable, failed, and version-only compiler results do not create
    slots. A label whose parser slot differs from the compiler slot is a
    disagreement. Neither side is discarded.
    """
    model.compiler_status = compiler.status
    if compiler.status != "AVAILABLE":
        return model
    by_label = {item["label"]: item for item in compiler.layouts} or {
        item["label"]: item for item in compiler.storage
    }
    for variable in model.variables:
        if variable.uncertain or variable.slot is None:
            continue
        compiler_item = by_label.get(variable.name)
        if compiler_item is None:
            continue
        if compiler_item.get("contract") not in {None, "", variable.contract, variable.origin}:
            continue
        if str(variable.slot) != compiler_item.get("slot", ""):
            model.disagreements.append(
                LayoutDisagreement(
                    variable.contract,
                    variable.name,
                    str(variable.slot),
                    compiler_item.get("slot", ""),
                )
            )
    return model


def _analyze(graph: SyntaxGraph, ctx: _StorageContext | None) -> StorageModel:
    model = StorageModel()
    if graph.language != "solidity" or graph.parser_tier.value == "profile_fallback":
        return model
    local = _facts(graph)
    facts = dict(ctx.facts) if ctx is not None else {}
    ambiguous = set(ctx.ambiguous) if ctx is not None else set()
    for name, fact in local.items():
        if name in ambiguous:
            continue
        facts.setdefault(name, fact)
    for contract, fact in local.items():
        if contract in ambiguous:
            model.uncertain[contract] = "more than one contract uses this name"
            model.variables.extend(_unplaced(fact, contract))
            continue
        order, reason = _linearize(contract, facts, ambiguous)
        if order is None:
            model.uncertain[contract] = reason
            model.order[contract] = ()
            model.variables.extend(_unplaced(fact, contract))
            continue
        model.order[contract] = tuple(order)
        placed, uncertain = _place(order, facts)
        if uncertain:
            model.uncertain[contract] = uncertain
            model.variables.extend(_unplaced_order(order, facts))
        else:
            model.variables.extend(placed)
    model.yul = _yul_accesses(graph, local)
    model.overlaps = _overlaps(graph, model)
    return model


def _facts(graph: SyntaxGraph) -> dict[str, _ContractFacts]:
    bases: dict[str, list[str]] = {}
    variables: dict[str, list[tuple[str, str, str, str]]] = {}
    structs: dict[str, tuple[str, ...]] = {}
    struct_conflict: set[str] = set()
    for event in graph.events:
        if event.kind == "sol_contract":
            fields = _fields(event.extra)
            name = event.text.strip()
            raw = [item.strip() for item in fields.get("bases", "").split(",") if item.strip()]
            bases[name] = list(reversed(raw))
            variables.setdefault(name, [])
        elif event.kind == "sol_state":
            fields = _fields(event.extra)
            contract = fields.get("contract", "")
            variables.setdefault(contract, []).append(
                (
                    fields.get("name", ""),
                    fields.get("type", ""),
                    fields.get("mutability", "storage"),
                    _visibility(event.text),
                )
            )
        elif event.kind == "sol_type_def" and _fields(event.extra).get("kind") == "struct":
            fields = _fields(event.extra)
            name = fields.get("name", "")
            members = _abi_members(fields.get("abi", ""))
            if not name or not members:
                continue
            if name in structs and structs[name] != members:
                struct_conflict.add(name)
            else:
                structs[name] = members
    for name in struct_conflict:
        structs.pop(name, None)
    return {
        name: _ContractFacts(graph.file_path, bases.get(name, []), variables.get(name, []), structs)
        for name in set(bases) | set(variables)
    }


def _linearize(
    contract: str, facts: dict[str, _ContractFacts], ambiguous: set[str]
) -> tuple[list[str] | None, str]:
    def merge(sequences: list[list[str]]) -> list[str] | None:
        pending = [list(item) for item in sequences if item]
        result: list[str] = []
        while any(pending):
            chosen = ""
            for sequence in pending:
                if not sequence:
                    continue
                head = sequence[0]
                if any(head in tail[1:] for tail in pending if tail):
                    continue
                chosen = head
                break
            if not chosen:
                return None
            result.append(chosen)
            for sequence in pending:
                if sequence and sequence[0] == chosen:
                    del sequence[0]
        return result

    memo: dict[str, list[str]] = {}
    stack: set[str] = set()

    def walk(name: str) -> list[str] | None:
        if name in memo:
            return memo[name]
        if name in stack or name in ambiguous or name not in facts:
            return None
        stack.add(name)
        fact = facts[name]
        sequences: list[list[str]] = []
        for base in fact.bases:
            if base in ambiguous or base not in facts:
                stack.remove(name)
                return None
            base_order = walk(base)
            if base_order is None:
                stack.remove(name)
                return None
            sequences.append(base_order)
        sequences.append(list(fact.bases))
        merged = merge(sequences)
        stack.remove(name)
        if merged is None:
            return None
        memo[name] = merged + [name]
        return memo[name]

    order = walk(contract)
    if order is None:
        return None, "a base contract is missing, duplicated, or the inheritance order is ambiguous"
    return order, ""


def _place(order: list[str], facts: dict[str, _ContractFacts]) -> tuple[list[StorageVariable], str]:
    structs: dict[str, tuple[str, ...]] = {}
    for name in order:
        structs.update(facts[name].structs)
    slot = 0
    offset = 0
    group = 0
    placed: list[StorageVariable] = []

    def bump() -> None:
        nonlocal slot, offset, group
        if offset:
            slot += 1
            offset = 0
            group += 1

    def pack(size: int) -> tuple[int, int, int]:
        nonlocal slot, offset
        if offset + size > 32:
            bump()
        chosen = slot, offset, group
        offset += size
        if offset == 32:
            bump()
        return chosen

    for name in order:
        for var_name, type_name, mutability, visibility in facts[name].variables:
            if mutability in {"constant", "immutable"}:
                placed.append(
                    StorageVariable(
                        name,
                        var_name,
                        type_name,
                        None,
                        None,
                        None,
                        visibility,
                        mutability,
                        name,
                    )
                )
                continue
            kind, detail = _classify(type_name, structs)
            if kind == "unknown":
                return [], f"`{var_name}` has type `{type_name}`, which does not determine a slot"
            if kind in {"mapping", "dynamic", "dynamic_array"}:
                bump()
                key_type, value_type = detail if isinstance(detail, tuple) else ("", "")
                placed.append(
                    StorageVariable(
                        name,
                        var_name,
                        type_name,
                        slot,
                        0,
                        group,
                        visibility,
                        mutability,
                        name,
                        key_type=key_type,
                        value_type=value_type,
                    )
                )
                slot += 1
                offset = 0
                group += 1
                continue
            if kind == "elementary" and isinstance(detail, int):
                var_slot, var_offset, var_group = pack(detail)
                placed.append(
                    StorageVariable(
                        name,
                        var_name,
                        type_name,
                        var_slot,
                        var_offset,
                        var_group,
                        visibility,
                        mutability,
                        name,
                    )
                )
                continue
            if kind == "struct":
                members = structs.get(str(detail), ())
                sizes = [_elementary_size(item) for item in members]
                if any(size is None for size in sizes):
                    return [], f"struct `{detail}` is not packed from elementary members"
                bump()
                start = slot
                start_group = group
                for size in sizes:
                    assert size is not None
                    pack(size)
                bump()
                placed.append(
                    StorageVariable(
                        name,
                        var_name,
                        type_name,
                        start,
                        0,
                        start_group,
                        visibility,
                        mutability,
                        name,
                        members=members,
                    )
                )
                continue
            if kind == "fixed_array":
                count, inner = detail if isinstance(detail, tuple) else (0, "")
                inner_size = _elementary_size(str(inner))
                if inner_size is None or not isinstance(count, int):
                    return [], f"`{var_name}` is a fixed array whose element size is unknown"
                bump()
                start = slot
                start_group = group
                for _ in range(count):
                    pack(inner_size)
                bump()
                placed.append(
                    StorageVariable(
                        name,
                        var_name,
                        type_name,
                        start,
                        0,
                        start_group,
                        visibility,
                        mutability,
                        name,
                    )
                )
    return placed, ""


def _classify(type_name: str, structs: dict[str, tuple[str, ...]]) -> tuple[str, object]:
    compact = re.sub(r"\s+", "", type_name)
    if compact.startswith("mapping(") and compact.endswith(")"):
        body = compact[len("mapping(") : -1]
        key, value = _split_mapping(body)
        return "mapping", (key, value)
    if compact.endswith("[]"):
        return "dynamic_array", compact[:-2]
    fixed = re.fullmatch(r"(.+)\[(\d+)\]", compact)
    if fixed:
        return "fixed_array", (int(fixed.group(2)), fixed.group(1))
    if compact in {"string", "bytes"}:
        return "dynamic", ""
    size = _elementary_size(compact)
    if size is not None:
        return "elementary", size
    ident = re.fullmatch(r"[A-Za-z_]\w*", compact)
    if ident and ident.group(0) in structs:
        return "struct", ident.group(0)
    return "unknown", ""


def _elementary_size(type_name: str) -> int | None:
    compact = re.sub(r"\s+", "", type_name)
    if compact in _ELEM and _ELEM[compact] is not None:
        return _ELEM[compact]
    match = re.fullmatch(r"uint(\d+)|int(\d+)|bytes(\d+)", compact)
    if not match:
        return None
    if match.group(3):
        width = int(match.group(3))
        return width if 1 <= width <= 32 else None
    bits = int(match.group(1) or match.group(2))
    if bits % 8 or not 8 <= bits <= 256:
        return None
    return bits // 8


def _split_mapping(body: str) -> tuple[str, str]:
    depth = 0
    for index, char in enumerate(body):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif body.startswith("=>", index) and depth == 0:
            return body[:index], body[index + 2 :]
    return body, ""


def _unplaced(fact: _ContractFacts, contract: str) -> list[StorageVariable]:
    return [
        StorageVariable(
            contract,
            name,
            type_name,
            None,
            None,
            None,
            visibility,
            mutability,
            contract,
            uncertain=True,
        )
        for name, type_name, mutability, visibility in fact.variables
    ]


def _unplaced_order(order: list[str], facts: dict[str, _ContractFacts]) -> list[StorageVariable]:
    found: list[StorageVariable] = []
    for name in order:
        found.extend(_unplaced(facts[name], name))
    return found


def _overlaps(graph: SyntaxGraph, model: StorageModel) -> list[str]:
    delegate_contracts = {
        _fields(event.extra).get("contract", "")
        for event in graph.events
        if event.kind == "sol_delegatecall"
    }
    if not delegate_contracts:
        return []
    certain = [
        item
        for item in model.variables
        if item.slot is not None and not item.uncertain and item.mutability == "storage"
    ]
    notes: list[str] = []
    for proxy in sorted(delegate_contracts):
        proxy_slots = {item.slot: item for item in certain if item.contract == proxy}
        if not proxy_slots:
            continue
        others = {item.contract for item in certain if item.contract != proxy}
        for other in sorted(others):
            for item in certain:
                if item.contract != other or item.slot not in proxy_slots:
                    continue
                left = proxy_slots[item.slot]
                notes.append(
                    f"Parser layout places `{left.contract}.{left.name}` and "
                    f"`{item.contract}.{item.name}` in slot {item.slot}. "
                    "This is potential evidence of a proxy/implementation overlap, "
                    "not a confirmed collision."
                )
    return list(dict.fromkeys(notes))


def _yul_accesses(graph: SyntaxGraph, facts: dict[str, _ContractFacts]) -> list[YulAccess]:
    del facts
    declarations: dict[str, str] = {}
    for event in graph.events:
        if event.kind != "sol_state":
            continue
        fields = _fields(event.extra)
        if fields.get("mutability") == "constant":
            matched = re.search(r"=\s*(0x[0-9a-fA-F]+|\d+)\s*;", event.text)
            declarations[fields.get("name", "")] = matched.group(1) if matched else ""
    found: list[YulAccess] = []
    for event in graph.events:
        if event.kind != "sol_function":
            continue
        fields = _fields(event.extra)
        for block in _assembly_blocks(event.text):
            for op, args in _yul_calls(block):
                expression = (
                    args[1] if op == "delegatecall" and len(args) > 1 else (args[0] if args else "")
                )
                constant = expression if re.fullmatch(r"[A-Za-z_]\w*", expression) else ""
                slot_literal = ""
                known = False
                if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", expression):
                    slot_literal = expression
                    known = True
                elif constant and declarations.get(constant):
                    slot_literal = declarations[constant]
                    known = True
                found.append(
                    YulAccess(
                        fields.get("contract", ""),
                        fields.get("function", ""),
                        op,
                        expression,
                        known,
                        slot_literal,
                        constant if constant in declarations else "",
                    )
                )
    return found


def _yul_calls(block: str) -> list[tuple[str, list[str]]]:
    found: list[tuple[str, list[str]]] = []
    index = 0
    while index < len(block):
        match = re.search(r"\b(sload|sstore|delegatecall)\s*\(", block[index:])
        if match is None:
            break
        open_at = index + match.end() - 1
        try:
            end = _consume_parens(block, open_at)
        except ValueError:
            break
        inner = block[open_at + 1 : end - 1]
        args = _split_args(inner)
        found.append((match.group(1), args))
        index = end
    return found


def _split_args(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _assembly_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    index = 0
    while True:
        found = re.search(r"\bassembly\s*\{", text[index:])
        if not found:
            break
        open_at = index + found.end() - 1
        depth = 0
        cursor = open_at
        while cursor < len(text):
            if text[cursor] == "{":
                depth += 1
            elif text[cursor] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(text[open_at + 1 : cursor])
                    index = cursor + 1
                    break
            cursor += 1
        else:
            break
    return blocks


def _abi_members(abi: str) -> tuple[str, ...]:
    body = abi.strip()
    if not (body.startswith("(") and body.endswith(")")):
        return ()
    parts = [item.strip() for item in body[1:-1].split(",") if item.strip()]
    return tuple(parts)


def _visibility(text: str) -> str:
    for word in ("public", "private", "internal"):
        if re.search(rf"\b{word}\b", text):
            return word
    return "internal"


def _fields(extra: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in extra.split("|"):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    return fields
