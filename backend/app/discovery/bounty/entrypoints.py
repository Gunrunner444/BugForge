"""Exposed entrypoints that reach a semantic candidate.

A detector may name an internal helper whose parameters are not ABI values, such as
a storage reference. The harness can only call a public or external function. This
module walks resolved calls backward from the helper to those functions.

The walk is structural. It uses the research model's functions and the existing
call splitters. It does not match project names, and it does not treat an
unresolved, ambiguous, or truncated path as proof that the helper is safe or
unreachable in the deployed bytecode. A path that is found names the source
location of every followed call.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass

from app.parsing.solidity_research import (
    ResearchModel,
    RFunction,
    match_close,
    member_calls,
    plain_calls,
    split_top,
)

MAX_DEPTH = 8
MAX_VISITS = 128
MAX_PATHS = 4
_MAX_NOTES = 24


@dataclass(frozen=True)
class CallEdge:
    """One resolved call, from its caller toward the candidate."""

    caller: str
    callee: str
    file: str
    line: int
    arguments: tuple[str, ...]
    # (callee parameter, caller parameter) when the argument is that parameter.
    forwarded: tuple[tuple[str, str], ...] = ()
    flow: tuple[str, ...] = ()


@dataclass(frozen=True)
class EntrypointPath:
    """An exposed function and the ordered calls from it to the candidate."""

    entry_contract: str
    entry_signature: str
    edges: tuple[CallEdge, ...]
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class EntrypointResult:
    """Paths that source structure supports, plus every limit the walk hit.

    ``directly_executable`` means the candidate itself is the call the harness
    would make. No caller was substituted for it.
    """

    paths: tuple[EntrypointPath, ...]
    incomplete: tuple[str, ...]
    truncated: bool
    directly_executable: bool


def entrypoints_for(model: ResearchModel, function: RFunction) -> EntrypointResult:
    """Exposed ABI-callable functions that reach ``function``, nearest structure first."""
    if _is_entry(model, function):
        return EntrypointResult(
            (EntrypointPath(function.contract, function.signature, ()),),
            (),
            False,
            True,
        )
    callers, notes = _caller_index(model, function.name)
    found: list[EntrypointPath] = []
    truncated = False
    visits = 0
    queue: deque[tuple[RFunction, tuple[CallEdge, ...], int, frozenset[str]]] = deque()
    queue.append((function, (), 0, frozenset({function.identity})))
    while queue:
        current, back, depth, seen = queue.popleft()
        visits += 1
        if visits > MAX_VISITS:
            truncated = True
            notes.append(f"visit limit {MAX_VISITS} reached before every caller was walked")
            break
        if current.identity != function.identity and _is_entry(model, current):
            found.append(
                EntrypointPath(
                    current.contract,
                    current.signature,
                    tuple(reversed(back)),
                )
            )
            continue
        sites = callers.get(current.identity, ())
        if not sites:
            if current.identity == function.identity:
                notes.append(f"no resolved caller reaches {current.identity}")
            continue
        for caller, edge in sites:
            if caller.identity in seen:
                notes.append(f"cycle at {caller.identity} -> {edge.callee}; that branch stops")
                continue
            if depth + 1 > MAX_DEPTH:
                truncated = True
                notes.append(
                    f"depth limit {MAX_DEPTH} reached at {caller.identity} -> {edge.callee}"
                )
                continue
            queue.append((caller, (*back, edge), depth + 1, seen | {caller.identity}))
    found.sort(key=lambda item: (item.entry_contract, item.entry_signature, _path_key(item)))
    unique: list[EntrypointPath] = []
    seen_paths: set[tuple[str, tuple[str, ...]]] = set()
    for path in found:
        key = (f"{path.entry_contract}.{path.entry_signature}", _path_key(path))
        if key in seen_paths:
            continue
        seen_paths.add(key)
        unique.append(path)
    if len(unique) > MAX_PATHS:
        truncated = True
        notes.append(f"{len(unique) - MAX_PATHS} additional exposed paths were not promoted")
        unique = unique[:MAX_PATHS]
    cleaned = _trim(notes)
    return EntrypointResult(tuple(unique), cleaned, truncated, False)


def path_lines(path: EntrypointPath) -> tuple[str, ...]:
    """Source-backed description of one path, including argument flow."""
    lines: list[str] = []
    for edge in path.edges:
        flow = ", ".join(edge.flow) or "no arguments"
        lines.append(f"{edge.caller} -> {edge.callee} @{edge.file}:{edge.line} ({flow})")
    return tuple(lines)


def forwarded_entry_params(path: EntrypointPath, helper: RFunction) -> dict[str, str]:
    """Entry parameter -> helper parameter, when every hop forwards a parameter.

    A local, a storage reference, or any other expression stops that parameter.
    It is not reported as forwarded.
    """
    if not path.edges:
        return {}
    found: dict[str, str] = {}
    for param in helper.params:
        if not param.name:
            continue
        current = param.name
        reached = True
        for edge in reversed(path.edges):
            mapping = dict(edge.forwarded)
            if current not in mapping:
                reached = False
                break
            current = mapping[current]
        if reached:
            found.setdefault(current, param.name)
    return found


def _is_entry(model: ResearchModel, function: RFunction) -> bool:
    item = model.contracts.get(function.contract)
    if item is None or item.kind != "contract":
        return False
    if function.kind != "function" or not function.exposed:
        return False
    from app.discovery.bounty.stateful import canonical_signature

    return canonical_signature(model, function) is not None


def _caller_index(
    model: ResearchModel, candidate_name: str
) -> tuple[dict[str, list[tuple[RFunction, CallEdge]]], list[str]]:
    reverse: dict[str, list[tuple[RFunction, CallEdge]]] = {}
    notes: list[str] = []
    libraries = {name for name, item in model.contracts.items() if item.kind == "library"}
    for owner in model.contracts.values():
        if owner.kind == "interface":
            continue
        for function in owner.functions:
            if not function.has_body:
                continue
            for edge in _edges_from(model, function, libraries, candidate_name, notes):
                reverse.setdefault(edge.callee, []).append((function, edge))
    for sites in reverse.values():
        sites.sort(key=lambda item: (item[0].file, item[0].line, item[0].signature, item[1].line))
    return reverse, notes


def _edges_from(
    model: ResearchModel,
    function: RFunction,
    libraries: set[str],
    candidate_name: str,
    notes: list[str],
) -> list[CallEdge]:
    edges: list[CallEdge] = []
    for name, arguments, offset in plain_calls(function.body):
        _add_resolved(
            model,
            function,
            function.contract,
            name,
            arguments,
            offset,
            False,
            candidate_name,
            notes,
            edges,
        )
    using = _using_libraries(model, function, libraries)
    for call in member_calls(function.body):
        receiver = " ".join(call.receiver.split())
        if receiver in libraries:
            _add_resolved(
                model,
                function,
                receiver,
                call.name,
                call.arguments,
                call.start,
                False,
                candidate_name,
                notes,
                edges,
            )
            continue
        if receiver in {"this", function.contract}:
            _add_resolved(
                model,
                function,
                function.contract,
                call.name,
                call.arguments,
                call.start,
                True,
                candidate_name,
                notes,
                edges,
            )
            continue
        if receiver == "super":
            owner = _super_owner(model, function, call.name)
            if owner:
                _add_resolved(
                    model,
                    function,
                    owner,
                    call.name,
                    call.arguments,
                    call.start,
                    False,
                    candidate_name,
                    notes,
                    edges,
                )
            elif candidate_name == call.name:
                notes.append(f"unresolved super call {call.name} at {_site(function, call.start)}")
            continue
        matched: list[tuple[RFunction, tuple[str, ...]]] = []
        for library in using:
            arguments = (call.receiver, *call.arguments)
            callees, ordered, status = _resolve(model, library, call.name, arguments)
            if status == "ok" and callees:
                matched.append((callees[0], ordered))
        if len(matched) == 1:
            callee, ordered = matched[0]
            edges.append(_edge(function, callee, ordered, call.start))
        elif len(matched) > 1 and call.name == candidate_name:
            notes.append(
                f"ambiguous library call {call.name} at {_site(function, call.start)}; "
                f"{len(matched)} libraries match"
            )
    return edges


def _add_resolved(
    model: ResearchModel,
    function: RFunction,
    owner: str,
    name: str,
    arguments: tuple[str, ...],
    offset: int,
    external_only: bool,
    candidate_name: str,
    notes: list[str],
    edges: list[CallEdge],
) -> None:
    callees, ordered, status = _resolve(model, owner, name, arguments)
    site = _site(function, offset)
    if status == "ok" and callees:
        callee = callees[0]
        if external_only and not callee.exposed:
            if name == candidate_name:
                notes.append(
                    f"{site} calls {name} externally, but {callee.identity} is not exposed"
                )
            return
        edges.append(_edge(function, callee, ordered, offset))
        return
    if name != candidate_name or status == "absent":
        return
    if status == "ambiguous":
        notes.append(
            f"ambiguous call {name} with {len(arguments)} arguments at {site}; "
            f"{len(callees)} overloads match; not followed"
        )
        return
    notes.append(
        f"unresolved call {name} with {len(arguments)} arguments at {site}; "
        "no overload has that arity"
    )


def _resolve(
    model: ResearchModel, owner: str, name: str, arguments: tuple[str, ...]
) -> tuple[list[RFunction], tuple[str, ...], str]:
    pool = [
        item
        for item in model.functions_of(owner)
        if item.kind == "function" and item.has_body and item.name == name
    ]
    if not pool:
        return [], arguments, "absent"
    named = _named_arguments(arguments)
    if named is None:
        matched = [item for item in pool if len(item.params) == len(arguments)]
        if len(matched) == 1:
            return matched, arguments, "ok"
        if len(matched) > 1:
            return matched, arguments, "ambiguous"
        return pool, arguments, "unresolved"
    matched = [
        item
        for item in pool
        if len(item.params) == len(named) and {param.name for param in item.params} == set(named)
    ]
    if len(matched) == 1:
        ordered = tuple(named[param.name] for param in matched[0].params)
        return matched, ordered, "ok"
    if len(matched) > 1:
        return matched, arguments, "ambiguous"
    return pool, arguments, "unresolved"


def _named_arguments(arguments: tuple[str, ...]) -> dict[str, str] | None:
    if len(arguments) != 1:
        return None
    text = arguments[0].strip()
    if not (text.startswith("{") and match_close(text, 0) == len(text) - 1):
        return None
    pairs: dict[str, str] = {}
    for item in split_top(text[1:-1]):
        key, sep, expr = item.partition(":")
        if not sep or not re.fullmatch(r"\s*[A-Za-z_]\w*\s*", key) or key.strip() in pairs:
            return None
        pairs[key.strip()] = expr.strip()
    return pairs or None


def _edge(
    caller: RFunction, callee: RFunction, arguments: tuple[str, ...], offset: int
) -> CallEdge:
    names = {param.name for param in caller.params if param.name}
    forwarded: list[tuple[str, str]] = []
    flow: list[str] = []
    for index, param in enumerate(callee.params):
        expr = arguments[index] if index < len(arguments) else ""
        bare = _bare(expr)
        label = param.name or f"arg{index}"
        if param.name and bare in names:
            forwarded.append((param.name, bare))
            flow.append(f"{label}<=param:{bare}")
        else:
            shown = bare or " ".join(expr.split())[:40] or "empty"
            flow.append(f"{label}=derived:{shown}")
    return CallEdge(
        caller=caller.identity,
        callee=callee.identity,
        file=caller.file,
        line=caller.line + caller.body[:offset].count("\n"),
        arguments=arguments,
        forwarded=tuple(forwarded),
        flow=tuple(flow),
    )


def _using_libraries(
    model: ResearchModel, function: RFunction, libraries: set[str]
) -> tuple[str, ...]:
    item = model.contracts.get(function.contract)
    text = f"{item.body if item else ''}\n{function.body}"
    found: list[str] = []
    for name in re.findall(r"\busing\s+([A-Za-z_]\w*)\s+for\b", text):
        if name in libraries and name not in found:
            found.append(name)
    return tuple(found)


def _super_owner(model: ResearchModel, function: RFunction, name: str) -> str:
    for base in model.bases_of(function.contract):
        if any(item.name == name and item.kind == "function" for item in model.functions_of(base)):
            return base
    return ""


def _bare(expr: str) -> str:
    text = expr.strip()
    if re.fullmatch(r"[A-Za-z_]\w*", text):
        return text
    return ""


def _site(function: RFunction, offset: int) -> str:
    line = function.line + function.body[:offset].count("\n")
    return f"{function.file}:{line} {function.contract}.{function.name}"


def _path_key(path: EntrypointPath) -> tuple[str, ...]:
    return tuple(f"{edge.caller}->{edge.callee}@{edge.line}" for edge in path.edges)


def _trim(notes: list[str]) -> tuple[str, ...]:
    unique: list[str] = []
    for note in notes:
        if note not in unique:
            unique.append(note)
        if len(unique) == _MAX_NOTES:
            break
    return tuple(unique)
