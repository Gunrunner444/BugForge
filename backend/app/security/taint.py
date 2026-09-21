"""Flow-sensitive, scope-aware taint tracking over a SyntaxGraph.

Precision (documented, not advertised beyond this):

* **flow-sensitive**: a later reaching definition replaces an earlier one in
  the same scope. ``q = tainted; q = "safe"; sink(q)`` is not tainted.
* **not path-sensitive**: assignments inside branches/loops merge conservatively.
  If either path may taint a symbol, later uses in the parent stay tainted.
* **not flow-insensitive**: taint is not a sticky property of ``scope_id::name``.

Symbols are ``scope_id::name``. Sibling functions never share locals.
Source/sink matching uses syntax-derived callees, member accesses, and
identifiers — never string-literal or comment text.

Same-file inter-procedural propagation runs only when the callee can be
resolved uniquely. Ambiguous names do not speculate.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from app.analyzers.framework_detector import FrameworkInfo
from app.parsing.model import Binding, CallArgument, CallSite, SyntaxGraph
from app.security.definitions import (
    SINK_SANITIZER_KINDS,
    LanguageSecurityVocab,
    SanitizerDefinition,
    SinkDefinition,
    SourceDefinition,
)
from app.security.language_vocab import vocab_for

TAINT_PRECISION = "flow-sensitive"
TAINT_PATH_SENSITIVE = False
MAX_TAINT_ROUNDS = 8
MAX_INTERPROC_DEPTH = 4
MAX_DEFINITIONS = 10_000

_IDENT = re.compile(r"[A-Za-z_$/][\w$]*")
_SQL_PLACEHOLDER = re.compile(r"(?:\?|\$\d+|%s|:\w+)")


def compile_patterns(patterns: Sequence[str]) -> list[re.Pattern[str]]:
    return [re.compile(p) for p in patterns]


def matches_any(text: str, patterns: Sequence[re.Pattern[str]]) -> re.Pattern[str] | None:
    for pattern in patterns:
        if pattern.search(text):
            return pattern
    return None


def _canon_qual(text: str) -> str:
    """Treat ``::`` / ``->`` / ``.`` as equivalent for cross-language matching."""
    return text.replace("::", ".").replace("->", ".")


def text_matches_any(text: str, patterns: Sequence[str]) -> str | None:
    """Qualified/identifier match. Does not search arbitrary haystacks."""
    return fragment_matches_source(text, patterns)


def fragment_matches_source(fragment: str, patterns: Sequence[str]) -> str | None:
    if not fragment:
        return None
    canon = _canon_qual(fragment)
    for pattern in patterns:
        p = _canon_qual(pattern)
        if not p:
            continue
        if canon == p:
            return pattern
        if canon.startswith(p + ".") or canon.startswith(p + "("):
            return pattern
        if canon.endswith("." + p) and "." in p:
            return pattern
        # Explicit regex sources (e.g. shell ``$1``) keep anchors; dotted
        # API patterns are never treated as regex because ``.`` is a member.
        if pattern.startswith("^") or pattern.endswith("$"):
            try:
                if re.search(pattern, fragment):
                    return pattern
            except re.error:
                continue
    return None


def vocab_sources(
    vocab: LanguageSecurityVocab, frameworks: Sequence[FrameworkInfo]
) -> tuple[SourceDefinition, ...]:
    extra: list[SourceDefinition] = []
    names = {fw.name.lower() for fw in frameworks}
    for key, sources in vocab.extra_sources_by_framework.items():
        if key.lower() in names:
            extra.extend(sources)
    return vocab.sources + tuple(extra)


@dataclass
class _Reach:
    reason: str | None
    def_index: int = 0
    merged: bool = False


def propagate_taint(
    graph: SyntaxGraph,
    sources: Sequence[SourceDefinition],
) -> dict[str, str]:
    """Map symbol_id → why the currently reaching definition is user-controlled."""
    source_pats = tuple(p for src in sources for p in src.patterns)
    reaching: dict[str, _Reach] = {}
    rounds = 0
    changed = True
    interproc_depth = 0
    while changed and rounds < MAX_TAINT_ROUNDS:
        changed = False
        rounds += 1
        applied = 0
        return_reasons = _return_reasons(graph, reaching, source_pats)
        for binding in _ordered_bindings(graph):
            applied += 1
            if applied > MAX_DEFINITIONS:
                break
            reason = _binding_taint(binding, source_pats, reaching, return_reasons)
            previous = reaching.get(binding.symbol_id)
            empty_rhs = (
                not binding.rhs
                and not binding.rhs_idents
                and not binding.rhs_accesses
                and not binding.rhs_callees
            )
            # Parameters / empty declarations are not reassignments. An
            # interprocedural callarg must remain the reaching state.
            if empty_rhs and previous is not None:
                continue
            # Replaying the same (or earlier) definition must not erase taint
            # that _interprocedural() attached to this reaching definition.
            # A later definition_index is a real reassignment and may clear it.
            if (
                reason is None
                and previous is not None
                and previous.reason
                and binding.definition_index <= previous.def_index
            ):
                continue
            if binding.is_conditional and previous is not None:
                new = _Reach(
                    reason=_merge_reason(previous.reason, reason),
                    def_index=binding.definition_index,
                    merged=True,
                )
            else:
                new = _Reach(reason=reason, def_index=binding.definition_index)
            if (
                previous is None
                or previous.reason != new.reason
                or previous.def_index != new.def_index
            ):
                reaching[binding.symbol_id] = new
                if (previous.reason if previous else None) != new.reason:
                    changed = True
        if interproc_depth < MAX_INTERPROC_DEPTH:
            live = {s: r.reason for s, r in reaching.items() if r.reason}
            for new_id, reason in _interprocedural(graph, live, source_pats):
                current = reaching.get(new_id)
                if current is None or current.reason != reason:
                    # Attach to the current reaching definition. A fake later
                    # def_index made the next binding pass look like an earlier
                    # assignment and overwrite this reason with None.
                    reaching[new_id] = _Reach(
                        reason=reason,
                        def_index=current.def_index if current is not None else 0,
                    )
                    changed = True
            interproc_depth += 1
    return {sid: r.reason for sid, r in reaching.items() if r.reason}


def _ordered_bindings(graph: SyntaxGraph) -> list[Binding]:
    def key(binding: Binding) -> tuple[int, int, int]:
        if binding.span is not None:
            return (binding.span.start_byte, binding.line, binding.definition_index)
        return (10**12, binding.line, binding.definition_index)

    return sorted(graph.bindings, key=key)


def _merge_reason(left: str | None, right: str | None) -> str | None:
    if left and right:
        return left if left == right else f"merge:{left}|{right}"
    return left or right


def _binding_taint(
    binding: Binding,
    source_pats: Sequence[str],
    reaching: dict[str, _Reach],
    return_reasons: dict[str, str] | None = None,
) -> str | None:
    if binding.rhs_is_literal and not binding.rhs_callees and not binding.rhs_accesses:
        return None
    for fragment in (*binding.rhs_accesses, *binding.rhs_callees, *binding.rhs_idents):
        hit = fragment_matches_source(fragment, source_pats)
        if hit:
            return f"source:{hit}"
    for ident in binding.rhs_idents:
        sid = _resolve_symbol(ident, binding.scope_id, reaching)
        if sid is not None and reaching[sid].reason:
            return f"from:{sid}:{reaching[sid].reason}"
    for callee in binding.rhs_callees:
        simple = callee.rsplit(".", 1)[-1]
        if return_reasons and simple in return_reasons:
            return f"from_return:{simple}:{return_reasons[simple]}"
    return None


def _return_reasons(
    graph: SyntaxGraph,
    reaching: dict[str, _Reach],
    source_pats: Sequence[str],
) -> dict[str, str]:
    """Map uniquely resolved function names to a return taint reason."""
    functions = [
        ent
        for ent in graph.entities
        if ent.entity_type in {"function", "async_function", "method", "async_method"}
    ]
    by_name: dict[str, list[object]] = {}
    for ent in functions:
        by_name.setdefault(ent.name, []).append(ent)
    out: dict[str, str] = {}
    for ret in graph.returns:
        func_name = ret.scope_id.rsplit(":", 1)[-1]
        if len(by_name.get(func_name, [])) != 1:
            continue
        reason: str | None = None
        for fragment in (*ret.accesses, *ret.idents):
            hit = fragment_matches_source(fragment, source_pats)
            if hit:
                reason = f"return:source:{hit}"
                break
        if reason is None:
            for ident in ret.idents:
                sid = _resolve_symbol(ident, ret.scope_id, reaching)
                if sid is not None:
                    reason = f"return:{sid}"
                    break
        if reason:
            out[func_name] = reason
    return out


def _resolve_symbol(
    name: str, scope_id: str, reaching: dict[str, _Reach] | dict[str, str]
) -> str | None:
    """Resolve ``name`` in ``scope_id``, then enclosing scopes, never sibling functions."""
    current: str | None = scope_id
    while current:
        candidate = f"{current}::{name}"
        if candidate in reaching:
            value = reaching[candidate]
            reason = value.reason if isinstance(value, _Reach) else value
            if reason:
                return candidate
            return None
        if "/" not in current:
            break
        current = current.rsplit("/", 1)[0]
    module = f"module::{name}"
    if module in reaching:
        value = reaching[module]
        reason = value.reason if isinstance(value, _Reach) else value
        if reason:
            return module
        return None
    return None


def _interprocedural(
    graph: SyntaxGraph,
    tainted: dict[str, str],
    source_pats: Sequence[str] = (),
) -> list[tuple[str, str]]:
    """Parameter and return propagation only when the callee is unique."""
    new: list[tuple[str, str]] = []
    functions = [
        ent
        for ent in graph.entities
        if ent.entity_type in {"function", "async_function", "method", "async_method"}
    ]
    by_name: dict[str, list[object]] = {}
    by_qualified: dict[str, list[object]] = {}
    for ent in functions:
        by_name.setdefault(ent.name, []).append(ent)
        by_qualified.setdefault(ent.qualified_name, []).append(ent)
        if ent.parent:
            by_qualified.setdefault(f"{ent.parent}.{ent.name}", []).append(ent)

    def resolve_callee(call: CallSite) -> object | None:
        candidates = by_qualified.get(call.qualified) or by_name.get(call.name) or []
        if len(candidates) == 1:
            return candidates[0]
        qualified_hits = [
            ent
            for ent in candidates
            if getattr(ent, "qualified_name", "") == call.qualified
            or call.qualified.endswith(f".{getattr(ent, 'name', '')}")
        ]
        if len(qualified_hits) == 1:
            return qualified_hits[0]
        return None

    reaching_wrap = {sid: _Reach(reason=reason) for sid, reason in tainted.items()}
    for call in graph.calls:
        callee = resolve_callee(call)
        if callee is None:
            continue
        callee_scope = _scope_for_entity(graph, callee)
        if callee_scope is None:
            continue
        params = list(getattr(callee, "parameters", ()) or ())
        args = list(call.arguments)
        if not args and (call.argument_idents or call.argument_accesses):
            args = [
                CallArgument(
                    index=0,
                    text=call.argument_text,
                    is_literal=call.argument_is_literal,
                    idents=call.argument_idents,
                    accesses=call.argument_accesses,
                    dynamic=call.dynamic,
                )
            ]
        for arg in args:
            reason = _argument_taint(arg, call.scope_id, reaching_wrap, source_pats)
            if not reason:
                continue
            if arg.index < len(params):
                pname = params[arg.index].name
                new.append((f"{callee_scope}::{pname}", f"callarg:{arg.index}:{reason}"))
    for ret in graph.returns:
        ret_reason = None
        for fragment in (*ret.accesses, *ret.idents):
            hit = fragment_matches_source(fragment, source_pats)
            if hit:
                ret_reason = f"return:source:{hit}"
                break
        if ret_reason is None:
            for ident in ret.idents:
                sid = _resolve_symbol(ident, ret.scope_id, reaching_wrap)
                if sid is not None:
                    ret_reason = f"return:{sid}"
                    break
        if ret_reason is None:
            continue
        func_name = ret.scope_id.rsplit(":", 1)[-1]
        if len(by_name.get(func_name, [])) != 1:
            continue
        for binding in graph.bindings:
            if binding.scope_id == ret.scope_id:
                continue
            if any(c == func_name or c.endswith(f".{func_name}") for c in binding.rhs_callees):
                new.append((binding.symbol_id, ret_reason))
    return new


def _scope_for_entity(graph: SyntaxGraph, entity: object) -> str | None:
    name = getattr(entity, "name", "")
    parent = getattr(entity, "parent", None)
    start = getattr(entity, "start_byte", None)
    matches: list[str] = []
    for scope in graph.scopes:
        if scope.name != name or scope.kind.value not in {"function", "method"}:
            continue
        if parent and parent not in scope.scope_id and parent not in (scope.parent_id or ""):
            continue
        if start is not None and scope.span is not None:
            if abs(scope.span.start_byte - int(start)) <= 2:
                return scope.scope_id
        matches.append(scope.scope_id)
    if len(matches) == 1:
        return matches[0]
    return None


def call_taint_reason(
    call: CallSite,
    source_pats: Sequence[str],
    tainted: dict[str, str],
    *,
    argument_indexes: Sequence[int] | None = None,
) -> str | None:
    reaching = {sid: _Reach(reason=reason) for sid, reason in tainted.items()}
    indexes = list(argument_indexes or [])
    if call.arguments and indexes:
        for index in indexes:
            arg = call.argument_at(index)
            if arg is None:
                continue
            reason = _argument_taint(arg, call.scope_id, reaching, source_pats)
            if reason:
                return reason
        return None
    if call.arguments:
        for arg in call.arguments:
            reason = _argument_taint(arg, call.scope_id, reaching, source_pats)
            if reason:
                return reason
        return None
    if call.argument_is_literal and not call.dynamic and not call.argument_idents:
        return None
    for fragment in (*call.argument_accesses, *call.argument_idents):
        hit = fragment_matches_source(fragment, source_pats)
        if hit:
            return f"source:{hit}"
    for ident in call.argument_idents:
        sid = _resolve_symbol(ident, call.scope_id, reaching)
        if sid is not None and reaching[sid].reason:
            return f"from:{sid}:{reaching[sid].reason}"
    return None


def _argument_taint(
    arg: CallArgument,
    scope_id: str,
    reaching: dict[str, _Reach],
    source_pats: Sequence[str],
) -> str | None:
    if arg.is_literal and not arg.dynamic and not arg.idents and not arg.accesses:
        return None
    for fragment in (*arg.accesses, *arg.callees, *arg.idents):
        hit = fragment_matches_source(fragment, source_pats)
        if hit:
            return f"source:{hit}"
    for ident in arg.idents:
        sid = _resolve_symbol(ident, scope_id, reaching)
        if sid is not None and reaching[sid].reason:
            return f"from:{sid}:{reaching[sid].reason}"
    return None


def call_matches_sink(call: CallSite, sink: SinkDefinition) -> bool:
    haystacks = (call.qualified, call.name)
    for name in sink.api_names:
        name_n = _canon_qual(name)
        for hay in haystacks:
            hay_n = _canon_qual(hay)
            if hay == name or hay_n == name_n:
                return _receiver_ok(call, sink)
            if (
                hay.endswith(f".{name}")
                or hay.endswith(f"::{name}")
                or hay.endswith(f"->{name}")
                or hay_n.endswith(f".{name_n}")
            ):
                return _receiver_ok(call, sink)
            if ("." in name_n or "::" in name or "->" in name) and (
                hay_n == name_n or hay_n.endswith("." + name_n)
            ):
                return _receiver_ok(call, sink)
    return False


def _receiver_ok(call: CallSite, sink: SinkDefinition) -> bool:
    if not sink.receiver_names:
        return True
    left = _canon_qual(call.qualified)
    return any(_canon_qual(name) in left for name in sink.receiver_names)


def argument_is_constant(call: CallSite, *, argument_indexes: Sequence[int] | None = None) -> bool:
    indexes = list(argument_indexes or [])
    if call.arguments and indexes:
        relevant = [a for i in indexes if (a := call.argument_at(i)) is not None]
        if not relevant:
            return False
        return all(a.is_literal and not a.dynamic and not a.idents for a in relevant)
    if call.arguments:
        return all(a.is_literal and not a.dynamic and not a.idents for a in call.arguments)
    if call.argument_idents:
        return False
    if call.dynamic:
        return False
    if call.argument_is_literal:
        return True
    text = call.argument_text.strip()
    if not text:
        return True
    if text[0] in {'"', "'", "`"} and text[-1] == text[0]:
        return True
    return False


def sanitizer_intervened(
    call: CallSite,
    sanitizers: Sequence[SanitizerDefinition],
    *,
    allowed_kinds: Sequence[str] = (),
    argument_indexes: Sequence[int] | None = None,
) -> SanitizerDefinition | None:
    """Match sanitizers on the relevant argument's callees, never argument text."""
    allowed = set(allowed_kinds) if allowed_kinds else None
    indexes = list(argument_indexes or [])
    args: list[CallArgument] = []
    if call.arguments and indexes:
        args = [a for i in indexes if (a := call.argument_at(i)) is not None]
    elif call.arguments:
        args = list(call.arguments)
    callees: tuple[str, ...] = ()
    for arg in args:
        callees += arg.callees
    if not callees:
        callees = call.argument_accesses
    for sanitizer in sanitizers:
        if allowed is not None and sanitizer.kind not in allowed:
            continue
        for name in sanitizer.api_names:
            name_n = _canon_qual(name)
            for callee in callees:
                callee_n = _canon_qual(callee)
                if callee == name or callee_n == name_n:
                    return sanitizer
                if name_n and (callee_n.endswith("." + name_n)):
                    return sanitizer
    return None


def looks_parameterized_sql(call: CallSite | str) -> bool:
    """Syntax-aware parameterization, not a substring search on the call text."""
    if isinstance(call, str):
        # Legacy helper used by older tests; refuse concatenated-looking text.
        if "+" in call or "${" in call:
            return False
        return bool(_SQL_PLACEHOLDER.search(call)) and "," in call
    if call.dynamic:
        return False
    if len(call.arguments) >= 2:
        query = call.arguments[0]
        if query.is_literal and not query.dynamic and _SQL_PLACEHOLDER.search(query.text):
            return True
    if not call.arguments and not call.dynamic and call.argument_is_literal:
        return bool(_SQL_PLACEHOLDER.search(call.argument_text))
    return False


def identifiers_in(text: str) -> list[str]:
    return [m.group(0) for m in _IDENT.finditer(text)]


def language_vocab(graph: SyntaxGraph) -> LanguageSecurityVocab | None:
    return vocab_for(graph.language)


def applicable_sanitizer_kinds(sink: SinkDefinition) -> tuple[str, ...]:
    if sink.sanitizer_kinds:
        return sink.sanitizer_kinds
    kinds = SINK_SANITIZER_KINDS.get(sink.vulnerability_class, frozenset())
    return tuple(kinds)
