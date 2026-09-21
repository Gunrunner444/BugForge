"""Flow-sensitive, scope-aware taint tracking over a SyntaxGraph.

Precision (documented, not advertised beyond this):

* **flow-sensitive at the use site**: a sink uses the definition reaching that
  call's source position, not the file-final state of the symbol.
  ``q = "safe"; sink(q); q = input`` is not tainted at the sink.
* **not path-sensitive**: assignments inside branches/loops merge conservatively.
  If either path may taint ``q``, later uses in the parent stay tainted.
* **not flow-insensitive**: taint is not a sticky property of ``scope_id::name``.
  Historical taint is distinct from the taint reaching a given program point.

Symbols are ``scope_id::name``. Sibling functions never share locals.
Source/sink matching uses syntax-derived callees, member accesses, and
identifiers — never string-literal or comment text.

Same-file inter-procedural propagation runs only when the callee can be
resolved uniquely. Ambiguous names do not speculate. Optional
``ExternalCallee`` entries describe uniquely resolved callees in other files;
they are applied at the call that binds their result, then later sinks use the
definition reaching that program point.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from app.analyzers.framework_detector import FrameworkInfo
from app.parsing.model import Binding, CallArgument, CallSite, SymbolKind, SyntaxGraph
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
_PRESERVING_CALLEES = frozenset({"format", "str", "sprintf", "Sprintf", "c_str"})

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


@dataclass(frozen=True)
class _Def:
    """One reaching definition of a symbol, ordered by source position."""

    start_byte: int
    line: int
    definition_index: int
    reason: str | None
    merged: bool = False


@dataclass
class TaintState:
    """Flow-sensitive taint: ordered definitions per symbol, queried at a use."""

    defs: dict[str, tuple[_Def, ...]]
    source_pats: tuple[str, ...] = ()
    incomplete: bool = False
    limit_reason: str = ""

    def final_map(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for sid, defs in self.defs.items():
            if defs and defs[-1].reason:
                out[sid] = defs[-1].reason
        return out

    def reason_at_name(self, name: str, scope_id: str, at_byte: int) -> str | None:
        """Taint of ``name`` reaching ``at_byte`` in ``scope_id``. Never sibling scopes."""
        current: str | None = scope_id
        while current:
            candidate = f"{current}::{name}"
            if candidate in self.defs:
                return _reason_at(self.defs[candidate], at_byte)
            if "/" not in current:
                break
            current = current.rsplit("/", 1)[0]
        module = f"module::{name}"
        if module in self.defs:
            return _reason_at(self.defs[module], at_byte)
        return None

    @staticmethod
    def from_final_map(tainted: dict[str, str], source_pats: Sequence[str] = ()) -> TaintState:
        """Treat a file-final map as definitions at byte 0 (legacy / tests)."""
        defs: dict[str, tuple[_Def, ...]] = {
            sid: (_Def(start_byte=0, line=1, definition_index=0, reason=reason),)
            for sid, reason in tainted.items()
        }
        return TaintState(defs=defs, source_pats=tuple(source_pats))


@dataclass(frozen=True)
class ExternalCallee:
    """A callee in another file, resolved uniquely from an import.

    ``return_effects`` are summary tokens (``source:…``, ``param:N``,
    ``sanitized:kind:…``). ``param_sinks`` records parameters that reach a sink
    inside that callee: ``(index, vulnerability_class, sink, line)``.
    """

    local_name: str
    callee_file: str
    callee_function: str
    return_effects: tuple[str, ...] = ()
    param_sinks: tuple[tuple[int, str, str, int], ...] = ()
    partial: bool = False
    hops: int = 0
    semantic_id: str = ""
    relationship: str = "import"


def reaching_sanitizer_kind(taint: str) -> str | None:
    """Outermost sanitizer kind carried by a use-site reason, if that is all it is."""
    marker = ":sanitized:"
    if marker not in taint or "|" in taint:
        return None
    kind = taint.split(marker, 1)[1].split(":", 1)[0]
    if not kind or kind in {"source", "param", "from", "cross_file", "callarg"}:
        return None
    return kind


def _use_byte(span: object | None, line: int) -> int:
    start = getattr(span, "start_byte", None)
    if isinstance(start, int):
        return start
    return max(0, line) * 10_000


def _reason_at(defs: tuple[_Def, ...], at_byte: int) -> str | None:
    hitting: _Def | None = None
    for item in defs:
        if item.start_byte <= at_byte:
            hitting = item
        else:
            break
    return hitting.reason if hitting is not None else None


def _freeze_timeline(
    timeline: dict[str, dict[int, _Def]],
    source_pats: Sequence[str],
    *,
    incomplete: bool = False,
    limit_reason: str = "",
) -> TaintState:
    frozen: dict[str, tuple[_Def, ...]] = {}
    for sid, by_index in timeline.items():
        frozen[sid] = tuple(
            sorted(by_index.values(), key=lambda item: (item.start_byte, item.definition_index))
        )
    return TaintState(
        defs=frozen,
        source_pats=tuple(source_pats),
        incomplete=incomplete,
        limit_reason=limit_reason,
    )


def _empty_rhs(binding: Binding) -> bool:
    return (
        not binding.rhs
        and not binding.rhs_idents
        and not binding.rhs_accesses
        and not binding.rhs_callees
    )


def _killing_assignment(binding: Binding) -> bool:
    """Literal RHS that is not a parameter/placeholder — clears this definition only."""
    return (
        binding.rhs_is_literal
        and not binding.rhs_callees
        and not binding.rhs_accesses
        and not _empty_rhs(binding)
    )


def _reach_for_definition(
    binding: Binding,
    computed: str | None,
    previous_this_walk: _Reach | None,
    existing: _Def | None,
) -> _Reach:
    """Taint of this definition. Never copy a later definition backward."""
    existing_reason = existing.reason if existing is not None else None
    if _empty_rhs(binding):
        reason = existing_reason or computed
    elif _killing_assignment(binding):
        reason = None
    elif computed:
        reason = computed
    else:
        reason = existing_reason
    merged = False
    if binding.is_conditional and previous_this_walk is not None:
        reason = _merge_reason(previous_this_walk.reason, reason)
        merged = True
    return _Reach(reason=reason, def_index=binding.definition_index, merged=merged)


def _peel_sanitizer(effect: str) -> tuple[str | None, str]:
    kind: str | None = None
    core = effect
    while core.startswith("sanitized:"):
        rest = core[len("sanitized:") :]
        part, sep, inner = rest.partition(":")
        if not sep or not part:
            break
        if kind is None:
            kind = part
        core = inner
    return kind, core


def _external_for_call(
    call: CallSite, externals: Mapping[str, ExternalCallee]
) -> ExternalCallee | None:
    """Match a call to one known callee.

    A qualified call such as ``obj.method`` or ``importlib...run`` matches only
    that qualified key. The bare name is used for an unqualified call. A
    ``new.Type.method`` call uses the ``Type.method`` key.
    """
    qualified = call.qualified or call.name
    if qualified.startswith("new."):
        qualified = qualified[4:]
    if "." in qualified and qualified != call.name:
        return externals.get(qualified)
    return externals.get(qualified) or externals.get(call.name)


def _call_matching_binding(
    binding: Binding,
    calls: Sequence[CallSite],
    externals: Mapping[str, ExternalCallee],
) -> CallSite | None:
    names: list[str] = []
    for callee in binding.rhs_callees:
        simple = callee.rsplit(".", 1)[-1]
        if callee in externals or simple in externals:
            names.append(callee)
            names.append(simple)
    if not names:
        return None
    wanted = set(names)
    fallback: CallSite | None = None
    for call in calls:
        if call.scope_id != binding.scope_id:
            continue
        if call.name not in wanted and call.qualified not in wanted:
            continue
        if (
            binding.span is not None
            and call.span is not None
            and binding.span.start_byte == call.span.start_byte
        ):
            return call
        if call.line == binding.line:
            fallback = call
    return fallback


def _render_effect(
    effect: str,
    call: CallSite,
    scope_id: str,
    source_pats: Sequence[str],
    reaching: dict[str, _Reach],
    at_byte: int,
    ext: ExternalCallee,
) -> str | None:
    kind, core = _peel_sanitizer(effect)
    prefix = f"cross_file:{ext.callee_file}:{ext.callee_function}:"
    if kind:
        prefix += f"sanitized:{kind}:"
    if core.startswith("source:"):
        return prefix + core
    if not core.startswith("param:"):
        return None
    try:
        index = int(core.split(":", 1)[1])
    except ValueError:
        return None
    arg = call.argument_at(index)
    if arg is None:
        return None
    reason = _argument_taint(arg, scope_id, reaching, source_pats, at_byte)
    if not reason:
        return None
    return prefix + core + ":" + reason


def _external_binding_reason(
    binding: Binding,
    calls: Sequence[CallSite],
    externals: Mapping[str, ExternalCallee],
    source_pats: Sequence[str],
    reaching: dict[str, _Reach],
) -> str | None:
    if not binding.rhs_callees or _killing_assignment(binding):
        return None
    call = _call_matching_binding(binding, calls, externals)
    if call is None:
        return None
    ext = _external_for_call(call, externals)
    if ext is None or not ext.return_effects:
        return None
    at_byte = _use_byte(binding.span, binding.line)
    unsanitized: list[str] = []
    sanitized: list[str] = []
    for effect in ext.return_effects:
        rendered = _render_effect(
            effect, call, binding.scope_id, source_pats, reaching, at_byte, ext
        )
        if not rendered:
            continue
        if ":sanitized:" in rendered:
            sanitized.append(rendered)
        else:
            unsanitized.append(rendered)
    chosen = unsanitized or sanitized
    return chosen[0] if chosen else None


def analyze_taint(
    graph: SyntaxGraph,
    sources: Sequence[SourceDefinition],
    externals: Mapping[str, ExternalCallee] | None = None,
) -> TaintState:
    """Compute ordered reaching definitions. Use ``taint_at_use`` at sinks."""
    source_pats = tuple(p for src in sources for p in src.patterns)
    external_map = dict(externals or {})
    calls = graph.calls
    timeline: dict[str, dict[int, _Def]] = {}
    rounds = 0
    changed = True
    interproc_depth = 0
    definition_capped = False
    depth_saturated = False
    while changed and rounds < MAX_TAINT_ROUNDS:
        changed = False
        rounds += 1
        applied = 0
        prior = _freeze_timeline(timeline, source_pats)
        return_reasons = _return_reasons(graph, prior, source_pats)
        reaching: dict[str, _Reach] = {}
        for binding in _ordered_bindings(graph):
            applied += 1
            if applied > MAX_DEFINITIONS:
                definition_capped = True
                break
            computed = _binding_taint(binding, source_pats, reaching, return_reasons)
            if not computed:
                computed = _sanitized_call_result(graph.language, binding, source_pats, reaching)
            if external_map:
                ext_reason = _external_binding_reason(
                    binding, calls, external_map, source_pats, reaching
                )
                if ext_reason and (not computed or ":sanitized:" in ext_reason):
                    computed = ext_reason
            existing = timeline.get(binding.symbol_id, {}).get(binding.definition_index)
            new = _reach_for_definition(
                binding,
                computed,
                reaching.get(binding.symbol_id),
                existing,
            )
            old_reason = existing.reason if existing is not None else None
            if old_reason != new.reason:
                changed = True
            reaching[binding.symbol_id] = new
            byte = _use_byte(binding.span, binding.line)
            timeline.setdefault(binding.symbol_id, {})[binding.definition_index] = _Def(
                start_byte=byte,
                line=binding.line,
                definition_index=binding.definition_index,
                reason=new.reason,
                merged=new.merged,
            )
        if interproc_depth < MAX_INTERPROC_DEPTH:
            state = _freeze_timeline(timeline, source_pats)
            live = {s: r.reason for s, r in reaching.items() if r.reason}
            added_edge = False
            for new_id, reason, idx in _interprocedural_edges(
                graph, live, source_pats, state=state
            ):
                existing = timeline.get(new_id, {}).get(idx)
                if existing is not None and existing.reason == reason:
                    continue
                target = _binding_at(graph, new_id, idx)
                byte = (
                    existing.start_byte
                    if existing is not None
                    else _use_byte(target.span, target.line)
                    if target is not None
                    else 0
                )
                line = (
                    existing.line
                    if existing is not None
                    else target.line
                    if target is not None
                    else 1
                )
                timeline.setdefault(new_id, {})[idx] = _Def(
                    start_byte=byte,
                    line=line,
                    definition_index=idx,
                    reason=reason,
                    merged=existing.merged if existing is not None else False,
                )
                changed = True
                added_edge = True
            interproc_depth += 1
            if interproc_depth >= MAX_INTERPROC_DEPTH and added_edge:
                depth_saturated = True
    reasons: list[str] = []
    if changed and rounds >= MAX_TAINT_ROUNDS:
        reasons.append("taint round limit")
    if definition_capped:
        reasons.append("taint definition limit")
    if depth_saturated:
        reasons.append("interprocedural depth limit")
    return _freeze_timeline(
        timeline,
        source_pats,
        incomplete=bool(reasons),
        limit_reason="; ".join(reasons),
    )


def propagate_taint(
    graph: SyntaxGraph,
    sources: Sequence[SourceDefinition],
) -> dict[str, str]:
    """File-final map (last definition per symbol). Sinks must use ``taint_at_use``."""
    return analyze_taint(graph, sources).final_map()


def taint_at_use(
    graph: SyntaxGraph,
    call: CallSite,
    sources: Sequence[SourceDefinition],
    *,
    argument_indexes: Sequence[int] | None = None,
) -> str | None:
    """Taint reaching ``call`` at its source position."""
    state = analyze_taint(graph, sources)
    return call_taint_reason(call, state.source_pats, state, argument_indexes=argument_indexes)


def _ordered_bindings(graph: SyntaxGraph) -> list[Binding]:
    def key(binding: Binding) -> tuple[int, int, int]:
        if binding.span is not None:
            return (binding.span.start_byte, binding.line, binding.definition_index)
        return (10**12, binding.line, binding.definition_index)

    return sorted(graph.bindings, key=key)


def _merge_reason(left: str | None, right: str | None) -> str | None:
    """Conservative branch merge. One clean side stays visible in the reason."""
    if left and right:
        return left if left == right else f"merge:{left}|{right}"
    present = left or right
    if present:
        return f"merge:{present}|clean"
    return None


def _callee_is_known_sanitizer(callee: str, sanitizers: Sequence[SanitizerDefinition]) -> bool:
    for sanitizer in sanitizers:
        for name in sanitizer.api_names:
            if callee == name or callee.endswith("." + name):
                return True
    return False


def _preserves_taint(callee: str) -> bool:
    """String formatting and ``str()`` keep the taint of their inputs."""
    return callee.rsplit(".", 1)[-1] in _PRESERVING_CALLEES


def _callee_is_source(callee: str, source_pats: Sequence[str]) -> bool:
    if fragment_matches_source(callee, source_pats):
        return True
    return fragment_matches_source(callee.rsplit(".", 1)[-1], source_pats) is not None


def _binding_taint(
    binding: Binding,
    source_pats: Sequence[str],
    reaching: dict[str, _Reach],
    return_reasons: dict[str, str] | None = None,
) -> str | None:
    if binding.rhs_is_literal and not binding.rhs_callees and not binding.rhs_accesses:
        return None
    source_callees = [
        callee for callee in binding.rhs_callees if _callee_is_source(callee, source_pats)
    ]
    transforming = [
        callee
        for callee in binding.rhs_callees
        if callee not in source_callees
        and not any(callee.startswith(source + ".") for source in source_callees)
        and not _preserves_taint(callee)
    ]
    if not transforming:
        for fragment in (*binding.rhs_accesses, *binding.rhs_callees, *binding.rhs_idents):
            hit = fragment_matches_source(fragment, source_pats)
            if hit:
                return f"source:{hit}"
        for ident in binding.rhs_idents:
            sid = _resolve_symbol(ident, binding.scope_id, reaching)
            if sid is not None and reaching[sid].reason:
                return f"from:{sid}:{reaching[sid].reason}"
        return None
    for callee in transforming:
        simple = callee.rsplit(".", 1)[-1]
        if return_reasons and simple in return_reasons:
            return f"from_return:{simple}:{return_reasons[simple]}"
    return None


def _sanitized_call_result(
    language: str,
    binding: Binding,
    source_pats: Sequence[str],
    reaching: dict[str, _Reach],
) -> str | None:
    """A known effective sanitizer call keeps taint, marked with its kind."""
    if not binding.rhs_callees:
        return None
    vocab = vocab_for(language)
    if vocab is None:
        return None
    sanitizer: SanitizerDefinition | None = None
    for candidate in vocab.sanitizers:
        if not candidate.effective:
            continue
        for name in candidate.api_names:
            for callee in binding.rhs_callees:
                if callee == name or callee.endswith("." + name):
                    sanitizer = candidate
                    break
            if sanitizer is not None:
                break
        if sanitizer is not None:
            break
    if sanitizer is None:
        return None
    inner: str | None = None
    for fragment in (*binding.rhs_accesses, *binding.rhs_idents):
        if any(
            fragment == callee or callee.endswith("." + fragment) for callee in binding.rhs_callees
        ):
            continue
        hit = fragment_matches_source(fragment, source_pats)
        if hit:
            inner = f"source:{hit}"
            break
    if inner is None:
        for ident in binding.rhs_idents:
            if any(
                ident == callee or callee.endswith("." + ident) or callee.startswith(ident + ".")
                for callee in binding.rhs_callees
            ):
                continue
            sid = _resolve_symbol(ident, binding.scope_id, reaching)
            if sid is not None and reaching[sid].reason:
                inner = f"from:{ident}:{reaching[sid].reason}"
                break
    if inner is None:
        return None
    return f"sanitized:{sanitizer.kind}:{inner}"


def _return_reasons(
    graph: SyntaxGraph,
    reaching: dict[str, _Reach] | TaintState,
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
            ret_byte = _use_byte(ret.span, ret.line)
            for ident in ret.idents:
                if isinstance(reaching, TaintState):
                    ident_reason = reaching.reason_at_name(ident, ret.scope_id, ret_byte)
                    if ident_reason:
                        reason = f"return:{ident}:{ident_reason}"
                        break
                    continue
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


def _binding_at(graph: SyntaxGraph, symbol_id: str, def_index: int) -> Binding | None:
    for binding in graph.bindings:
        if binding.symbol_id == symbol_id and binding.definition_index == def_index:
            return binding
    return None


def _parameter_def_index(graph: SyntaxGraph, symbol_id: str) -> int:
    matches = [b for b in graph.bindings if b.symbol_id == symbol_id]
    params = [
        b
        for b in matches
        if b.kind is SymbolKind.PARAMETER
        or b.declarator == "param"
        or (_empty_rhs(b) and b.is_declaration)
    ]
    if params:
        return min(b.definition_index for b in params)
    if matches:
        return min(b.definition_index for b in matches)
    return 0


def _interprocedural(
    graph: SyntaxGraph,
    tainted: dict[str, str],
    source_pats: Sequence[str] = (),
    *,
    state: TaintState | None = None,
) -> list[tuple[str, str]]:
    """Parameter and return edges (symbol, reason). Tests inspect this shape."""
    return [
        (sid, reason)
        for sid, reason, _idx in _interprocedural_edges(graph, tainted, source_pats, state=state)
    ]


def _interprocedural_edges(
    graph: SyntaxGraph,
    tainted: dict[str, str],
    source_pats: Sequence[str] = (),
    *,
    state: TaintState | None = None,
) -> list[tuple[str, str, int]]:
    """Parameter and return propagation only when the callee is unique.

    Call-argument taint is attached to the *parameter* definition, not a later
    reassignment of the same name. Return taint is attached to the assignment
    whose RHS is that call, not a later definition of the same symbol.
    """
    new: list[tuple[str, str, int]] = []
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

    use_state = state or TaintState.from_final_map(tainted, source_pats)
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
        at_byte = _use_byte(call.span, call.line)
        for arg in args:
            reason = _argument_taint(arg, call.scope_id, use_state, source_pats, at_byte)
            if not reason:
                continue
            if arg.index < len(params):
                pname = params[arg.index].name
                sid = f"{callee_scope}::{pname}"
                new.append((sid, f"callarg:{arg.index}:{reason}", _parameter_def_index(graph, sid)))
    for ret in graph.returns:
        ret_reason = None
        for fragment in (*ret.accesses, *ret.idents):
            hit = fragment_matches_source(fragment, source_pats)
            if hit:
                ret_reason = f"return:source:{hit}"
                break
        if ret_reason is None:
            ret_byte = _use_byte(ret.span, ret.line)
            for ident in ret.idents:
                reason = use_state.reason_at_name(ident, ret.scope_id, ret_byte)
                if reason:
                    ret_reason = f"return:{ident}:{reason}"
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
                new.append((binding.symbol_id, ret_reason, binding.definition_index))
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
    tainted: TaintState | dict[str, str],
    *,
    argument_indexes: Sequence[int] | None = None,
    sanitizers: Sequence[SanitizerDefinition] = (),
) -> str | None:
    state = (
        tainted
        if isinstance(tainted, TaintState)
        else TaintState.from_final_map(tainted, source_pats)
    )
    at_byte = _use_byte(call.span, call.line)
    indexes = list(argument_indexes or [])
    if call.arguments and indexes:
        for index in indexes:
            arg = call.argument_at(index)
            if arg is None:
                continue
            reason = _argument_taint(arg, call.scope_id, state, source_pats, at_byte, sanitizers)
            if reason:
                return reason
        return None
    if call.arguments:
        for arg in call.arguments:
            reason = _argument_taint(arg, call.scope_id, state, source_pats, at_byte, sanitizers)
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
        reason = state.reason_at_name(ident, call.scope_id, at_byte)
        if reason:
            return f"from:{ident}:{reason}"
    return None


def _argument_taint(
    arg: CallArgument,
    scope_id: str,
    reaching: dict[str, _Reach] | TaintState,
    source_pats: Sequence[str],
    at_byte: int = 0,
    sanitizers: Sequence[SanitizerDefinition] = (),
) -> str | None:
    if arg.is_literal and not arg.dynamic and not arg.idents and not arg.accesses:
        return None
    if arg.callees and any(
        not _callee_is_source(callee, source_pats)
        and not _preserves_taint(callee)
        and not _callee_is_known_sanitizer(callee, sanitizers)
        for callee in arg.callees
    ):
        # An unknown call may replace its inputs. Do not assume it preserves taint.
        return None
    for fragment in (*arg.accesses, *arg.callees, *arg.idents):
        hit = fragment_matches_source(fragment, source_pats)
        if hit:
            return f"source:{hit}"
    if isinstance(reaching, TaintState):
        for ident in arg.idents:
            reason = reaching.reason_at_name(ident, scope_id, at_byte)
            if reason:
                return f"from:{ident}:{reason}"
        return None
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
