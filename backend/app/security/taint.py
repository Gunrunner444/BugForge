"""Scope-aware intra-procedural taint tracking over a SyntaxGraph.

Symbols are identified by ``scope_id::name``. ``function A``'s ``q`` is never
the same symbol as ``function B``'s ``q``. Source and sink matching uses
syntax-derived callees/accesses, never string-literal or comment text.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from app.analyzers.framework_detector import FrameworkInfo
from app.parsing.model import Binding, CallSite, SyntaxGraph
from app.security.definitions import (
    LanguageSecurityVocab,
    SanitizerDefinition,
    SinkDefinition,
    SourceDefinition,
)
from app.security.language_vocab import vocab_for

_IDENT = re.compile(r"[A-Za-z_$/][\w$]*")


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
    canon = _canon_qual(text)
    for pattern in patterns:
        try:
            if re.search(pattern, text) or re.search(_canon_qual(pattern), canon):
                return pattern
        except re.error:
            if pattern in text or _canon_qual(pattern) in canon:
                return pattern
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


def propagate_taint(
    graph: SyntaxGraph,
    sources: Sequence[SourceDefinition],
) -> dict[str, str]:
    """Map symbol_id → why it is considered user-controlled."""
    tainted: dict[str, str] = {}
    source_pats = tuple(p for src in sources for p in src.patterns)
    changed = True
    rounds = 0
    while changed and rounds < 16:
        changed = False
        rounds += 1
        for binding in graph.bindings:
            if binding.symbol_id in tainted:
                continue
            reason = _binding_taint(binding, source_pats, tainted, graph)
            if reason:
                tainted[binding.symbol_id] = reason
                changed = True
        # Limited intra-file inter-procedural: callee params and returns.
        for new_id, reason in _interprocedural(graph, tainted):
            if new_id not in tainted:
                tainted[new_id] = reason
                changed = True
    return tainted


def _binding_taint(
    binding: Binding,
    source_pats: Sequence[str],
    tainted: dict[str, str],
    graph: SyntaxGraph,
) -> str | None:
    if binding.rhs_is_literal and not binding.rhs_callees and not binding.rhs_accesses:
        return None
    for fragment in (*binding.rhs_accesses, *binding.rhs_callees, *binding.rhs_idents):
        hit = text_matches_any(fragment, source_pats)
        if hit:
            return f"source:{hit}"
    for ident in binding.rhs_idents:
        sid = _resolve_symbol(ident, binding.scope_id, tainted)
        if sid is not None:
            return f"from:{sid}:{tainted[sid]}"
    return None


def _resolve_symbol(name: str, scope_id: str, tainted: dict[str, str]) -> str | None:
    """Resolve ``name`` in ``scope_id``, then enclosing scopes, never sibling functions."""
    current: str | None = scope_id
    while current:
        candidate = f"{current}::{name}"
        if candidate in tainted:
            return candidate
        if "/" not in current:
            break
        current = current.rsplit("/", 1)[0]
    module = f"module::{name}"
    if module in tainted:
        return module
    return None


def _interprocedural(graph: SyntaxGraph, tainted: dict[str, str]) -> list[tuple[str, str]]:
    """Parameter → callee parameter and return → caller, only when unique."""
    new: list[tuple[str, str]] = []
    functions = {
        ent.name: ent
        for ent in graph.entities
        if ent.entity_type in {"function", "async_function", "method", "async_method"}
    }
    # name collisions: skip speculative resolution
    counts: dict[str, int] = {}
    for name in functions:
        counts[name] = counts.get(name, 0) + 1
    unique = {name: ent for name, ent in functions.items() if counts[name] == 1}

    for call in graph.calls:
        callee = unique.get(call.name)
        if callee is None:
            continue
        callee_scope = None
        for scope in graph.scopes:
            if scope.name == callee.name and scope.kind.value in {"function", "method"}:
                callee_scope = scope.scope_id
                break
        if callee_scope is None:
            continue
        for ident in call.argument_idents:
            sid = _resolve_symbol(ident, call.scope_id, tainted)
            if sid is None:
                continue
            if callee.parameters:
                pname = callee.parameters[0].name
                new.append((f"{callee_scope}::{pname}", f"callarg:{sid}"))
    for ret in graph.returns:
        for ident in ret.idents:
            sid = _resolve_symbol(ident, ret.scope_id, tainted)
            if sid is None:
                continue
            # taint caller assignments of this function
            func_name = ret.scope_id.rsplit(":", 1)[-1]
            for binding in graph.bindings:
                if (
                    func_name in binding.rhs_callees
                    or binding.rhs.endswith(f"{func_name}(")
                    or func_name in binding.rhs
                ):
                    if binding.scope_id != ret.scope_id:
                        # only if the rhs actually calls this function
                        if any(
                            c == func_name or c.endswith(f".{func_name}")
                            for c in binding.rhs_callees
                        ):
                            new.append((binding.symbol_id, f"return:{sid}"))
    return new


def call_taint_reason(
    call: CallSite,
    source_pats: Sequence[str],
    tainted: dict[str, str],
) -> str | None:
    if call.argument_is_literal and not call.dynamic and not call.argument_idents:
        return None
    for fragment in (*call.argument_accesses, *call.argument_idents):
        hit = text_matches_any(fragment, source_pats)
        if hit:
            return f"source:{hit}"
    for ident in call.argument_idents:
        sid = _resolve_symbol(ident, call.scope_id, tainted)
        if sid is not None:
            return f"from:{sid}:{tainted[sid]}"
    return None


def call_matches_sink(call: CallSite, sink: SinkDefinition) -> bool:
    haystacks = (call.qualified, call.name, f"{call.qualified}({call.argument_text})")
    for name in sink.api_names:
        name_n = _canon_qual(name)
        for hay in haystacks:
            hay_n = _canon_qual(hay)
            if hay == name or hay_n == name_n:
                return True
            if (
                hay.endswith(f".{name}")
                or hay.endswith(f"::{name}")
                or hay.endswith(f"->{name}")
                or hay_n.endswith(f".{name_n}")
            ):
                return True
            if (name in hay or name_n in hay_n) and ("." in name_n or "::" in name or "->" in name):
                return True
    return False


def argument_is_constant(call: CallSite) -> bool:
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
    call: CallSite, sanitizers: Sequence[SanitizerDefinition]
) -> SanitizerDefinition | None:
    fragments = (*call.argument_accesses, call.qualified, call.argument_text)
    for sanitizer in sanitizers:
        for name in sanitizer.api_names:
            if any(name in fragment for fragment in fragments):
                return sanitizer
    return None


def looks_parameterized_sql(argument_text: str) -> bool:
    return bool(re.search(r"""['\"].*(?:\?|\$\d+|%s|:\w+).*['\"]\s*,""", argument_text, re.DOTALL))


def identifiers_in(text: str) -> list[str]:
    return [m.group(0) for m in _IDENT.finditer(text)]


def language_vocab(graph: SyntaxGraph) -> LanguageSecurityVocab | None:
    return vocab_for(graph.language)
