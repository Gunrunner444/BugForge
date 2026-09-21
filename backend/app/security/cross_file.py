"""Bounded cross-file taint for uniquely resolved local imports.

Only Python and JavaScript/TypeScript graphs produced by a full syntax parser
participate. Profile fallback is not dataflow. Ambiguous or unresolved names
produce no edge. Limits stop the walk and leave an explicit diagnostic; a
stopped walk is not a clean result.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from app.core.config import settings
from app.domain.language import ParserTier
from app.domain.security import VulnerabilityClass
from app.domain.source import ParsedEntity, ParsedImport
from app.parsing.model import Binding, CallSite, SymbolKind, SyntaxGraph
from app.security.definitions import SINK_SANITIZER_KINDS, SanitizerDefinition, SinkDefinition
from app.security.language_vocab import vocab_for
from app.security.taint import (
    ExternalCallee,
    _empty_rhs,
    _killing_assignment,
    _ordered_bindings,
    _peel_sanitizer,
    _scope_for_entity,
    _use_byte,
    call_matches_sink,
    fragment_matches_source,
    sanitizer_intervened,
)

_CROSS_FILE_LANGUAGES = frozenset({"python", "javascript", "typescript"})
_FUNCTION_TYPES = frozenset({"function", "async_function"})
_AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class CrossFileLimits:
    max_files: int = 400
    max_import_depth: int = 3
    max_rounds: int = 4
    max_edges: int = 2_000
    budget_ms: int = 1_500

    @staticmethod
    def from_settings() -> CrossFileLimits:
        return CrossFileLimits(
            max_files=settings.taint_max_files,
            max_import_depth=settings.taint_max_import_depth,
            max_rounds=settings.taint_max_cross_file_rounds,
            max_edges=settings.taint_max_cross_file_edges,
            budget_ms=settings.taint_cross_file_budget_ms,
        )


@dataclass(frozen=True)
class FlowDiagnostic:
    kind: str
    message: str
    file_path: str


@dataclass(frozen=True)
class _Summary:
    file_path: str
    function_name: str
    scope_id: str
    parameters: tuple[str, ...]
    return_effects: tuple[str, ...]
    param_sinks: tuple[tuple[int, str, str, int], ...]
    hops: int = 0
    partial: bool = False


@dataclass
class ProjectFlow:
    """Import-resolved callees for one repository scan."""

    externals: dict[str, dict[str, ExternalCallee]] = field(default_factory=dict)
    diagnostics: list[FlowDiagnostic] = field(default_factory=list)
    incomplete: bool = False

    def externals_for(self, file_path: str) -> dict[str, ExternalCallee]:
        return self.externals.get(file_path, {})

    def lookup(self, file_path: str, call: CallSite) -> ExternalCallee | None:
        table = self.externals_for(file_path)
        for key in (call.qualified, call.name):
            hit = table.get(key)
            if hit is not None:
                return hit
        return None


def build_project(
    graphs: dict[str, SyntaxGraph],
    *,
    limits: CrossFileLimits | None = None,
) -> ProjectFlow:
    limits = limits or CrossFileLimits.from_settings()
    project = ProjectFlow()
    started = time.monotonic()

    def expired() -> bool:
        if limits.budget_ms <= 0:
            return True
        return (time.monotonic() - started) * 1000 >= limits.budget_ms

    if expired():
        project.incomplete = True
        project.diagnostics.append(
            FlowDiagnostic(
                kind="cross_file_incomplete",
                message="cross-file taint budget exhausted before propagation",
                file_path="",
            )
        )
        return project

    eligible = {
        path: graph
        for path, graph in graphs.items()
        if _eligible(graph)
    }
    ordered = sorted(eligible)
    if len(ordered) > limits.max_files:
        project.incomplete = True
        project.diagnostics.append(
            FlowDiagnostic(
                kind="cross_file_incomplete",
                message=f"cross-file taint stopped after {limits.max_files} files",
                file_path=ordered[limits.max_files],
            )
        )
        ordered = ordered[: limits.max_files]
        eligible = {path: eligible[path] for path in ordered}

    targets, target_diag = _import_targets(eligible)
    project.diagnostics.extend(target_diag)
    summaries: dict[tuple[str, str], _Summary] = {}
    edges = 0
    depth_limited = False

    for _round in range(max(1, limits.max_rounds)):
        if expired():
            project.incomplete = True
            project.diagnostics.append(
                FlowDiagnostic(
                    kind="cross_file_incomplete",
                    message="cross-file taint budget exhausted",
                    file_path="",
                )
            )
            break
        changed = False
        for path in ordered:
            graph = eligible[path]
            partial = bool(graph.diagnostics.truncated or graph.diagnostics.has_errors)
            for entity in _module_functions(graph):
                if expired() or edges > limits.max_edges:
                    project.incomplete = True
                    project.diagnostics.append(
                        FlowDiagnostic(
                            kind="cross_file_incomplete",
                            message="cross-file taint stopped at configured edge or time limit",
                            file_path=path,
                        )
                    )
                    break
                scope_id = _scope_for_entity(graph, entity)
                if scope_id is None:
                    continue
                summary, used_edges, limited = _summarize(
                    graph,
                    entity.name,
                    scope_id,
                    tuple(p.name for p in entity.parameters),
                    summaries,
                    targets,
                    partial=partial,
                    max_depth=limits.max_import_depth,
                )
                edges += used_edges
                if limited:
                    depth_limited = True
                key = (path, entity.name)
                if summaries.get(key) != summary:
                    summaries[key] = summary
                    changed = True
            if project.incomplete:
                break
        if project.incomplete or not changed:
            break

    if depth_limited:
        project.incomplete = True
        project.diagnostics.append(
            FlowDiagnostic(
                kind="cross_file_depth_limited",
                message="cross-file taint stopped at max import depth",
                file_path="",
            )
        )
    project.externals, dropped = _externals_from(
        eligible, summaries, targets, max_depth=limits.max_import_depth
    )
    if dropped and not any(item.kind == "cross_file_depth_limited" for item in project.diagnostics):
        project.incomplete = True
        project.diagnostics.append(
            FlowDiagnostic(
                kind="cross_file_depth_limited",
                message="cross-file taint stopped at max import depth",
                file_path="",
            )
        )
    return project


def _eligible(graph: SyntaxGraph) -> bool:
    if graph.language not in _CROSS_FILE_LANGUAGES:
        return False
    return graph.parser_tier is ParserTier.FULL_AST


def _module_functions(graph: SyntaxGraph) -> list[ParsedEntity]:
    found: list[ParsedEntity] = []
    for entity in graph.entities:
        if entity.parent:
            continue
        if entity.entity_type not in _FUNCTION_TYPES:
            continue
        found.append(entity)
    return found


def _unique_function_names(graph: SyntaxGraph) -> dict[str, ParsedEntity]:
    counts: dict[str, list[ParsedEntity]] = {}
    for entity in _module_functions(graph):
        counts.setdefault(entity.name, []).append(entity)
    return {name: ents[0] for name, ents in counts.items() if len(ents) == 1}


def _import_targets(
    graphs: dict[str, SyntaxGraph],
) -> tuple[dict[tuple[str, str], tuple[str, str] | str], list[FlowDiagnostic]]:
    """Map ``(importer, local call name)`` to ``(file, function)`` or ambiguous."""
    targets: dict[tuple[str, str], tuple[str, str] | str] = {}
    diagnostics: list[FlowDiagnostic] = []

    def bind(importer: str, local: str, value: tuple[str, str] | str, line_file: str) -> None:
        key = (importer, local)
        current = targets.get(key)
        if current is None:
            targets[key] = value
            return
        if current != value:
            targets[key] = _AMBIGUOUS
            diagnostics.append(
                FlowDiagnostic(
                    kind="ambiguous_import",
                    message=f"local name {local} resolves to more than one function",
                    file_path=line_file,
                )
            )

    for path, graph in sorted(graphs.items()):
        for imp in graph.imports:
            if imp.name == "*":
                diagnostics.append(
                    FlowDiagnostic(
                        kind="ambiguous_import",
                        message="star import is not a dataflow edge",
                        file_path=path,
                    )
                )
                continue
            resolved = _resolve_module(graph, imp, graphs)
            if resolved is None:
                if imp.import_type == "relative" or imp.relative_level > 0 or _looks_relative(imp.module):
                    diagnostics.append(
                        FlowDiagnostic(
                            kind="unresolved_import",
                            message=f"relative import {imp.module or imp.name or ''} was not resolved",
                            file_path=path,
                        )
                    )
                continue
            if resolved == _AMBIGUOUS:
                diagnostics.append(
                    FlowDiagnostic(
                        kind="ambiguous_import",
                        message=f"import {imp.module or imp.name or ''} matches more than one file",
                        file_path=path,
                    )
                )
                local = _local_name(imp)
                if local:
                    bind(path, local, _AMBIGUOUS, path)
                continue
            target = graphs.get(resolved)
            if target is None:
                continue
            names = _unique_function_names(target)
            if _is_namespace_import(imp):
                alias = imp.alias or _module_alias(imp.module, imp.name)
                if not alias:
                    continue
                for func_name in sorted(names):
                    bind(path, f"{alias}.{func_name}", (resolved, func_name), path)
                continue
            if imp.syntax_kind == "import_default":
                continue
            imported = imp.name
            if not imported or imported not in names:
                continue
            local = imp.alias or imported
            bind(path, local, (resolved, imported), path)
    return targets, diagnostics


def _is_namespace_import(imp: ParsedImport) -> bool:
    if imp.syntax_kind == "import_namespace":
        return True
    if imp.syntax_kind == "import":
        return True
    return not imp.is_from_import and not imp.name


def _local_name(imp: ParsedImport) -> str:
    if imp.alias:
        return imp.alias
    if imp.name:
        return imp.name
    return _module_alias(imp.module, None)


def _module_alias(module: str, name: str | None) -> str:
    text = name or module
    text = text.replace("\\", "/").rstrip("/")
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    if text.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".py")):
        text = text.rsplit(".", 1)[0]
    if "." in text and "/" not in module:
        return text.rsplit(".", 1)[-1]
    return text


def _looks_relative(module: str) -> bool:
    return module.startswith("./") or module.startswith("../") or module.startswith(".")


def _resolve_module(
    graph: SyntaxGraph, imp: ParsedImport, graphs: dict[str, SyntaxGraph]
) -> str | None:
    if graph.language == "python":
        return _resolve_python(graph.file_path, imp, graphs)
    if graph.language in {"javascript", "typescript"}:
        return _resolve_javascript(graph.file_path, imp.module, graphs)
    return None


def _resolve_python(
    importer: str, imp: ParsedImport, graphs: dict[str, SyntaxGraph]
) -> str | None:
    level = imp.relative_level
    module = imp.module
    if level <= 0 and imp.import_type == "relative":
        level = 1
    if not module and imp.is_from_import and imp.name and level > 0:
        module = imp.name
        # `from . import helpers` binds the submodule, not a function.
    if level > 0:
        return _python_relative_file(importer, module, level, graphs)
    if not module:
        return None
    return _unique_suffix(module, graphs, "python")


def _python_relative_file(
    importer: str, module: str, level: int, graphs: dict[str, SyntaxGraph]
) -> str | None:
    directory = PurePosixPath(importer).parent
    for _ in range(level - 1):
        if directory == PurePosixPath("."):
            return None
        directory = directory.parent
    parts = [part for part in module.split(".") if part]
    base = directory.joinpath(*parts) if parts else directory
    norm = PurePosixPath(os.path.normpath(base.as_posix()))
    if ".." in norm.parts:
        return None
    candidates = []
    for suffix in (".py", "/__init__.py"):
        cand = f"{norm.as_posix()}{suffix}"
        if cand in graphs and graphs[cand].language == "python":
            candidates.append(cand)
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        return _AMBIGUOUS
    return None


def _unique_suffix(module: str, graphs: dict[str, SyntaxGraph], language: str) -> str | None:
    parts = [part for part in module.replace("\\", "/").split(".") if part and part != "/"]
    if not parts or any(part in {"..", "."} for part in parts):
        return None
    suffix_py = "/".join(parts) + ".py"
    suffix_init = "/".join(parts) + "/__init__.py"
    hits: list[str] = []
    for path, graph in graphs.items():
        if graph.language != language:
            continue
        norm = path.replace("\\", "/")
        if norm == suffix_py or norm.endswith("/" + suffix_py):
            hits.append(path)
        elif norm == suffix_init or norm.endswith("/" + suffix_init):
            hits.append(path)
    unique = sorted(set(hits))
    if len(unique) == 1:
        return unique[0]
    if len(unique) > 1:
        return _AMBIGUOUS
    return None


def _resolve_javascript(
    importer: str, module: str, graphs: dict[str, SyntaxGraph]
) -> str | None:
    if not _looks_relative(module):
        return None
    raw = os.path.normpath(str(PurePosixPath(importer).parent / module))
    norm = PurePosixPath(raw)
    if ".." in norm.parts:
        return None
    text = norm.as_posix()
    suffixes = [""]
    if PurePosixPath(text).suffix not in {".js", ".jsx", ".mjs", ".ts", ".tsx"}:
        suffixes = ["", ".js", ".jsx", ".mjs", ".ts", ".tsx", "/index.js", "/index.ts"]
    hits: list[str] = []
    for suffix in suffixes:
        cand = text + suffix
        graph = graphs.get(cand)
        if graph is not None and graph.language in {"javascript", "typescript"}:
            hits.append(cand)
    unique = sorted(set(hits))
    if len(unique) == 1:
        return unique[0]
    if len(unique) > 1:
        return _AMBIGUOUS
    return None


def _summarize(
    graph: SyntaxGraph,
    function_name: str,
    scope_id: str,
    parameters: tuple[str, ...],
    summaries: dict[tuple[str, str], _Summary],
    targets: dict[tuple[str, str], tuple[str, str] | str],
    *,
    partial: bool,
    max_depth: int,
) -> tuple[_Summary, int, bool]:
    vocab = vocab_for(graph.language)
    source_pats = tuple(p for src in vocab.sources for p in src.patterns) if vocab else ()
    sinks: tuple[SinkDefinition, ...] = vocab.sinks if vocab else ()
    sanitizers: tuple[SanitizerDefinition, ...] = vocab.sanitizers if vocab else ()
    param_index = {name: index for index, name in enumerate(parameters)}
    timeline: dict[str, list[tuple[int, frozenset[str]]]] = {}
    latest: dict[str, frozenset[str]] = {}
    edges = 0
    limited = False
    hops = 0

    def at(name: str, byte: int) -> frozenset[str]:
        hit: frozenset[str] = frozenset()
        for start, tokens in timeline.get(f"{scope_id}::{name}", []):
            if start <= byte:
                hit = tokens
            else:
                break
        return hit

    def resolve(call: CallSite) -> _Summary | None:
        qualified = call.qualified if call.qualified and call.qualified != call.name else ""
        if qualified and ("." in qualified or "/" in qualified):
            target = targets.get((graph.file_path, qualified))
            if isinstance(target, tuple):
                return summaries.get(target)
            return None
        locals_ = [entity for entity in _module_functions(graph) if entity.name == call.name]
        if len(locals_) > 1:
            return None
        if len(locals_) == 1:
            return summaries.get((graph.file_path, call.name))
        for key in (call.qualified, call.name):
            target = targets.get((graph.file_path, key))
            if isinstance(target, tuple):
                return summaries.get(target)
            if target == _AMBIGUOUS:
                return None
        return None

    for binding in _ordered_bindings(graph):
        if binding.scope_id != scope_id:
            continue
        byte = _use_byte(binding.span, binding.line)
        tokens, added, hop, hit_limit = _binding_tokens(
            binding,
            graph,
            scope_id,
            param_index,
            source_pats,
            sanitizers,
            at,
            resolve,
            max_depth,
        )
        edges += added
        hops = max(hops, hop)
        limited = limited or hit_limit
        if binding.is_conditional:
            tokens = tokens | latest.get(binding.symbol_id, frozenset())
        latest[binding.symbol_id] = tokens
        timeline.setdefault(binding.symbol_id, []).append((byte, tokens))

    returned: set[str] = set()
    for ret in graph.returns:
        if ret.scope_id != scope_id:
            continue
        byte = _use_byte(ret.span, ret.line)
        for fragment in (*ret.accesses, *ret.idents):
            hit = fragment_matches_source(fragment, source_pats)
            if hit:
                returned.add(f"source:{hit}")
        for ident in ret.idents:
            returned |= set(at(ident, byte))
        for call in graph.calls:
            if call.scope_id != scope_id or call.line != ret.line:
                continue
            summary = resolve(call)
            if summary is None:
                continue
            if summary.file_path != graph.file_path:
                if summary.hops + 1 > max_depth:
                    limited = True
                    continue
                edges += 1
                hops = max(hops, summary.hops + 1)
            returned |= _instantiate(summary.return_effects, call, at, byte, source_pats)
        sanitizer = _sanitizer_on(ret.accesses, sanitizers)
        if sanitizer is not None and sanitizer.effective and returned:
            returned = {f"sanitized:{sanitizer.kind}:{token}" for token in returned}

    param_sinks: set[tuple[int, str, str, int]] = set()
    for call in graph.calls:
        if call.scope_id != scope_id:
            continue
        summary = resolve(call)
        if summary is not None and summary.file_path == graph.file_path and summary.function_name == function_name:
            summary = None
        if summary is not None:
            cross = summary.file_path != graph.file_path
            if cross and summary.hops + 1 > max_depth:
                limited = True
                continue
            if cross:
                edges += 1
                hops = max(hops, summary.hops + 1)
            for index, vuln, sink_name, line in summary.param_sinks:
                for token in _call_arg_tokens(call, index, source_pats, at, _use_byte(call.span, call.line)):
                    kind, core = _peel_sanitizer(token)
                    if not core.startswith("param:"):
                        continue
                    if kind and _kind_blocks(kind, vuln):
                        continue
                    try:
                        param_i = int(core.split(":", 1)[1])
                    except ValueError:
                        continue
                    param_sinks.add((param_i, vuln, sink_name, line))
            continue
        for sink in sinks:
            if sink.required_context:
                continue
            if not call_matches_sink(call, sink):
                continue
            indexes = list(sink.argument_indexes) if sink.argument_indexes else _all_arg_indexes(call)
            kinds = sink.sanitizer_kinds or tuple(SINK_SANITIZER_KINDS.get(sink.vulnerability_class, ()))
            if sanitizer_intervened(call, sanitizers, allowed_kinds=kinds, argument_indexes=indexes):
                continue
            for index in indexes:
                for token in _call_arg_tokens(call, index, source_pats, at, _use_byte(call.span, call.line)):
                    kind, core = _peel_sanitizer(token)
                    if not core.startswith("param:"):
                        continue
                    if kind and kind in kinds:
                        continue
                    try:
                        param_i = int(core.split(":", 1)[1])
                    except ValueError:
                        continue
                    param_sinks.add(
                        (param_i, sink.vulnerability_class.value, call.qualified or call.name, call.line)
                    )

    summary = _Summary(
        file_path=graph.file_path,
        function_name=function_name,
        scope_id=scope_id,
        parameters=parameters,
        return_effects=tuple(sorted(returned)),
        param_sinks=tuple(sorted(param_sinks)),
        hops=hops,
        partial=partial,
    )
    return summary, edges, limited


def _binding_tokens(
    binding: Binding,
    graph: SyntaxGraph,
    scope_id: str,
    param_index: dict[str, int],
    source_pats: tuple[str, ...],
    sanitizers: tuple[SanitizerDefinition, ...],
    at: Callable[[str, int], frozenset[str]],
    resolve: Callable[[CallSite], _Summary | None],
    max_depth: int,
) -> tuple[frozenset[str], int, int, bool]:
    if (
        _empty_rhs(binding)
        and binding.name in param_index
        and (
            binding.kind is SymbolKind.PARAMETER
            or binding.declarator == "param"
            or binding.is_declaration
        )
    ):
        return frozenset({f"param:{param_index[binding.name]}"}), 0, 0, False
    if _killing_assignment(binding):
        return frozenset(), 0, 0, False
    tokens: set[str] = set()
    edges = 0
    hops = 0
    limited = False
    byte = _use_byte(binding.span, binding.line)
    for fragment in (*binding.rhs_accesses, *binding.rhs_callees, *binding.rhs_idents):
        hit = fragment_matches_source(fragment, source_pats)
        if hit:
            tokens.add(f"source:{hit}")
    for ident in binding.rhs_idents:
        tokens |= set(at(ident, byte))
    for call in graph.calls:
        if call.scope_id != scope_id or call.line != binding.line:
            continue
        if call.name not in binding.rhs_callees and call.qualified not in binding.rhs_callees:
            continue
        summary = resolve(call)
        if summary is None or not summary.return_effects:
            continue
        if summary.file_path != graph.file_path and summary.hops + 1 > max_depth:
            limited = True
            continue
        if summary.file_path != graph.file_path:
            edges += 1
            hops = max(hops, summary.hops + 1)
        tokens |= _instantiate(summary.return_effects, call, at, byte, source_pats)
    sanitizer = _sanitizer_on(binding.rhs_callees, sanitizers)
    if sanitizer is not None and sanitizer.effective and tokens:
        tokens = {f"sanitized:{sanitizer.kind}:{token}" for token in tokens}
    return frozenset(tokens), edges, hops, limited


def _instantiate(
    effects: tuple[str, ...],
    call: CallSite,
    at: Callable[[str, int], frozenset[str]],
    byte: int,
    source_pats: tuple[str, ...],
) -> set[str]:
    out: set[str] = set()
    for effect in effects:
        kind, core = _peel_sanitizer(effect)
        produced: set[str] = set()
        if core.startswith("source:"):
            produced.add(core)
        elif core.startswith("param:"):
            try:
                index = int(core.split(":", 1)[1])
            except ValueError:
                continue
            produced |= _call_arg_tokens(call, index, source_pats, at, byte)
        for token in produced:
            out.add(f"sanitized:{kind}:{token}" if kind else token)
    return out


def _call_arg_tokens(
    call: CallSite,
    index: int,
    source_pats: tuple[str, ...],
    at: Callable[[str, int], frozenset[str]],
    byte: int,
) -> set[str]:
    arg = call.argument_at(index) if call.arguments else None
    if arg is not None:
        if arg.is_literal and not arg.idents and not arg.accesses and not arg.callees and not arg.dynamic:
            return set()
        fragments = (*arg.accesses, *arg.callees, *arg.idents)
        idents = arg.idents
    elif index == 0:
        fragments = (*call.argument_accesses, *call.argument_idents)
        idents = call.argument_idents
    else:
        return set()
    tokens: set[str] = set()
    for fragment in fragments:
        hit = fragment_matches_source(fragment, source_pats)
        if hit:
            tokens.add(f"source:{hit}")
    for ident in idents:
        tokens |= set(at(ident, byte))
    return tokens


def _all_arg_indexes(call: CallSite) -> list[int]:
    if call.arguments:
        return [arg.index for arg in call.arguments]
    return [0]


def _sanitizer_on(
    fragments: tuple[str, ...], sanitizers: tuple[SanitizerDefinition, ...]
) -> SanitizerDefinition | None:
    for sanitizer in sanitizers:
        for name in sanitizer.api_names:
            for fragment in fragments:
                if fragment == name or fragment.endswith("." + name):
                    return sanitizer
    return None


def _kind_blocks(kind: str, vuln_value: str) -> bool:
    try:
        vuln = VulnerabilityClass(vuln_value)
    except ValueError:
        return False
    return kind in SINK_SANITIZER_KINDS.get(vuln, frozenset())


def _externals_from(
    graphs: dict[str, SyntaxGraph],
    summaries: dict[tuple[str, str], _Summary],
    targets: dict[tuple[str, str], tuple[str, str] | str],
    *,
    max_depth: int,
) -> tuple[dict[str, dict[str, ExternalCallee]], bool]:
    externals: dict[str, dict[str, ExternalCallee]] = {}
    dropped = False
    for path, graph in graphs.items():
        local_functions = {entity.name for entity in _module_functions(graph)}
        table: dict[str, ExternalCallee] = {}
        for (importer, local), target in sorted(targets.items()):
            if importer != path or not isinstance(target, tuple):
                continue
            bare = local.rsplit(".", 1)[-1]
            if local in local_functions or bare in local_functions and "." not in local:
                continue
            summary = summaries.get(target)
            if summary is None or summary.file_path == path:
                continue
            # The caller consumes one more hop than the callee summary already used.
            if summary.hops >= max_depth and (summary.return_effects or summary.param_sinks):
                dropped = True
                continue
            table[local] = ExternalCallee(
                local_name=local,
                callee_file=summary.file_path,
                callee_function=summary.function_name,
                return_effects=summary.return_effects,
                param_sinks=summary.param_sinks,
                partial=summary.partial,
            )
        if table:
            externals[path] = table
    return externals, dropped
