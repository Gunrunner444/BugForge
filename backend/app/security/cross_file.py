"""Bounded cross-file taint for uniquely resolved local imports.

Only Python and JavaScript/TypeScript graphs produced by a full syntax parser
participate. Profile fallback is not dataflow. Ambiguous or unresolved names
produce no edge. A partial or truncated callee is not a summary. Limits stop
the walk and leave an explicit diagnostic; a stopped walk is not a clean result.

High-confidence extensions, still unique-identity only:

* Python and JS/TS re-exports, including package ``__init__.py`` and
  ``export { name } from ...``
* methods whose class is imported and constructed, or called as ``Class.method``
* no inheritance guessing and no dynamic dispatch
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
    _callee_is_source,
    _empty_rhs,
    _killing_assignment,
    _ordered_bindings,
    _peel_sanitizer,
    _preserves_taint,
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
class FlowEdge:
    """Stable repository edge. Identifiers are ``file::symbol``, never addresses."""

    kind: str
    source_id: str
    target_id: str


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
    decorators: tuple[str, ...] = ()


@dataclass
class ProjectFlow:
    """Import-resolved callees for one repository scan."""

    externals: dict[str, dict[str, ExternalCallee]] = field(default_factory=dict)
    diagnostics: list[FlowDiagnostic] = field(default_factory=list)
    edges: list[FlowEdge] = field(default_factory=list)
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

    eligible = {path: graph for path, graph in graphs.items() if _eligible(graph)}
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

    targets, classes, target_diag = _import_targets(
        eligible, max_reexport_depth=limits.max_import_depth
    )
    project.diagnostics.extend(target_diag)
    summaries: dict[tuple[str, str], _Summary] = {}
    edges = 0
    depth_limited = False
    changed = False

    if limits.max_rounds <= 0:
        project.incomplete = True
        project.diagnostics.append(
            FlowDiagnostic(
                kind="cross_file_incomplete",
                message="cross-file taint stopped before any propagation round",
                file_path="",
            )
        )
    else:
        for _round in range(limits.max_rounds):
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
                partial = _graph_partial(graph)
                for entity in _summarizable(graph):
                    if expired():
                        project.incomplete = True
                        project.diagnostics.append(
                            FlowDiagnostic(
                                kind="cross_file_incomplete",
                                message="cross-file taint budget exhausted",
                                file_path=path,
                            )
                        )
                        break
                    if edges >= limits.max_edges:
                        project.incomplete = True
                        project.diagnostics.append(
                            FlowDiagnostic(
                                kind="cross_file_incomplete",
                                message="cross-file taint stopped at configured edge limit",
                                file_path=path,
                            )
                        )
                        break
                    scope_id = _scope_for_entity(graph, entity)
                    if scope_id is None:
                        continue
                    summary_name = entity.qualified_name or entity.name
                    summary, used_edges, limited, capped = _summarize(
                        graph,
                        summary_name,
                        scope_id,
                        tuple(p.name for p in entity.parameters),
                        summaries,
                        targets,
                        partial=partial,
                        max_depth=limits.max_import_depth,
                        decorators=tuple(entity.decorators),
                        edge_budget=limits.max_edges - edges,
                    )
                    edges += used_edges
                    if limited:
                        depth_limited = True
                    if capped:
                        project.incomplete = True
                        project.diagnostics.append(
                            FlowDiagnostic(
                                kind="cross_file_incomplete",
                                message="cross-file taint stopped at configured edge limit",
                                file_path=path,
                            )
                        )
                    key = (path, summary_name)
                    if summaries.get(key) != summary:
                        summaries[key] = summary
                        changed = True
                    if project.incomplete:
                        break
                if project.incomplete:
                    break
            if project.incomplete or not changed:
                break
        else:
            if changed:
                project.incomplete = True
                project.diagnostics.append(
                    FlowDiagnostic(
                        kind="cross_file_incomplete",
                        message="cross-file taint stopped at max propagation rounds",
                        file_path="",
                    )
                )

    if depth_limited:
        project.incomplete = True
        project.diagnostics.append(
            FlowDiagnostic(
                kind="cross_file_depth_limited",
                message="cross-file taint stopped at max import depth",
                file_path="",
            )
        )
    project.externals, dropped, export_diag = _externals_from(
        eligible,
        summaries,
        targets,
        classes,
        max_depth=limits.max_import_depth,
    )
    project.diagnostics.extend(export_diag)
    if dropped and not any(item.kind == "cross_file_depth_limited" for item in project.diagnostics):
        project.incomplete = True
        project.diagnostics.append(
            FlowDiagnostic(
                kind="cross_file_depth_limited",
                message="cross-file taint stopped at max import depth",
                file_path="",
            )
        )
    project.edges = _flow_edges(targets, classes, project.externals)
    if any(item.kind == "cross_file_partial" for item in project.diagnostics):
        project.incomplete = True
    project.diagnostics = _stable_diagnostics(project.diagnostics)
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


def _graph_partial(graph: SyntaxGraph) -> bool:
    return bool(graph.diagnostics.truncated or graph.diagnostics.has_errors)


def _summarizable(graph: SyntaxGraph) -> list[ParsedEntity]:
    found: list[ParsedEntity] = []
    seen: set[str] = set()
    for entity in graph.entities:
        if entity.entity_type not in _FUNCTION_TYPES | {"method", "async_method"}:
            continue
        if entity.entity_type in _FUNCTION_TYPES and entity.parent:
            continue
        key = entity.qualified_name or entity.name
        if key in seen:
            continue
        seen.add(key)
        found.append(entity)
    return found


def _unique_classes(graph: SyntaxGraph) -> dict[str, ParsedEntity]:
    counts: dict[str, list[ParsedEntity]] = {}
    for entity in graph.entities:
        if entity.entity_type != "class" or entity.parent:
            continue
        counts.setdefault(entity.name, []).append(entity)
    return {name: ents[0] for name, ents in counts.items() if len(ents) == 1}


def _methods_by_class(graph: SyntaxGraph) -> dict[str, dict[str, ParsedEntity]]:
    grouped: dict[str, dict[str, list[ParsedEntity]]] = {}
    for entity in graph.entities:
        if entity.entity_type not in {"method", "async_method"} or not entity.parent:
            continue
        grouped.setdefault(entity.parent, {}).setdefault(entity.name, []).append(entity)
    unique: dict[str, dict[str, ParsedEntity]] = {}
    for class_name, methods in grouped.items():
        unique[class_name] = {name: ents[0] for name, ents in methods.items() if len(ents) == 1}
    return unique


def _symbol_id(file_path: str, name: str) -> str:
    return f"{file_path.replace(chr(92), '/')}::{name}"


def _stable_diagnostics(items: list[FlowDiagnostic]) -> list[FlowDiagnostic]:
    seen: set[tuple[str, str, str]] = set()
    ordered: list[FlowDiagnostic] = []
    for item in sorted(items, key=lambda diag: (diag.file_path, diag.kind, diag.message)):
        key = (item.file_path, item.kind, item.message)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(item)
    return ordered


def _flow_edges(
    targets: dict[tuple[str, str], tuple[str, str] | str],
    classes: dict[tuple[str, str], tuple[str, str]],
    externals: dict[str, dict[str, ExternalCallee]],
) -> list[FlowEdge]:
    edges: list[FlowEdge] = []
    seen: set[tuple[str, str, str]] = set()

    def add(kind: str, source: str, target: str) -> None:
        key = (kind, source, target)
        if key in seen:
            return
        seen.add(key)
        edges.append(FlowEdge(kind=kind, source_id=source, target_id=target))

    for (importer, local), target in sorted(targets.items()):
        if isinstance(target, tuple):
            add("import", _symbol_id(importer, local), _symbol_id(target[0], target[1]))
    for (importer, local), (file_path, class_name) in sorted(classes.items()):
        add("class_import", _symbol_id(importer, local), _symbol_id(file_path, class_name))
    for file_path, table in sorted(externals.items()):
        for local, ext in sorted(table.items()):
            add(
                "call",
                _symbol_id(file_path, local),
                ext.semantic_id or _symbol_id(ext.callee_file, ext.callee_function),
            )
    return edges


def _import_targets(
    graphs: dict[str, SyntaxGraph],
    *,
    max_reexport_depth: int,
) -> tuple[
    dict[tuple[str, str], tuple[str, str] | str],
    dict[tuple[str, str], tuple[str, str]],
    list[FlowDiagnostic],
]:
    """Map ``(importer, local call name)`` to ``(file, function)`` or ambiguous.

    ``classes`` maps ``(importer, local class name)`` to ``(file, class)``.
    Re-exports are followed only while the next hop is unique.
    """
    targets: dict[tuple[str, str], tuple[str, str] | str] = {}
    classes: dict[tuple[str, str], tuple[str, str]] = {}
    diagnostics: list[FlowDiagnostic] = []
    pending: list[tuple[str, str, str, str]] = []

    def bind(importer: str, local: str, value: tuple[str, str] | str, line_file: str) -> None:
        if not local:
            return
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

    def bind_class(importer: str, local: str, value: tuple[str, str], line_file: str) -> None:
        key = (importer, local)
        current = classes.get(key)
        if current is None:
            classes[key] = value
            return
        if current != value:
            classes.pop(key, None)
            diagnostics.append(
                FlowDiagnostic(
                    kind="ambiguous_import",
                    message=f"local class {local} resolves to more than one type",
                    file_path=line_file,
                )
            )

    for path, graph in sorted(graphs.items()):
        for imp in graph.imports:
            if imp.name == "*" or imp.syntax_kind == "export_star":
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
                if (
                    imp.import_type == "relative"
                    or imp.relative_level > 0
                    or _looks_relative(imp.module)
                ):
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
            if _graph_partial(target):
                diagnostics.append(
                    FlowDiagnostic(
                        kind="cross_file_partial",
                        message="partial callee graph is not a cross-file summary",
                        file_path=resolved,
                    )
                )
                continue
            names = _unique_function_names(target)
            class_names = _unique_classes(target)
            if _is_namespace_import(imp) or _is_module_alias_import(imp, names):
                alias = imp.alias or _module_alias(imp.module, imp.name) or imp.name or ""
                if not alias:
                    continue
                for func_name in sorted(names):
                    bind(path, f"{alias}.{func_name}", (resolved, func_name), path)
                for class_name in sorted(class_names):
                    bind_class(path, f"{alias}.{class_name}", (resolved, class_name), path)
                continue
            if imp.syntax_kind == "import_default":
                continue
            imported = imp.name
            if not imported:
                continue
            local = imp.alias or imported
            if imported in names:
                bind(path, local, (resolved, imported), path)
                continue
            if imported in class_names:
                bind_class(path, local, (resolved, imported), path)
                continue
            pending.append((path, local, resolved, imported))

    for _depth in range(max(0, max_reexport_depth)):
        if not pending:
            break
        progressed = False
        still: list[tuple[str, str, str, str]] = []
        for importer, local, src_file, src_name in pending:
            dest = targets.get((src_file, src_name))
            if isinstance(dest, tuple):
                bind(importer, local, dest, importer)
                progressed = True
                continue
            class_dest = classes.get((src_file, src_name))
            if class_dest is not None:
                bind_class(importer, local, class_dest, importer)
                progressed = True
                continue
            if dest == _AMBIGUOUS:
                bind(importer, local, _AMBIGUOUS, importer)
                continue
            still.append((importer, local, src_file, src_name))
        pending = still
        if not progressed:
            break
    return targets, classes, diagnostics


def _is_module_alias_import(imp: ParsedImport, function_names: dict[str, ParsedEntity]) -> bool:
    """``from . import helpers`` binds the module, not a function of that name."""
    if not imp.is_from_import or imp.module:
        return False
    imported = imp.name or ""
    return bool(imported) and imported not in function_names


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


def _resolve_python(importer: str, imp: ParsedImport, graphs: dict[str, SyntaxGraph]) -> str | None:
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


def _resolve_javascript(importer: str, module: str, graphs: dict[str, SyntaxGraph]) -> str | None:
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
    decorators: tuple[str, ...] = (),
    edge_budget: int = 10**9,
) -> tuple[_Summary, int, bool, bool]:
    vocab = vocab_for(graph.language)
    source_pats = tuple(p for src in vocab.sources for p in src.patterns) if vocab else ()
    sinks: tuple[SinkDefinition, ...] = vocab.sinks if vocab else ()
    sanitizers: tuple[SanitizerDefinition, ...] = vocab.sanitizers if vocab else ()
    param_index = {name: index for index, name in enumerate(parameters)}
    timeline: dict[str, list[tuple[int, frozenset[str]]]] = {}
    latest: dict[str, frozenset[str]] = {}
    edges = 0
    limited = False
    capped = False
    hops = 0

    def at(name: str, byte: int) -> frozenset[str]:
        hit: frozenset[str] = frozenset()
        for start, tokens in timeline.get(f"{scope_id}::{name}", []):
            if start <= byte:
                hit = tokens
            else:
                break
        return hit

    def usable(summary: _Summary | None) -> _Summary | None:
        if summary is None or summary.partial:
            return None
        if summary.file_path == graph.file_path and summary.function_name == function_name:
            return None
        return summary

    def resolve(call: CallSite) -> _Summary | None:
        if "." in function_name:
            parent = function_name.split(".", 1)[0]
            qualified_self = call.qualified
            for prefix in ("self.", "cls."):
                if qualified_self.startswith(prefix):
                    method = qualified_self[len(prefix) :]
                    if method and "." not in method:
                        return usable(summaries.get((graph.file_path, f"{parent}.{method}")))
        qualified = call.qualified if call.qualified and call.qualified != call.name else ""
        if qualified and ("." in qualified or "/" in qualified):
            target = targets.get((graph.file_path, qualified))
            if isinstance(target, tuple):
                return usable(summaries.get(target))
            if target == _AMBIGUOUS:
                return None
        locals_ = [entity for entity in _module_functions(graph) if entity.name == call.name]
        if len(locals_) > 1:
            return None
        if len(locals_) == 1 and "." not in call.qualified:
            return usable(summaries.get((graph.file_path, call.name)))
        for key in (call.qualified, call.name):
            target = targets.get((graph.file_path, key))
            if isinstance(target, tuple):
                return usable(summaries.get(target))
            if target == _AMBIGUOUS:
                return None
        return None

    for binding in _ordered_bindings(graph):
        if binding.scope_id != scope_id:
            continue
        byte = _use_byte(binding.span, binding.line)
        tokens, added, hop, hit_limit, hit_cap = _binding_tokens(
            binding,
            graph,
            scope_id,
            param_index,
            source_pats,
            sanitizers,
            at,
            resolve,
            max_depth,
            edge_budget - edges,
        )
        edges += added
        hops = max(hops, hop)
        limited = limited or hit_limit
        capped = capped or hit_cap
        if binding.is_conditional:
            tokens = tokens | latest.get(binding.symbol_id, frozenset())
        latest[binding.symbol_id] = tokens
        timeline.setdefault(binding.symbol_id, []).append((byte, tokens))

    returned: set[str] = set()
    for ret in graph.returns:
        if ret.scope_id != scope_id:
            continue
        byte = _use_byte(ret.span, ret.line)
        source_tokens: set[str] = set()
        for fragment in (*ret.accesses, *ret.idents):
            hit = fragment_matches_source(fragment, source_pats)
            if hit:
                source_tokens.add(f"source:{hit}")
        ident_tokens: set[str] = set()
        for ident in ret.idents:
            ident_tokens |= set(at(ident, byte))
        opaque = False
        from_calls: set[str] = set()
        for call in graph.calls:
            if call.scope_id != scope_id or call.line != ret.line:
                continue
            if _call_is_transparent(call, source_pats, sanitizers):
                continue
            summary = resolve(call)
            if summary is None:
                opaque = True
                continue
            if summary.file_path != graph.file_path:
                if summary.hops + 1 > max_depth:
                    limited = True
                    opaque = True
                    continue
                if edges >= edge_budget:
                    capped = True
                    opaque = True
                    continue
                edges += 1
                hops = max(hops, summary.hops + 1)
            if summary.return_effects:
                from_calls |= _instantiate(summary.return_effects, call, at, byte, source_pats)
            else:
                opaque = True
        if opaque:
            returned |= source_tokens | from_calls
        else:
            returned |= source_tokens | ident_tokens | from_calls
        sanitizer = _sanitizer_on(ret.accesses, sanitizers)
        if sanitizer is not None and sanitizer.effective and returned:
            returned = {f"sanitized:{sanitizer.kind}:{token}" for token in returned}

    param_sinks: set[tuple[int, str, str, int]] = set()
    for call in graph.calls:
        if call.scope_id != scope_id:
            continue
        summary = resolve(call)
        if (
            summary is not None
            and summary.file_path == graph.file_path
            and summary.function_name == function_name
        ):
            summary = None
        if summary is not None:
            cross = summary.file_path != graph.file_path
            if cross and summary.hops + 1 > max_depth:
                limited = True
                continue
            if cross:
                if edges >= edge_budget:
                    capped = True
                    continue
                edges += 1
                hops = max(hops, summary.hops + 1)
            for index, vuln, sink_name, line in summary.param_sinks:
                for token in _call_arg_tokens(
                    call, index, source_pats, at, _use_byte(call.span, call.line)
                ):
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
            indexes = (
                list(sink.argument_indexes) if sink.argument_indexes else _all_arg_indexes(call)
            )
            kinds = sink.sanitizer_kinds or tuple(
                SINK_SANITIZER_KINDS.get(sink.vulnerability_class, ())
            )
            if sanitizer_intervened(
                call, sanitizers, allowed_kinds=kinds, argument_indexes=indexes
            ):
                continue
            for index in indexes:
                for token in _call_arg_tokens(
                    call, index, source_pats, at, _use_byte(call.span, call.line)
                ):
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
                        (
                            param_i,
                            sink.vulnerability_class.value,
                            call.qualified or call.name,
                            call.line,
                        )
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
        decorators=decorators,
    )
    return summary, edges, limited, capped


def _call_is_transparent(
    call: CallSite,
    source_pats: tuple[str, ...],
    sanitizers: tuple[SanitizerDefinition, ...],
) -> bool:
    names = tuple(name for name in (call.qualified, call.name) if name)
    if any(_callee_is_source(name, source_pats) for name in names):
        return True
    if any(_preserves_taint(name) for name in names):
        return True
    return _sanitizer_on(names, sanitizers) is not None


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
    edge_budget: int,
) -> tuple[frozenset[str], int, int, bool, bool]:
    if (
        _empty_rhs(binding)
        and binding.name in param_index
        and (
            binding.kind is SymbolKind.PARAMETER
            or binding.declarator == "param"
            or binding.is_declaration
        )
    ):
        return frozenset({f"param:{param_index[binding.name]}"}), 0, 0, False, False
    if _killing_assignment(binding):
        return frozenset(), 0, 0, False, False
    source_tokens: set[str] = set()
    ident_tokens: set[str] = set()
    edges = 0
    hops = 0
    limited = False
    capped = False
    byte = _use_byte(binding.span, binding.line)
    for fragment in (*binding.rhs_accesses, *binding.rhs_callees, *binding.rhs_idents):
        hit = fragment_matches_source(fragment, source_pats)
        if hit:
            source_tokens.add(f"source:{hit}")
    for ident in binding.rhs_idents:
        ident_tokens |= set(at(ident, byte))
    opaque = False
    from_calls: set[str] = set()
    for call in graph.calls:
        if call.scope_id != scope_id or call.line != binding.line:
            continue
        if call.name not in binding.rhs_callees and call.qualified not in binding.rhs_callees:
            continue
        if _call_is_transparent(call, source_pats, sanitizers):
            continue
        summary = resolve(call)
        if summary is None:
            opaque = True
            continue
        if summary.file_path != graph.file_path and summary.hops + 1 > max_depth:
            limited = True
            opaque = True
            continue
        if summary.file_path != graph.file_path:
            if edges >= edge_budget:
                capped = True
                opaque = True
                continue
            edges += 1
            hops = max(hops, summary.hops + 1)
        if summary.return_effects:
            from_calls |= _instantiate(summary.return_effects, call, at, byte, source_pats)
        else:
            opaque = True
    if binding.rhs_callees and not opaque:
        seen = {
            call.qualified
            for call in graph.calls
            if call.scope_id == scope_id and call.line == binding.line
        }
        seen.update(
            call.name
            for call in graph.calls
            if call.scope_id == scope_id and call.line == binding.line
        )
        for callee in binding.rhs_callees:
            if _callee_is_source(callee, source_pats) or _preserves_taint(callee):
                continue
            if _sanitizer_on((callee,), sanitizers) is not None:
                continue
            if callee not in seen and callee.rsplit(".", 1)[-1] not in seen:
                opaque = True
    tokens = source_tokens | from_calls
    if not opaque:
        tokens |= ident_tokens
    sanitizer = _sanitizer_on(binding.rhs_callees, sanitizers)
    if sanitizer is not None and sanitizer.effective and tokens:
        tokens = {f"sanitized:{sanitizer.kind}:{token}" for token in tokens}
    return frozenset(tokens), edges, hops, limited, capped


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
        if (
            arg.is_literal
            and not arg.idents
            and not arg.accesses
            and not arg.callees
            and not arg.dynamic
        ):
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
    classes: dict[tuple[str, str], tuple[str, str]],
    *,
    max_depth: int,
) -> tuple[dict[str, dict[str, ExternalCallee]], bool, list[FlowDiagnostic]]:
    externals: dict[str, dict[str, ExternalCallee]] = {}
    diagnostics: list[FlowDiagnostic] = []
    dropped = False
    partial_files: set[str] = set()
    for path, graph in sorted(graphs.items()):
        local_functions = {entity.name for entity in _module_functions(graph)}
        caller_partial = _graph_partial(graph)
        table: dict[str, ExternalCallee] = {}
        for (importer, local), target in sorted(targets.items()):
            if importer != path or not isinstance(target, tuple):
                continue
            bare = local.rsplit(".", 1)[-1]
            if local in local_functions or (bare in local_functions and "." not in local):
                continue
            placed = _place_external(
                table,
                local,
                summaries.get(target),
                path,
                offset=0,
                caller_partial=caller_partial,
                max_depth=max_depth,
            )
            if placed == "partial":
                partial_files.add(target[0])
            elif placed == "depth":
                dropped = True
        file_classes = {
            local: dest for (importer, local), dest in classes.items() if importer == path
        }
        for local, (class_file, class_name) in sorted(file_classes.items()):
            methods = (
                _methods_by_class(graphs[class_file]).get(class_name, {})
                if class_file in graphs
                else {}
            )
            for method_name, _entity in sorted(methods.items()):
                summary = summaries.get((class_file, f"{class_name}.{method_name}"))
                explicit = _place_external(
                    table,
                    f"{local}.{method_name}",
                    summary,
                    path,
                    offset=_receiver_offset(summary, instance=False),
                    caller_partial=caller_partial,
                    max_depth=max_depth,
                )
                constructed = _place_external(
                    table,
                    f"{local}().{method_name}",
                    summary,
                    path,
                    offset=_receiver_offset(summary, instance=True),
                    caller_partial=caller_partial,
                    max_depth=max_depth,
                )
                if explicit == "partial" or constructed == "partial":
                    partial_files.add(class_file)
                if explicit == "depth" or constructed == "depth":
                    dropped = True
        for binding in _ordered_bindings(graph):
            for callee in binding.rhs_callees:
                simple = callee.rsplit(".", 1)[-1]
                if simple.startswith("new."):
                    simple = simple[4:]
                dest = file_classes.get(callee) or file_classes.get(simple)
                if dest is None:
                    continue
                class_file, class_name = dest
                methods = (
                    _methods_by_class(graphs[class_file]).get(class_name, {})
                    if class_file in graphs
                    else {}
                )
                for method_name in sorted(methods):
                    summary = summaries.get((class_file, f"{class_name}.{method_name}"))
                    placed = _place_external(
                        table,
                        f"{binding.name}.{method_name}",
                        summary,
                        path,
                        offset=_receiver_offset(summary, instance=True),
                        caller_partial=caller_partial,
                        max_depth=max_depth,
                    )
                    if placed == "partial":
                        partial_files.add(class_file)
                    elif placed == "depth":
                        dropped = True
        if table:
            externals[path] = dict(sorted(table.items()))
    for file_path in sorted(partial_files):
        diagnostics.append(
            FlowDiagnostic(
                kind="cross_file_partial",
                message="partial callee graph is not a cross-file summary",
                file_path=file_path,
            )
        )
    return externals, dropped, diagnostics


def _receiver_offset(summary: _Summary | None, *, instance: bool) -> int:
    if summary is None or not summary.parameters:
        return 0
    decorators = " ".join(summary.decorators)
    if "staticmethod" in decorators:
        return 0
    first = summary.parameters[0]
    if "classmethod" in decorators and first in {"cls", "self"}:
        return 1
    if first in {"self", "cls"}:
        return 1 if instance else 0
    return 0


def _shift_effect(effect: str, offset: int) -> str | None:
    kind, core = _peel_sanitizer(effect)
    if core.startswith("param:"):
        try:
            index = int(core.split(":", 1)[1])
        except ValueError:
            return None
        shifted = index - offset
        if shifted < 0:
            return None
        core = f"param:{shifted}"
    rendered = f"sanitized:{kind}:{core}" if kind else core
    return rendered


def _place_external(
    table: dict[str, ExternalCallee],
    local: str,
    summary: _Summary | None,
    importer: str,
    *,
    offset: int,
    caller_partial: bool,
    max_depth: int,
) -> str:
    if summary is None or summary.file_path == importer:
        return ""
    if summary.partial:
        return "partial"
    if summary.hops >= max_depth and (summary.return_effects or summary.param_sinks):
        return "depth"
    effects_list: list[str] = []
    for effect in summary.return_effects:
        shifted = _shift_effect(effect, offset)
        if shifted is not None:
            effects_list.append(shifted)
    effects = tuple(effects_list)
    sinks: list[tuple[int, str, str, int]] = []
    for index, vuln, name, line in summary.param_sinks:
        shifted_index = index - offset
        if shifted_index < 0:
            continue
        sinks.append((shifted_index, vuln, name, line))
    semantic_id = _symbol_id(summary.file_path, summary.function_name)
    previous = table.get(local)
    if previous is not None and previous.semantic_id and previous.semantic_id != semantic_id:
        table.pop(local, None)
        return ""
    table[local] = ExternalCallee(
        local_name=local,
        callee_file=summary.file_path,
        callee_function=summary.function_name,
        return_effects=tuple(sorted(effects)),
        param_sinks=tuple(sorted(sinks)),
        partial=caller_partial,
        hops=summary.hops,
        semantic_id=semantic_id,
    )
    return "ok"
