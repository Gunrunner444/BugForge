"""Taint-aware source→sink security rules using semantic vocabularies."""

from __future__ import annotations

from collections.abc import Sequence

from app.analyzers.framework_detector import FrameworkInfo
from app.domain.security import VulnerabilityClass
from app.parsing.model import CallSite, SyntaxGraph
from app.security.definitions import (
    LanguageSecurityVocab,
    PathIssueKind,
    SinkCertainty,
    SinkDefinition,
)
from app.security.rules.base import RuleDocumentation, SecurityObservation, SecurityRule
from app.security.taint import (
    ExternalCallee,
    TaintState,
    _external_for_call,
    analyze_taint,
    applicable_sanitizer_kinds,
    argument_is_constant,
    call_matches_sink,
    call_taint_reason,
    language_vocab,
    looks_parameterized_sql,
    reaching_sanitizer_kind,
    sanitizer_intervened,
    vocab_sources,
)


class TaintFlowRule(SecurityRule):
    """Flag user-controlled data reaching a dangerous sink.

    Does not prove exploitability. Requires a syntax graph, not a keyword search.
    """

    def __init__(
        self,
        *,
        rule_id: str,
        vulnerability_class: VulnerabilityClass,
        documentation: RuleDocumentation,
    ) -> None:
        self.rule_id = rule_id
        self.vulnerability_class = vulnerability_class
        self.documentation = documentation

    def check(
        self,
        graph: SyntaxGraph,
        *,
        frameworks: Sequence[FrameworkInfo] = (),
        project: object | None = None,
    ) -> list[SecurityObservation]:
        vocab = language_vocab(graph)
        if vocab is None:
            return []
        sinks = [
            sink
            for sink in vocab.sinks
            if sink.vulnerability_class is self.vulnerability_class
            or (
                self.vulnerability_class is VulnerabilityClass.UNSAFE_DESERIALIZATION
                and sink.vulnerability_class is VulnerabilityClass.POTENTIAL_UNSAFE_DESERIALIZATION
            )
            or (
                self.vulnerability_class is VulnerabilityClass.POTENTIAL_PATH_TRAVERSAL
                and sink.vulnerability_class is VulnerabilityClass.POTENTIAL_PATH_TRAVERSAL
            )
        ]
        if not sinks:
            return []
        sources = vocab_sources(vocab, frameworks)
        source_pats = tuple(p for src in sources for p in src.patterns)
        externals = _externals(project, graph.file_path)
        taint_state = analyze_taint(graph, sources, externals=externals or None)
        framework_name = (
            ",".join(
                fw.name
                for fw in frameworks
                if fw.language.split("/")[0] in {graph.language, "javascript", "typescript"}
            )
            or ""
        )
        observations: list[SecurityObservation] = []
        seen: set[tuple[str, int, str, str]] = set()
        for call in graph.calls:
            matched = next((sink for sink in sinks if call_matches_sink(call, sink)), None)
            if matched is None:
                continue
            if matched.required_context and matched.required_context not in graph.semantic_context:
                if matched.required_context != graph.file_context:
                    continue
            indexes = matched.argument_indexes
            if argument_is_constant(call, argument_indexes=indexes or None):
                continue
            if (
                self.vulnerability_class is VulnerabilityClass.SQL_INJECTION
                and looks_parameterized_sql(call)
            ):
                continue
            taint = call_taint_reason(
                call,
                source_pats,
                taint_state,
                argument_indexes=indexes or None,
                sanitizers=vocab.sanitizers,
            )
            if not taint and not call.dynamic:
                continue
            if indexes and call.arguments:
                # Taint must touch a dangerous argument, not an unrelated slot.
                if not taint:
                    continue
            kinds = applicable_sanitizer_kinds(matched)
            sanitizer = sanitizer_intervened(
                call,
                vocab.sanitizers,
                allowed_kinds=kinds,
                argument_indexes=indexes or None,
            )
            if sanitizer is not None and sanitizer.effective:
                continue
            if _sanitizer_blocks_reason(taint or "", kinds):
                continue
            confidence = "high" if taint else "medium"
            if sanitizer is not None:
                confidence = "low"
            vuln = matched.vulnerability_class
            if vuln is VulnerabilityClass.POTENTIAL_PATH_TRAVERSAL:
                path_kind = _path_kind(call, taint)
            else:
                path_kind = None
            key = (graph.file_path, call.line, call.qualified, str(indexes))
            if key in seen:
                continue
            seen.add(key)
            local_extra: dict[str, str] = {}
            if taint_state.incomplete:
                local_extra["analysis_incomplete"] = taint_state.limit_reason or "bounded"
            if taint and "merge:" in taint:
                local_extra["branch_merge"] = "true"
            observations.append(
                _observation(
                    self,
                    graph,
                    call,
                    matched,
                    confidence,
                    taint=taint or "dynamic_construction",
                    framework=framework_name or graph.framework,
                    path_kind=path_kind,
                    sanitizer=sanitizer.sanitizer_id if sanitizer else "",
                    argument_index=indexes[0] if indexes else matched.argument_index,
                    extra=local_extra or None,
                )
            )
        if externals:
            observations.extend(
                _cross_file_observations(
                    self,
                    graph,
                    externals,
                    sinks,
                    taint_state,
                    source_pats,
                    vocab,
                    framework_name,
                    seen,
                )
            )
        return observations


def _externals(project: object | None, file_path: str) -> dict[str, ExternalCallee]:
    if project is None:
        return {}
    getter = getattr(project, "externals_for", None)
    if not callable(getter):
        return {}
    table = getter(file_path)
    return dict(table or {})


def _sanitizer_blocks_reason(taint: str, kinds: tuple[str, ...] | list[str]) -> bool:
    if not taint or not kinds:
        return False
    kind = reaching_sanitizer_kind(taint)
    return kind is not None and kind in set(kinds)


def _cross_file_observations(
    rule: TaintFlowRule,
    graph: SyntaxGraph,
    externals: dict[str, ExternalCallee],
    sinks: list[SinkDefinition],
    taint_state: TaintState,
    source_pats: tuple[str, ...],
    vocab: object,
    framework_name: str,
    seen: set[tuple[str, int, str, str]],
) -> list[SecurityObservation]:
    if not isinstance(vocab, LanguageSecurityVocab):
        return []
    observations: list[SecurityObservation] = []
    for call in graph.calls:
        ext = _external_for_call(call, externals)
        if ext is None:
            continue
        if ext.callee_file == graph.file_path and ext.relationship != "alias":
            continue
        for index, vuln_value, sink_name, sink_line in ext.param_sinks:
            if vuln_value != rule.vulnerability_class.value:
                continue
            matched = next(
                (sink for sink in sinks if sink.vulnerability_class.value == vuln_value),
                None,
            )
            if matched is None:
                continue
            if argument_is_constant(call, argument_indexes=(index,)):
                continue
            taint = call_taint_reason(
                call,
                source_pats,
                taint_state,
                argument_indexes=(index,),
                sanitizers=vocab.sanitizers,
            )
            if not taint:
                continue
            kinds = applicable_sanitizer_kinds(matched)
            sanitizer = sanitizer_intervened(
                call,
                vocab.sanitizers,
                allowed_kinds=kinds,
                argument_indexes=(index,),
            )
            if sanitizer is not None and sanitizer.effective:
                continue
            if _sanitizer_blocks_reason(taint, kinds):
                continue
            if any(item[:3] == (graph.file_path, call.line, call.qualified) for item in seen):
                continue
            key = (graph.file_path, call.line, call.qualified, f"cross:{index}:{vuln_value}")
            if key in seen:
                continue
            seen.add(key)
            observations.append(
                _observation(
                    rule,
                    graph,
                    call,
                    matched,
                    "high",
                    taint=taint,
                    framework=framework_name or graph.framework,
                    path_kind=_path_kind(call, taint)
                    if matched.vulnerability_class is VulnerabilityClass.POTENTIAL_PATH_TRAVERSAL
                    else None,
                    sanitizer="",
                    argument_index=index,
                    extra={
                        "taint_scope": (
                            "alias" if ext.callee_file == graph.file_path else "cross_file"
                        ),
                        "defining_file": ext.callee_file,
                        "defining_symbol": ext.callee_function,
                        "caller_file": graph.file_path,
                        "caller_symbol": _caller_symbol(call),
                        "callee_file": ext.callee_file,
                        "callee_function": ext.callee_function,
                        "callee_sink": sink_name,
                        "callee_line": str(sink_line),
                        "parameter_index": str(index),
                        "cross_file_depth": str(ext.hops),
                        "hop": str(ext.hops),
                        "cross_file_partial": "true" if ext.partial else "false",
                        "parser_complete": "false" if ext.partial else "true",
                        "relationship": ext.relationship,
                        "re_export": "true" if ext.relationship == "re_export" else "false",
                        "class_method": "true" if ext.relationship == "method" else "false",
                        "semantic_id": ext.semantic_id
                        or f"{ext.callee_file}::{ext.callee_function}",
                        "flow": (
                            f"{graph.file_path} -> {ext.callee_file}::{ext.callee_function}"
                            f" param:{index} sink:{sink_name}"
                        ),
                        **(
                            {"analysis_incomplete": taint_state.limit_reason or "bounded"}
                            if taint_state.incomplete
                            else {}
                        ),
                        **({"branch_merge": "true"} if "merge:" in taint else {}),
                    },
                )
            )
    return observations


def _caller_symbol(call: CallSite) -> str:
    """Enclosing function or method name when the call is not at module scope."""
    scope = call.scope_id or ""
    if not scope or scope == "module":
        return ""
    return scope.rsplit(":", 1)[-1]


def _path_kind(call: CallSite, taint: str | None) -> PathIssueKind:
    text = call.argument_text
    if call.arguments:
        text = " ".join(a.text for a in call.arguments)
    if ".." in text:
        return PathIssueKind.UNSAFE_PATH_CONSTRUCTION
    if taint:
        return PathIssueKind.POSSIBLE_PATH_TRAVERSAL
    return PathIssueKind.USER_CONTROLLED_PATH


def _observation(
    rule: TaintFlowRule,
    graph: SyntaxGraph,
    call: CallSite,
    sink: SinkDefinition,
    confidence: str,
    *,
    taint: str,
    framework: str,
    path_kind: PathIssueKind | None,
    sanitizer: str,
    argument_index: int = 0,
    extra: dict[str, str] | None = None,
) -> SecurityObservation:
    line = call.line
    snippet = graph.lines[line - 1].strip() if 0 < line <= len(graph.lines) else call.argument_text
    title_class = sink.vulnerability_class.value.replace("_", " ")
    if sink.certainty is SinkCertainty.INDICATOR:
        title = f"Potential {title_class}"
    else:
        title = f"Potential {title_class}"
    span = call.span
    limitations = rule.documentation.limitations
    if sink.notes:
        limitations = f"{limitations} {sink.notes}"
    metadata = {
        "sink": call.qualified,
        "taint": taint,
        "parser_backend": graph.parser_backend,
        "parser_tier": str(graph.parser_tier),
        "node_id": call.node_id,
        "scope_id": call.scope_id,
        "sink_id": sink.sink_id,
        "sink_certainty": sink.certainty.value,
        "dangerous_condition": sink.dangerous_condition,
        "safe_alternatives": ",".join(sink.safe_alternatives),
        "framework": framework,
        "file_context": graph.file_context,
        "sanitizer": sanitizer,
        "taint_path": taint,
        "argument_index": str(argument_index),
        "taint_source": taint.split(":", 1)[-1] if taint else "",
        "taint_precision": "flow-sensitive",
        "path_sensitive": "false",
        "taint_use_site": "true",
        "taint_scope": "cross_file" if "cross_file:" in taint else "local",
        "branch_merge": "true" if "merge:" in taint else "false",
    }
    if extra:
        metadata.update(extra)
    if span is not None:
        metadata.update(
            {
                "start_byte": str(span.start_byte),
                "end_byte": str(span.end_byte),
                "start_column": str(span.start_column),
                "end_column": str(span.end_column),
            }
        )
    if path_kind is not None:
        metadata["path_issue_kind"] = path_kind.value
        if path_kind is not PathIssueKind.DEMONSTRATED_DIRECTORY_ESCAPE:
            metadata["verification_required"] = "directory_escape_not_demonstrated"
    return SecurityObservation(
        rule_id=rule.rule_id,
        vulnerability_class=sink.vulnerability_class,
        title=title,
        summary=f"{call.qualified} may receive user-controlled data ({taint})",
        file_path=graph.file_path,
        line=line,
        evidence_text=snippet[:500],
        confidence=confidence,
        language=graph.language,
        documentation=rule.documentation,
        metadata=metadata,
        end_line=span.end_line if span is not None else line,
        start_column=span.start_column if span is not None else None,
        end_column=span.end_column if span is not None else None,
        start_byte=span.start_byte if span is not None else None,
        end_byte=span.end_byte if span is not None else None,
        node_id=call.node_id,
        parser_backend=graph.parser_backend,
        framework_context=framework,
        taint_path=taint,
        possible_false_positives=rule.documentation.false_positives,
        limitations=limitations,
        argument_index=argument_index,
        parser_tier=str(graph.parser_tier),
        scope_id=call.scope_id,
        sink_id=sink.sink_id,
        source_id=taint,
    )


SQL_DOC = RuleDocumentation(
    detects="User-controlled data or dynamically constructed strings reaching a query API.",
    evidence="Call site, taint reason, surrounding source line, parser backend.",
    limitations="Intra-procedural plus uniquely resolved same-file and same-repository calls. Flow-sensitive at the use site, not path-sensitive. Bounded interprocedural and bounded cross-file. Does not prove the query is exploitable.",
    false_positives="ORMs, query builders, and sanitized helpers can still match.",
)
CMD_DOC = RuleDocumentation(
    detects="User-controlled data reaching process/shell execution APIs.",
    evidence="Call site and taint/dynamic construction.",
    limitations="Does not model shell escaping or allow-lists unless a known sanitizer is present.",
    false_positives="Fixed command arrays with a tainted argument that is not the executable.",
)
PATH_DOC = RuleDocumentation(
    detects="User-controlled paths used in file APIs (potential path traversal).",
    evidence="Call site and taint reason. Static analysis never claims a demonstrated directory escape.",
    limitations="Does not prove the path can leave the intended root.",
    false_positives="Path joins that later enforce a root prefix.",
)
SSRF_DOC = RuleDocumentation(
    detects="User-controlled URLs passed to HTTP clients.",
    evidence="Call site and taint reason.",
    limitations="Does not check allow-lists or parser confusion.",
    false_positives="Internal URLs built from trusted config mixed with request data.",
)
XSS_DOC = RuleDocumentation(
    detects="User-controlled data written to HTML/DOM sinks.",
    evidence="Call site and taint reason.",
    limitations="Does not evaluate auto-escaping templates.",
    false_positives="Frameworks that escape by default (e.g. React text nodes).",
)
DESER_DOC = RuleDocumentation(
    detects="Deserialization of untrusted data. Indicator APIs such as JSON.parse are not treated as confirmed gadget execution.",
    evidence="Call site and taint reason.",
    limitations="JSON.parse / encoding/json are often safe; they emit potential_unsafe_deserialization.",
    false_positives="Trusted cache payloads.",
)
EVAL_DOC = RuleDocumentation(
    detects="Dynamic evaluation/execution of code.",
    evidence="Call site; constant literals are ignored.",
    limitations="Flow-sensitive at the use site, not path-sensitive. Bounded same-file and cross-file interprocedural analysis when the callee is unique. Cannot see runtime-built strings assembled outside the repository.",
    false_positives="Test helpers and debug REPL hooks.",
)
REDIRECT_DOC = RuleDocumentation(
    detects="Redirects parameterized by user input.",
    evidence="Call site and taint reason.",
    limitations="Does not validate open-redirect allow-lists.",
    false_positives="Redirects to relative paths computed from enums.",
)


def default_taint_rules() -> list[SecurityRule]:
    return [
        TaintFlowRule(
            rule_id="sec.taint.sql",
            vulnerability_class=VulnerabilityClass.SQL_INJECTION,
            documentation=SQL_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.command",
            vulnerability_class=VulnerabilityClass.COMMAND_INJECTION,
            documentation=CMD_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.path",
            vulnerability_class=VulnerabilityClass.POTENTIAL_PATH_TRAVERSAL,
            documentation=PATH_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.ssrf",
            vulnerability_class=VulnerabilityClass.SSRF,
            documentation=SSRF_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.xss",
            vulnerability_class=VulnerabilityClass.XSS,
            documentation=XSS_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.deser",
            vulnerability_class=VulnerabilityClass.UNSAFE_DESERIALIZATION,
            documentation=DESER_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.eval",
            vulnerability_class=VulnerabilityClass.DYNAMIC_EXECUTION,
            documentation=EVAL_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.redirect",
            vulnerability_class=VulnerabilityClass.UNSAFE_REDIRECT,
            documentation=REDIRECT_DOC,
        ),
    ]
