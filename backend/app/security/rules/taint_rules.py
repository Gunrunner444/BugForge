"""Taint-aware source→sink security rules using semantic vocabularies."""

from __future__ import annotations

from collections.abc import Sequence

from app.analyzers.framework_detector import FrameworkInfo
from app.domain.security import VulnerabilityClass
from app.parsing.model import CallSite, SyntaxGraph
from app.security.definitions import (
    PathIssueKind,
    SinkCertainty,
    SinkDefinition,
)
from app.security.rules.base import RuleDocumentation, SecurityObservation, SecurityRule
from app.security.taint import (
    argument_is_constant,
    call_matches_sink,
    call_taint_reason,
    language_vocab,
    looks_parameterized_sql,
    propagate_taint,
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
        tainted = propagate_taint(graph, sources)
        framework_name = (
            ",".join(
                fw.name
                for fw in frameworks
                if fw.language.split("/")[0] in {graph.language, "javascript", "typescript"}
            )
            or ""
        )
        observations: list[SecurityObservation] = []
        seen: set[tuple[str, int, str]] = set()
        for call in graph.calls:
            matched = next((sink for sink in sinks if call_matches_sink(call, sink)), None)
            if matched is None:
                continue
            if argument_is_constant(call):
                continue
            if (
                self.vulnerability_class is VulnerabilityClass.SQL_INJECTION
                and looks_parameterized_sql(call.argument_text)
            ):
                continue
            taint = call_taint_reason(call, source_pats, tainted)
            if not taint and not call.dynamic:
                continue
            sanitizer = sanitizer_intervened(call, vocab.sanitizers)
            if sanitizer is not None and sanitizer.effective:
                continue
            confidence = "high" if taint else "medium"
            if sanitizer is not None:
                confidence = "low"
            vuln = matched.vulnerability_class
            if vuln is VulnerabilityClass.POTENTIAL_PATH_TRAVERSAL:
                path_kind = _path_kind(call, taint)
            else:
                path_kind = None
            key = (graph.file_path, call.line, call.qualified)
            if key in seen:
                continue
            seen.add(key)
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
                )
            )
        return observations


def _path_kind(call: CallSite, taint: str | None) -> PathIssueKind:
    combined = f"{call.argument_text} {taint or ''}"
    if ".." in combined:
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
    }
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
    )


SQL_DOC = RuleDocumentation(
    detects="User-controlled data or dynamically constructed strings reaching a query API.",
    evidence="Call site, taint reason, surrounding source line, parser backend.",
    limitations="Intra-procedural (plus limited same-file calls); does not prove the query is exploitable.",
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
    limitations="Cannot see runtime-built strings assembled in other files.",
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
