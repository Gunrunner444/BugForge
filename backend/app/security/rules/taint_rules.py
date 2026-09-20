"""Taint-aware source→sink security rules."""

from __future__ import annotations

import re
from collections.abc import Sequence

from app.analyzers.framework_detector import FrameworkInfo
from app.domain.security import VulnerabilityClass
from app.parsing.model import LanguageProfile, SyntaxGraph
from app.parsing.profiles import profile_for
from app.security.rules.base import RuleDocumentation, SecurityObservation, SecurityRule
from app.security.taint import (
    argument_is_constant,
    call_is_tainted,
    call_matches_sink,
    compile_patterns,
    extra_sources,
    propagate_taint,
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
        sink_attr: str,
        documentation: RuleDocumentation,
    ) -> None:
        self.rule_id = rule_id
        self.vulnerability_class = vulnerability_class
        self._sink_attr = sink_attr
        self.documentation = documentation

    def check(
        self,
        graph: SyntaxGraph,
        *,
        frameworks: Sequence[FrameworkInfo] = (),
    ) -> list[SecurityObservation]:
        profile = profile_for(graph.language)
        if profile is None:
            return []
        sink_patterns = compile_patterns(getattr(profile, self._sink_attr))
        if not sink_patterns:
            return []
        source_pats = compile_patterns(profile.source_patterns + extra_sources(profile, frameworks))
        tainted = propagate_taint(graph, source_pats)
        observations: list[SecurityObservation] = []
        seen: set[tuple[str, int, str]] = set()
        for call in graph.calls:
            if not call_matches_sink(call, sink_patterns):
                continue
            if argument_is_constant(call.argument_text):
                continue
            if _looks_parameterized(call.argument_text):
                continue
            taint = call_is_tainted(call, source_pats, tainted)
            if not taint and not call.dynamic:
                continue
            confidence = "high" if taint else "medium"
            key = (graph.file_path, call.line, call.qualified)
            if key in seen:
                continue
            seen.add(key)
            observations.append(
                _observation(
                    self,
                    graph,
                    profile,
                    call.line,
                    call.qualified,
                    call.argument_text,
                    confidence,
                    taint=taint or "dynamic_construction",
                )
            )
        return observations


def _observation(
    rule: TaintFlowRule,
    graph: SyntaxGraph,
    profile: LanguageProfile,
    line: int,
    sink: str,
    args: str,
    confidence: str,
    *,
    taint: str,
) -> SecurityObservation:
    snippet = graph.lines[line - 1].strip() if 0 < line <= len(graph.lines) else args
    return SecurityObservation(
        rule_id=rule.rule_id,
        vulnerability_class=rule.vulnerability_class,
        title=f"Potential {rule.vulnerability_class.value.replace('_', ' ')}",
        summary=f"{sink} may receive user-controlled data ({taint})",
        file_path=graph.file_path,
        line=line,
        evidence_text=snippet[:500],
        confidence=confidence,
        language=graph.language,
        documentation=rule.documentation,
        metadata={"sink": sink, "taint": taint, "profile": profile.language_id},
    )


SQL_DOC = RuleDocumentation(
    detects="User-controlled data or dynamically constructed strings reaching a query API.",
    evidence="Call site, taint reason, surrounding source line.",
    limitations="Intra-procedural only; does not prove the query is exploitable.",
    false_positives="ORMs, query builders, and sanitized helpers can still match.",
)
CMD_DOC = RuleDocumentation(
    detects="User-controlled data reaching process/shell execution APIs.",
    evidence="Call site and taint/dynamic construction.",
    limitations="Does not model shell escaping or allow-lists.",
    false_positives="Fixed command arrays with a tainted argument that is not the executable.",
)
PATH_DOC = RuleDocumentation(
    detects="User-controlled paths used in file APIs.",
    evidence="Call site and taint reason.",
    limitations="Does not prove directory escape.",
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
    detects="Deserialization of untrusted data.",
    evidence="Call site and taint reason.",
    limitations="JSON.parse is often safe; flagged only with taint + language-risky APIs.",
    false_positives="Trusted cache payloads.",
)
EVAL_DOC = RuleDocumentation(
    detects="Dynamic evaluation/execution of code.",
    evidence="Call site; constant literals are ignored.",
    limitations="Cannot see runtime-built strings assembled in other functions.",
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
            sink_attr="sql_sinks",
            documentation=SQL_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.command",
            vulnerability_class=VulnerabilityClass.COMMAND_INJECTION,
            sink_attr="command_sinks",
            documentation=CMD_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.path",
            vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
            sink_attr="path_sinks",
            documentation=PATH_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.ssrf",
            vulnerability_class=VulnerabilityClass.SSRF,
            sink_attr="ssrf_sinks",
            documentation=SSRF_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.xss",
            vulnerability_class=VulnerabilityClass.XSS,
            sink_attr="xss_sinks",
            documentation=XSS_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.deser",
            vulnerability_class=VulnerabilityClass.UNSAFE_DESERIALIZATION,
            sink_attr="deser_sinks",
            documentation=DESER_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.eval",
            vulnerability_class=VulnerabilityClass.DYNAMIC_EXECUTION,
            sink_attr="eval_sinks",
            documentation=EVAL_DOC,
        ),
        TaintFlowRule(
            rule_id="sec.taint.redirect",
            vulnerability_class=VulnerabilityClass.UNSAFE_REDIRECT,
            sink_attr="redirect_sinks",
            documentation=REDIRECT_DOC,
        ),
    ]


_PARAM_SQL = re.compile(
    r"""['\"].*(?:\?|\$\d+|%s|:\w+).*['\"]\s*,""",
    re.DOTALL,
)


def _looks_parameterized(argument_text: str) -> bool:
    """Skip execute/query calls that pass a constant SQL string plus bound params."""
    return _PARAM_SQL.search(argument_text) is not None
