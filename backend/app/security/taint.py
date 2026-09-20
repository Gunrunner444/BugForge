"""Intra-procedural taint tracking over a SyntaxGraph."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from app.analyzers.framework_detector import FrameworkInfo
from app.parsing.model import CallSite, LanguageProfile, SyntaxGraph

_IDENT = re.compile(r"[A-Za-z_$/][\w$]*")


def compile_patterns(patterns: Sequence[str]) -> list[re.Pattern[str]]:
    return [re.compile(p) for p in patterns]


def matches_any(text: str, patterns: Sequence[re.Pattern[str]]) -> re.Pattern[str] | None:
    for pattern in patterns:
        if pattern.search(text):
            return pattern
    return None


def extra_sources(profile: LanguageProfile, frameworks: Sequence[FrameworkInfo]) -> tuple[str, ...]:
    extra: list[str] = []
    names = {fw.name.lower() for fw in frameworks}
    for key, patterns in profile.extra_source_by_framework.items():
        if key.lower() in names:
            extra.extend(patterns)
    return tuple(extra)


def propagate_taint(
    graph: SyntaxGraph,
    source_patterns: Sequence[re.Pattern[str]],
) -> dict[str, str]:
    """Map identifier → why it is considered user-controlled."""
    tainted: dict[str, str] = {}
    changed = True
    rounds = 0
    while changed and rounds < 16:
        changed = False
        rounds += 1
        for binding in graph.bindings:
            if binding.name in tainted:
                continue
            reason = _taint_reason(binding.rhs, source_patterns, tainted)
            if reason:
                tainted[binding.name] = reason
                changed = True
    return tainted


def _taint_reason(
    text: str,
    source_patterns: Sequence[re.Pattern[str]],
    tainted: dict[str, str],
) -> str | None:
    hit = matches_any(text, source_patterns)
    if hit:
        return f"source:{hit.pattern}"
    for name, reason in tainted.items():
        if re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", text):
            return f"from:{name}:{reason}"
    return None


def call_is_tainted(
    call: CallSite,
    source_patterns: Sequence[re.Pattern[str]],
    tainted: dict[str, str],
) -> str | None:
    return _taint_reason(call.argument_text, source_patterns, tainted)


def call_matches_sink(call: CallSite, sink_patterns: Sequence[re.Pattern[str]]) -> bool:
    haystack = f"{call.qualified}({call.argument_text})"
    return matches_any(haystack, sink_patterns) is not None


def argument_is_constant(argument_text: str) -> bool:
    text = argument_text.strip()
    if not text:
        return True
    if any(
        marker in text for marker in ("+", "${", "#{", "%s", "%d", "{}", ".format(", 'f"', "f'")
    ):
        return False
    if text[0] in {'"', "'", "`"} and text[-1] == text[0]:
        return True
    return False


def identifiers_in(text: str) -> Iterable[str]:
    for match in _IDENT.finditer(text):
        yield match.group(0)
