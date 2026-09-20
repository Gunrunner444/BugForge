"""JavaScript/TypeScript quality rules.

These are language-specific checks that do not belong in the security sink
system. They operate on comment-stripped source so string/comment lookalikes
are not findings.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.analysis.base import AnalyzerRule
from app.analysis.finding import Finding
from app.parsing.comments import strip_comments

_EQ = re.compile(r"(?<![=!<>])==(?!=)")
_NE = re.compile(r"(?<![=!<>])!=(?!=)")
_VAR = re.compile(r"\bvar\s+(?P<name>[A-Za-z_$][\w$]*)")
_WITH = re.compile(r"\bwith\s*\(")
_EMPTY_CATCH = re.compile(r"\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}")
_NULLISH = re.compile(r"\b(?:null|undefined)\b", re.IGNORECASE)


def _clean(source: str) -> str:
    stripped = strip_comments(source, line_comment="//", block_comment=("/*", "*/"))
    return _blank_strings(stripped)


def _blank_strings(source: str) -> str:
    out: list[str] = []
    i = 0
    n = len(source)
    in_str: str | None = None
    escape = False
    while i < n:
        ch = source[i]
        if in_str:
            if escape:
                escape = False
                out.append(" ")
            elif ch == "\\":
                escape = True
                out.append(" ")
            elif ch == in_str:
                in_str = None
                out.append(" ")
            else:
                out.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        if ch in {'"', "'", "`"}:
            in_str = ch
            out.append(" ")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _line_at(source: str, index: int) -> int:
    return source.count("\n", 0, index) + 1


def _snippet(source: str, line: int) -> str:
    lines = source.splitlines() or [""]
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()[:200]
    return ""


class LooseEqualityRule(AnalyzerRule):
    """Flag `==` / `!=` except the `== null` / `== undefined` idiom."""

    RULE_ID = "js_loose_equality"
    SEVERITY = "low"
    CONFIDENCE = "high"

    def check_file(self, file_path: Path, source: str) -> list[Finding]:
        cleaned = _clean(source)
        findings: list[Finding] = []
        for rx, message, fix in (
            (_EQ, "Use `===` instead of `==`", "Replace `==` with `===`"),
            (_NE, "Use `!==` instead of `!=`", "Replace `!=` with `!==`"),
        ):
            for match in rx.finditer(cleaned):
                window = cleaned[max(0, match.start() - 24) : match.end() + 24]
                if _NULLISH.search(window):
                    continue
                line = _line_at(cleaned, match.start())
                findings.append(
                    Finding(
                        category=self.RULE_ID,
                        severity=self.SEVERITY,
                        confidence=self.CONFIDENCE,
                        file_path=str(file_path),
                        line=line,
                        end_line=line,
                        message=message,
                        explanation=(
                            "Loose equality coerces types and hides bugs. Strict equality "
                            "(`===` / `!==`) compares without coercion. The `== null` idiom "
                            "is allowed because it matches both `null` and `undefined`."
                        ),
                        analyzer=self.RULE_ID,
                        evidence=_snippet(source, line),
                        suggested_fix=fix,
                    )
                )
        return findings


class VarDeclarationRule(AnalyzerRule):
    """Flag `var` in favor of `let` / `const`."""

    RULE_ID = "js_var_declaration"
    SEVERITY = "low"
    CONFIDENCE = "high"

    def check_file(self, file_path: Path, source: str) -> list[Finding]:
        cleaned = _clean(source)
        findings: list[Finding] = []
        for match in _VAR.finditer(cleaned):
            line = _line_at(cleaned, match.start())
            name = match.group("name")
            findings.append(
                Finding(
                    category=self.RULE_ID,
                    severity=self.SEVERITY,
                    confidence=self.CONFIDENCE,
                    file_path=str(file_path),
                    line=line,
                    end_line=line,
                    message=f"`var {name}` is function-scoped; prefer `let` or `const`",
                    explanation=(
                        "`var` is function-scoped and hoisted, which leads to accidental "
                        "sharing across blocks. Use `const` by default and `let` when the "
                        "binding must be reassigned."
                    ),
                    analyzer=self.RULE_ID,
                    evidence=_snippet(source, line),
                    suggested_fix=f"Replace `var {name}` with `const {name}` or `let {name}`",
                )
            )
        return findings


class EmptyCatchRule(AnalyzerRule):
    """Flag empty `catch` blocks that swallow errors."""

    RULE_ID = "js_empty_catch"
    SEVERITY = "medium"
    CONFIDENCE = "high"

    def check_file(self, file_path: Path, source: str) -> list[Finding]:
        cleaned = _clean(source)
        findings: list[Finding] = []
        for match in _EMPTY_CATCH.finditer(cleaned):
            line = _line_at(cleaned, match.start())
            findings.append(
                Finding(
                    category=self.RULE_ID,
                    severity=self.SEVERITY,
                    confidence=self.CONFIDENCE,
                    file_path=str(file_path),
                    line=line,
                    end_line=line,
                    message="Empty `catch` block swallows errors",
                    explanation=(
                        "An empty catch hides failures and makes production issues undiagnosable. "
                        "Log, rethrow, or handle the error explicitly."
                    ),
                    analyzer=self.RULE_ID,
                    evidence=_snippet(source, line),
                    suggested_fix="Handle or rethrow the error inside the catch block",
                )
            )
        return findings


class WithStatementRule(AnalyzerRule):
    """Flag the `with` statement, which is forbidden in strict mode."""

    RULE_ID = "js_with_statement"
    SEVERITY = "medium"
    CONFIDENCE = "high"

    def check_file(self, file_path: Path, source: str) -> list[Finding]:
        cleaned = _clean(source)
        findings: list[Finding] = []
        for match in _WITH.finditer(cleaned):
            line = _line_at(cleaned, match.start())
            findings.append(
                Finding(
                    category=self.RULE_ID,
                    severity=self.SEVERITY,
                    confidence=self.CONFIDENCE,
                    file_path=str(file_path),
                    line=line,
                    end_line=line,
                    message="`with` statements are forbidden in strict mode",
                    explanation=(
                        "`with` mutates the identifier lookup scope and is banned under "
                        "`'use strict'`. Reference properties on the object explicitly."
                    ),
                    analyzer=self.RULE_ID,
                    evidence=_snippet(source, line),
                    suggested_fix="Replace `with (obj) { x }` with `obj.x`",
                )
            )
        return findings


ALL_JAVASCRIPT_RULES: list[AnalyzerRule] = [
    LooseEqualityRule(),
    VarDeclarationRule(),
    EmptyCatchRule(),
    WithStatementRule(),
]
