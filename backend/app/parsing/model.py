"""Shared syntax-graph types used by language parsers and security rules.

This is the language-neutral substrate. Individual languages fill it via
Python's AST or a profile-driven parser. Tree-sitter can be plugged in later
behind the same types without changing the security engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.domain.source import LanguageParseResult, ParsedEntity, ParsedImport


@dataclass(frozen=True)
class CallSite:
    """One function/method call in source."""

    name: str
    qualified: str
    line: int
    argument_text: str
    dynamic: bool = False  # concatenation, interpolation, or format


@dataclass(frozen=True)
class Binding:
    """A name bound to an expression (assignment / declaration)."""

    name: str
    line: int
    rhs: str


@dataclass
class SyntaxGraph:
    """Syntax-aware view of one source file."""

    language: str
    file_path: str
    source: str
    lines: tuple[str, ...]
    imports: tuple[ParsedImport, ...] = ()
    entities: tuple[ParsedEntity, ...] = ()
    calls: tuple[CallSite, ...] = ()
    bindings: tuple[Binding, ...] = ()
    errors: tuple[str, ...] = ()

    def to_parse_result(self) -> LanguageParseResult:
        return LanguageParseResult(
            file_path=self.file_path,
            language=self.language,
            line_count=len(self.lines) or 1,
            errors=list(self.errors),
            imports=list(self.imports),
            entities=list(self.entities),
        )


@dataclass
class LanguageProfile:
    """Declarative parser + taint profile for one language.

    Profiles live in the parsing/security adapters, not in core orchestration.
    """

    language_id: str
    display_name: str
    extensions: frozenset[str]
    line_comment: str | None = "//"
    block_comment: tuple[str, str] | None = ("/*", "*/")
    import_patterns: tuple[str, ...] = ()
    function_patterns: tuple[str, ...] = ()
    class_patterns: tuple[str, ...] = ()
    assignment_patterns: tuple[str, ...] = ()
    source_patterns: tuple[str, ...] = ()
    sql_sinks: tuple[str, ...] = ()
    command_sinks: tuple[str, ...] = ()
    path_sinks: tuple[str, ...] = ()
    ssrf_sinks: tuple[str, ...] = ()
    xss_sinks: tuple[str, ...] = ()
    deser_sinks: tuple[str, ...] = ()
    eval_sinks: tuple[str, ...] = ()
    redirect_sinks: tuple[str, ...] = ()
    crypto_patterns: tuple[str, ...] = ()
    extra_source_by_framework: dict[str, tuple[str, ...]] = field(default_factory=dict)
