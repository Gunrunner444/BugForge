"""Language-neutral syntax parser registry."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from app.parsing.extract import parse_with_profile
from app.parsing.model import LanguageProfile, SyntaxGraph
from app.parsing.profiles import PROFILES, profile_for
from app.parsing.python_graph import parse_python_graph

ParserFn = Callable[[Path, str], SyntaxGraph]


class SyntaxParserRegistry:
    """Maps language ids to graph builders. Core code looks up by id."""

    def __init__(self) -> None:
        self._parsers: dict[str, ParserFn] = {}

    def register(self, language_id: str, parser: ParserFn, *, replace: bool = False) -> None:
        key = language_id.strip().lower()
        if key in self._parsers and not replace:
            raise ValueError(f"syntax parser {key!r} is already registered")
        self._parsers[key] = parser

    def has(self, language_id: str) -> bool:
        return language_id.strip().lower() in self._parsers

    def parse(self, language_id: str, file_path: Path, source: str) -> SyntaxGraph:
        key = language_id.strip().lower()
        parser = self._parsers.get(key)
        if parser is None:
            raise KeyError(f"No syntax parser registered for {key!r}")
        return parser(file_path, source)

    def available_ids(self) -> list[str]:
        return sorted(self._parsers)


def _profile_parser(profile: LanguageProfile) -> ParserFn:
    def parse(file_path: Path, source: str) -> SyntaxGraph:
        return parse_with_profile(profile, file_path, source)

    return parse


def default_syntax_registry() -> SyntaxParserRegistry:
    registry = SyntaxParserRegistry()
    registry.register("python", parse_python_graph)
    for language_id, profile in PROFILES.items():
        if language_id == "python":
            continue
        registry.register(language_id, _profile_parser(profile))
    return registry


_REGISTRY: SyntaxParserRegistry | None = None


def get_syntax_registry() -> SyntaxParserRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = default_syntax_registry()
    return _REGISTRY


def parse_source(language_id: str, file_path: Path, source: str) -> SyntaxGraph:
    return get_syntax_registry().parse(language_id, file_path, source)


def can_parse(language_id: str) -> bool:
    return get_syntax_registry().has(language_id) or profile_for(language_id) is not None
