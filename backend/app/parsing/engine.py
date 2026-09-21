"""Language-neutral syntax parser registry."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from app.domain.language import ParserTier
from app.parsing.extract import parse_with_profile
from app.parsing.model import LanguageProfile, SyntaxGraph
from app.parsing.profiles import PROFILES, profile_for
from app.parsing.python_graph import parse_python_graph
from app.parsing.treesitter import treesitter_available
from app.parsing.treesitter_graph import parse_treesitter_graph

ParserFn = Callable[[Path, str], SyntaxGraph]


class SyntaxParserRegistry:
    """Maps language ids to graph builders. Core code looks up by id."""

    def __init__(self) -> None:
        self._parsers: dict[str, ParserFn] = {}
        self._backends: dict[str, str] = {}
        self._tiers: dict[str, ParserTier] = {}

    def register(
        self,
        language_id: str,
        parser: ParserFn,
        *,
        replace: bool = False,
        backend: str = "custom",
        tier: ParserTier = ParserTier.FULL_AST,
    ) -> None:
        key = language_id.strip().lower()
        if key in self._parsers and not replace:
            raise ValueError(f"syntax parser {key!r} is already registered")
        self._parsers[key] = parser
        self._backends[key] = backend
        self._tiers[key] = tier

    def has(self, language_id: str) -> bool:
        return language_id.strip().lower() in self._parsers

    def parse(self, language_id: str, file_path: Path, source: str) -> SyntaxGraph:
        key = language_id.strip().lower()
        parser = self._parsers.get(key)
        if parser is None:
            raise KeyError(f"No syntax parser registered for {key!r}")
        return parser(file_path, source)

    def backend(self, language_id: str) -> str:
        return self._backends.get(language_id.strip().lower(), "unknown")

    def tier(self, language_id: str) -> ParserTier:
        return self._tiers.get(language_id.strip().lower(), ParserTier.DETECTION_ONLY)

    def available_ids(self) -> list[str]:
        return sorted(self._parsers)


def _profile_parser(profile: LanguageProfile) -> ParserFn:
    def parse(file_path: Path, source: str) -> SyntaxGraph:
        graph = parse_with_profile(profile, file_path, source)
        graph.parser_backend = "profile"
        graph.parser_tier = ParserTier.PROFILE_FALLBACK
        return graph

    return parse


def _treesitter_or_profile(language_id: str, profile: LanguageProfile) -> ParserFn:
    fallback = _profile_parser(profile)

    def parse(file_path: Path, source: str) -> SyntaxGraph:
        if treesitter_available(language_id) or (
            language_id == "typescript" and str(file_path).endswith(".tsx")
        ):
            graph = parse_treesitter_graph(language_id, file_path, source)
            if graph is not None:
                return graph
        return fallback(file_path, source)

    return parse


def default_syntax_registry() -> SyntaxParserRegistry:
    registry = SyntaxParserRegistry()
    registry.register(
        "python",
        parse_python_graph,
        backend="cpython_ast",
        tier=ParserTier.FULL_AST,
    )
    for language_id, profile in PROFILES.items():
        if language_id == "python":
            continue
        if treesitter_available(language_id):
            registry.register(
                language_id,
                _treesitter_or_profile(language_id, profile),
                backend="tree_sitter",
                tier=ParserTier.FULL_AST,
            )
        else:
            registry.register(
                language_id,
                _profile_parser(profile),
                backend="profile",
                tier=ParserTier.PROFILE_FALLBACK,
            )
    return registry


_REGISTRY: SyntaxParserRegistry | None = None


def get_syntax_registry() -> SyntaxParserRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = default_syntax_registry()
    return _REGISTRY


def reset_syntax_registry() -> None:
    global _REGISTRY
    _REGISTRY = None


def parse_source(language_id: str, file_path: Path, source: str) -> SyntaxGraph:
    return get_syntax_registry().parse(language_id, file_path, source)


def can_parse(language_id: str) -> bool:
    return get_syntax_registry().has(language_id) or profile_for(language_id) is not None


def parser_backend_for(language_id: str) -> str:
    if get_syntax_registry().has(language_id):
        return get_syntax_registry().backend(language_id)
    return "none"


def parser_tier_for(language_id: str) -> ParserTier:
    if get_syntax_registry().has(language_id):
        return get_syntax_registry().tier(language_id)
    return ParserTier.DETECTION_ONLY
