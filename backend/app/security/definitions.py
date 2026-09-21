"""Semantic source, sink, sanitizer, and path-policy abstractions.

These types are language-neutral. Concrete catalogs live in language
vocabularies and are looked up by id — the taint engine never switches on
language names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from app.domain.security import VulnerabilityClass


class PathIssueKind(StrEnum):
    USER_CONTROLLED_PATH = "user_controlled_path"
    UNSAFE_PATH_CONSTRUCTION = "unsafe_path_construction"
    POSSIBLE_PATH_TRAVERSAL = "possible_path_traversal"
    DEMONSTRATED_DIRECTORY_ESCAPE = "demonstrated_directory_escape"


class SinkCertainty(StrEnum):
    SENSITIVE = "sensitive_sink"
    INDICATOR = "indicator"


@dataclass(frozen=True)
class SourceDefinition:
    source_id: str
    patterns: tuple[str, ...]
    kind: str  # http | cli | env | file | deserialized | browser | framework
    frameworks: tuple[str, ...] = ()


@dataclass(frozen=True)
class SinkDefinition:
    sink_id: str
    vulnerability_class: VulnerabilityClass
    api_names: tuple[str, ...]
    argument_index: int = 0
    requires_taint: bool = True
    certainty: SinkCertainty = SinkCertainty.SENSITIVE
    sanitizer_ids: tuple[str, ...] = ()
    safe_alternatives: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    dangerous_condition: str = "attacker-controlled data reaches this API"
    notes: str = ""
    qualified_substrings: tuple[str, ...] = ()


@dataclass(frozen=True)
class SanitizerDefinition:
    sanitizer_id: str
    api_names: tuple[str, ...]
    kind: str  # html_encode | sql_param | path_canon | url_allow | shell_escape | type_check | framework_escape
    effective: bool = False
    notes: str = ""


@dataclass(frozen=True)
class LanguageSecurityVocab:
    language_id: str
    sources: tuple[SourceDefinition, ...] = ()
    sinks: tuple[SinkDefinition, ...] = ()
    sanitizers: tuple[SanitizerDefinition, ...] = ()
    crypto_names: tuple[str, ...] = ()
    extra_sources_by_framework: dict[str, tuple[SourceDefinition, ...]] = field(default_factory=dict)

    def sinks_for(self, vulnerability_class: VulnerabilityClass) -> tuple[SinkDefinition, ...]:
        return tuple(s for s in self.sinks if s.vulnerability_class is vulnerability_class)
