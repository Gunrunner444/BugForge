"""Built-in language adapters.

Programming languages with a syntax profile implement parse, entity/import
extraction, and security analysis. Auxiliary formats remain detection-only.
"""

from __future__ import annotations

from app.adapters.languages.base import LanguageAdapter
from app.adapters.languages.profile import ProfileLanguageAdapter
from app.analysis.javascript_analyzer import ALL_JAVASCRIPT_RULES
from app.domain.language import LanguageCapability


class DetectionLanguageAdapter(LanguageAdapter):
    """Shared implementation for languages that can be detected but not analyzed."""

    def __init__(
        self,
        language_id: str,
        display_name: str,
        extensions: frozenset[str],
        *,
        is_source: bool,
    ) -> None:
        self._language_id = language_id
        self._display_name = display_name
        self._extensions = extensions
        caps = {LanguageCapability.DETECTION}
        if is_source:
            caps.add(LanguageCapability.SOURCE)
        self._capabilities = frozenset(caps)

    @property
    def language_id(self) -> str:
        return self._language_id

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def file_extensions(self) -> frozenset[str]:
        return self._extensions

    @property
    def capabilities(self) -> frozenset[LanguageCapability]:
        return self._capabilities


class JavaScriptAdapter(ProfileLanguageAdapter):
    def __init__(self) -> None:
        super().__init__(
            "javascript",
            "JavaScript",
            frozenset({".js", ".mjs", ".cjs", ".jsx"}),
            rules=ALL_JAVASCRIPT_RULES,
        )


class TypeScriptAdapter(ProfileLanguageAdapter):
    def __init__(self) -> None:
        super().__init__(
            "typescript",
            "TypeScript",
            frozenset({".ts", ".tsx"}),
            rules=ALL_JAVASCRIPT_RULES,
        )


class RubyAdapter(ProfileLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("ruby", "Ruby", frozenset({".rb"}))


class CAdapter(ProfileLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("c", "C", frozenset({".c", ".h"}))


class CppAdapter(ProfileLanguageAdapter):
    def __init__(self) -> None:
        super().__init__(
            "cpp",
            "C++",
            frozenset({".cpp", ".cc", ".cxx", ".hpp"}),
        )


class GoAdapter(ProfileLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("go", "Go", frozenset({".go"}))


class RustAdapter(ProfileLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("rust", "Rust", frozenset({".rs"}))


class JavaAdapter(ProfileLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("java", "Java", frozenset({".java"}))


class PHPAdapter(ProfileLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("php", "PHP", frozenset({".php"}))


class KotlinAdapter(ProfileLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("kotlin", "Kotlin", frozenset({".kt", ".kts"}))


class SwiftAdapter(ProfileLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("swift", "Swift", frozenset({".swift"}))


# Auxiliary languages previously tracked by the extension map. Detection only.
AUXILIARY_LANGUAGES: tuple[DetectionLanguageAdapter, ...] = (
    DetectionLanguageAdapter("csharp", "C#", frozenset({".cs"}), is_source=True),
    DetectionLanguageAdapter("shell", "Shell", frozenset({".sh", ".bash", ".zsh"}), is_source=True),
    DetectionLanguageAdapter("yaml", "YAML", frozenset({".yaml", ".yml"}), is_source=False),
    DetectionLanguageAdapter("json", "JSON", frozenset({".json"}), is_source=False),
    DetectionLanguageAdapter("toml", "TOML", frozenset({".toml"}), is_source=False),
    DetectionLanguageAdapter("markdown", "Markdown", frozenset({".md"}), is_source=False),
    DetectionLanguageAdapter(
        "restructuredtext",
        "reStructuredText",
        frozenset({".rst"}),
        is_source=False,
    ),
    DetectionLanguageAdapter("html", "HTML", frozenset({".html", ".htm"}), is_source=True),
    DetectionLanguageAdapter("css", "CSS", frozenset({".css"}), is_source=True),
    DetectionLanguageAdapter("scss", "SCSS", frozenset({".scss", ".sass"}), is_source=True),
    DetectionLanguageAdapter("sql", "SQL", frozenset({".sql"}), is_source=True),
    DetectionLanguageAdapter("r", "R", frozenset({".r"}), is_source=True),
    DetectionLanguageAdapter("scala", "Scala", frozenset({".scala"}), is_source=True),
    DetectionLanguageAdapter("dart", "Dart", frozenset({".dart"}), is_source=True),
    DetectionLanguageAdapter("lua", "Lua", frozenset({".lua"}), is_source=True),
    DetectionLanguageAdapter("elixir", "Elixir", frozenset({".ex", ".exs"}), is_source=True),
)

PROGRAMMING_LANGUAGE_ADAPTERS: tuple[type[LanguageAdapter], ...] = (
    JavaScriptAdapter,
    TypeScriptAdapter,
    RubyAdapter,
    CAdapter,
    CppAdapter,
    GoAdapter,
    RustAdapter,
    JavaAdapter,
    PHPAdapter,
    KotlinAdapter,
    SwiftAdapter,
)
