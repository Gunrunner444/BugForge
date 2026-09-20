"""Detection-capable language adapters without fake analysis implementations.

These adapters exist so language detection and source-file classification go
through the registry. Parse and static analysis raise
:class:`UnsupportedCapabilityError` until a later phase implements them.
"""

from __future__ import annotations

from app.adapters.languages.base import LanguageAdapter
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


class JavaScriptAdapter(DetectionLanguageAdapter):
    def __init__(self) -> None:
        super().__init__(
            "javascript",
            "JavaScript",
            frozenset({".js", ".mjs", ".cjs", ".jsx"}),
            is_source=True,
        )


class TypeScriptAdapter(DetectionLanguageAdapter):
    def __init__(self) -> None:
        super().__init__(
            "typescript",
            "TypeScript",
            frozenset({".ts", ".tsx"}),
            is_source=True,
        )


class RubyAdapter(DetectionLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("ruby", "Ruby", frozenset({".rb"}), is_source=True)


class CAdapter(DetectionLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("c", "C", frozenset({".c", ".h"}), is_source=True)


class CppAdapter(DetectionLanguageAdapter):
    def __init__(self) -> None:
        super().__init__(
            "cpp",
            "C++",
            frozenset({".cpp", ".cc", ".cxx", ".hpp"}),
            is_source=True,
        )


class GoAdapter(DetectionLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("go", "Go", frozenset({".go"}), is_source=True)


class RustAdapter(DetectionLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("rust", "Rust", frozenset({".rs"}), is_source=True)


class JavaAdapter(DetectionLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("java", "Java", frozenset({".java"}), is_source=True)


class PHPAdapter(DetectionLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("php", "PHP", frozenset({".php"}), is_source=True)


class KotlinAdapter(DetectionLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("kotlin", "Kotlin", frozenset({".kt", ".kts"}), is_source=True)


class SwiftAdapter(DetectionLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("swift", "Swift", frozenset({".swift"}), is_source=True)


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
