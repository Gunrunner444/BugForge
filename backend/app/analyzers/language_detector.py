from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path


@dataclass
class LanguageStats:
    language: str
    file_count: int
    percentage: float


# Maps lowercase file extensions to canonical language names
EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".md": "markdown",
    ".rst": "restructuredtext",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "scss",
    ".sass": "scss",
    ".sql": "sql",
    ".r": "r",
    ".scala": "scala",
    ".dart": "dart",
    ".lua": "lua",
    ".ex": "elixir",
    ".exs": "elixir",
}


def language_for_path(path: Path) -> str | None:
    return EXTENSION_MAP.get(path.suffix.lower())


def detect_languages(file_paths: list[Path]) -> list[LanguageStats]:
    counts: Counter[str] = Counter()
    for p in file_paths:
        lang = language_for_path(p)
        if lang:
            counts[lang] += 1

    total = counts.total()
    return [
        LanguageStats(
            language=lang,
            file_count=count,
            percentage=round(count / total * 100, 1) if total else 0.0,
        )
        for lang, count in counts.most_common()
    ]
