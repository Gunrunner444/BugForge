from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FrameworkInfo:
    name: str
    language: str
    confidence: float
    evidence: list[str] = field(default_factory=list)


# Describes how to detect a framework
_PYTHON_FRAMEWORKS: list[dict[str, Any]] = [
    {
        "name": "django",
        "language": "python",
        "indicator_files": ["manage.py"],
        "indicator_dirs": [],
        "config_patterns": [r"django"],
        "import_patterns": [r"^django"],
    },
    {
        "name": "flask",
        "language": "python",
        "indicator_files": [],
        "indicator_dirs": [],
        "config_patterns": [r"flask"],
        "import_patterns": [r"^flask"],
    },
    {
        "name": "fastapi",
        "language": "python",
        "indicator_files": [],
        "indicator_dirs": [],
        "config_patterns": [r"fastapi"],
        "import_patterns": [r"^fastapi"],
    },
    {
        "name": "pytest",
        "language": "python",
        "indicator_files": ["pytest.ini", "conftest.py"],
        "indicator_dirs": ["tests", "test"],
        "config_patterns": [r"\[tool\.pytest", r"\[pytest\]", r"pytest"],
        "import_patterns": [r"^pytest"],
    },
    {
        "name": "sqlalchemy",
        "language": "python",
        "indicator_files": [],
        "indicator_dirs": [],
        "config_patterns": [r"sqlalchemy"],
        "import_patterns": [r"^sqlalchemy"],
    },
    {
        "name": "pydantic",
        "language": "python",
        "indicator_files": [],
        "indicator_dirs": [],
        "config_patterns": [r"pydantic"],
        "import_patterns": [r"^pydantic"],
    },
]

_JS_FRAMEWORKS: list[dict[str, Any]] = [
    {
        "name": "next.js",
        "language": "javascript/typescript",
        "indicator_files": ["next.config.js", "next.config.ts", "next.config.mjs"],
        "indicator_dirs": [],
        "config_patterns": [r'"next"'],
        "import_patterns": [],
    },
    {
        "name": "react",
        "language": "javascript/typescript",
        "indicator_files": [],
        "indicator_dirs": [],
        "config_patterns": [r'"react"'],
        "import_patterns": [],
    },
    {
        "name": "express",
        "language": "javascript",
        "indicator_files": [],
        "indicator_dirs": [],
        "config_patterns": [r'"express"'],
        "import_patterns": [],
    },
]


class FrameworkDetector:
    def detect(self, repo_root: Path, all_file_paths: list[Path]) -> list[FrameworkInfo]:
        relative_paths = {p.relative_to(repo_root) for p in all_file_paths if p.is_relative_to(repo_root)}
        {str(p) for p in relative_paths}
        file_names = {p.name for p in relative_paths}
        dir_names = {str(part) for p in relative_paths for part in p.parts[:-1]}

        results: list[FrameworkInfo] = []

        for spec in _PYTHON_FRAMEWORKS:
            info = self._check_framework(spec, repo_root, file_names, dir_names)
            if info:
                results.append(info)

        # Check JS frameworks via package.json
        pkg_json = repo_root / "package.json"
        if pkg_json.exists():
            try:
                content = pkg_json.read_text(encoding="utf-8", errors="replace")
                for spec in _JS_FRAMEWORKS:
                    for pattern in spec["config_patterns"]:
                        if re.search(pattern, content):
                            results.append(
                                FrameworkInfo(
                                    name=spec["name"],
                                    language=spec["language"],
                                    confidence=0.9,
                                    evidence=["package.json"],
                                )
                            )
                            break
            except OSError:
                pass

        return results

    def _check_framework(
        self,
        spec: dict[str, Any],
        repo_root: Path,
        file_names: set[str],
        dir_names: set[str],
    ) -> FrameworkInfo | None:
        evidence: list[str] = []
        score = 0.0

        for fname in spec["indicator_files"]:
            if fname in file_names:
                evidence.append(fname)
                score += 0.4

        for dname in spec["indicator_dirs"]:
            if dname in dir_names:
                evidence.append(f"{dname}/")
                score += 0.2

        # Check pyproject.toml / requirements.txt / setup.cfg for package names
        for config_file in ["pyproject.toml", "requirements.txt", "requirements-dev.txt", "setup.cfg"]:
            config_path = repo_root / config_file
            if config_path.exists():
                try:
                    content = config_path.read_text(encoding="utf-8", errors="replace")
                    for pattern in spec["config_patterns"]:
                        if re.search(pattern, content, re.IGNORECASE):
                            evidence.append(config_file)
                            score += 0.4
                            break
                except OSError:
                    pass

        if score > 0:
            return FrameworkInfo(
                name=spec["name"],
                language=spec["language"],
                confidence=min(score, 1.0),
                evidence=evidence,
            )
        return None
