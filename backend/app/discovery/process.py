"""Controlled local process execution for optional discovery tools.

Commands are argument lists. BugForge secrets are stripped. Output is redacted.
Nothing is downloaded.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from app.security_testing.secrets import redact_text

_STRIP = frozenset(
    {
        "SECRET_KEY",
        "DATABASE_URL",
        "POSTGRES_PASSWORD",
        "REDIS_URL",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
        "BUGFORGE_OPERATOR_TOKEN",
    }
)


def tool_path(name: str) -> str | None:
    return shutil.which(name)


def tool_version(name: str, args: tuple[str, ...] = ("--version",)) -> str:
    path = tool_path(name)
    if path is None:
        return ""
    try:
        completed = subprocess.run(
            [path, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env=_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    text = (completed.stdout or completed.stderr).strip().splitlines()
    return text[0][:120] if text else ""


def run_command(
    argv: list[str],
    *,
    cwd: Path,
    timeout: float = 30,
    stdin: str = "",
) -> tuple[int, str, str, bool]:
    if not argv or "/" in argv[0] or argv[0].startswith("."):
        name = argv[0] if argv else "command"
        return 127, "", f"refusing path-qualified command {name}", False
    if tool_path(argv[0]) is None:
        return 127, "", f"{argv[0]} is not installed", False
    executable = tool_path(argv[0]) or argv[0]
    try:
        completed = subprocess.run(
            [executable, *argv[1:]],
            cwd=cwd,
            input=stdin,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_env(),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode("utf-8", "replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        stderr = (
            exc.stderr.decode("utf-8", "replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )
        return -1, redact_text(stdout), redact_text(stderr or "timed out"), True
    except OSError as exc:
        return -1, "", redact_text(str(exc)), False
    return completed.returncode, redact_text(completed.stdout), redact_text(completed.stderr), False


def _env() -> dict[str, str]:
    env = os.environ.copy()
    for key in _STRIP:
        env.pop(key, None)
    return env
