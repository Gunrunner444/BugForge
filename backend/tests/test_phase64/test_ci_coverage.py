"""The Foundry job must name every test module that requires Forge.

A directory argument covers the modules under it. A manually copied list that
omits a new phase fails this test in the ordinary pytest job, which does not
itself install Forge.
"""

from __future__ import annotations

import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
WORKFLOW = BACKEND.parent / ".github" / "workflows" / "backend.yml"
TESTS = BACKEND / "tests"


def _pytest_args(job: str) -> list[str]:
    text = WORKFLOW.read_text(encoding="utf-8")
    body = text.split(f"  {job}:", 1)[1]
    next_job = re.search(r"\n {2}[A-Za-z]", body)
    if next_job is not None:
        body = body[: next_job.start()]
    return re.findall(r"tests/[A-Za-z0-9_./:-]+", body)


def _requires_forge(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return "requires_forge" in text


def _covered(relative: str, args: list[str]) -> bool:
    module = relative.removesuffix(".py").replace("/", ".")
    for arg in args:
        cleaned = arg.rstrip("/")
        if relative == cleaned or relative.startswith(cleaned + "/"):
            return True
        if cleaned.startswith(relative):
            return True
        # pytest node ids: tests/file.py::test_name
        if cleaned.split("::", 1)[0] in {relative, relative.removesuffix(".py")}:
            return True
        if module and cleaned.replace("/", ".").startswith(module):
            return True
    return False


def test_every_forge_module_is_in_a_foundry_job() -> None:
    assert WORKFLOW.is_file()
    jobs = ("stateful-integration:", "compound-integration:", "yearn-integration:")
    text = WORKFLOW.read_text(encoding="utf-8")
    for name in jobs:
        assert name in text
    covered_by: list[str] = []
    for job in ("stateful-integration", "compound-integration", "yearn-integration"):
        covered_by.extend(_pytest_args(job))
    missing = []
    for path in sorted(TESTS.rglob("test_*.py")):
        if not _requires_forge(path):
            continue
        relative = path.relative_to(BACKEND).as_posix()
        if not _covered(relative, covered_by):
            missing.append(relative)
    assert missing == []


def test_required_ci_selects_backend_and_workflow_changes() -> None:
    workflow = BACKEND.parent / ".github" / "workflows" / "required-ci.yml"
    text = workflow.read_text(encoding="utf-8")
    match = re.search(r"grep -Eq '([^']+)'", text)
    assert match is not None
    pattern = match.group(1)
    assert re.search(pattern, "backend/app/discovery/bounty/applicability.py")
    assert re.search(pattern, ".github/workflows/backend.yml")
    assert re.search(pattern, ".github/workflows/required-ci.yml")
    assert re.search(pattern, "frontend/src/main.tsx") is None
    assert re.search(pattern, "README.md") is None


def test_the_foundry_job_fails_closed_when_forge_is_absent() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    stateful = text.split("  stateful-integration:", 1)[1].split("  compound-integration:", 1)[0]
    assert "BUGFORGE_REQUIRE_FOUNDRY" in stateful
    assert "continue-on-error" not in stateful
    assert "tests/test_phase64" in stateful
    yearn = text.split("  yearn-integration:", 1)[1]
    assert "82806289f967590c4efbf6bc3d237e4e7f0a0966" in yearn
    assert "0.8.18" in yearn
    assert "BUGFORGE_REQUIRE_YEARN" in yearn
    assert "FOUNDRY_OFFLINE" in yearn
    assert "continue-on-error" not in yearn
