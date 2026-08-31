"""
Test runner service — Phase 2 entry point.

Discovers pytest, executes it via the configured TestExecutor,
parses the JSON output, and persists results.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from uuid import UUID

from app.execution.base import ExecutionConfig, TestExecutor
from app.testing.pytest_parser import ParsedTestRun, parse_pytest_json

logger = logging.getLogger(__name__)

# Maximum stdout/stderr to store per run (2 MB each)
_MAX_OUTPUT_BYTES = 2 * 1024 * 1024


class TestRunNotFoundError(Exception):
    pass


class TestRunnerService:
    """Orchestrates test discovery, execution, and persistence."""

    def __init__(self, executor: TestExecutor) -> None:
        self._executor = executor

    async def create_test_run(self, project_id: UUID, repository_path: str) -> Any:
        """Create a pending TestRun record and return it."""
        from app.database import async_session_factory
        from app.models.test_run import TestRun

        async with async_session_factory() as session:
            run = TestRun(project_id=project_id, repository_path=repository_path, status="pending")
            session.add(run)
            await session.commit()
            await session.refresh(run)
            return run

    async def execute_test_run(self, test_run_id: UUID, repository_path: str) -> None:
        """Full test pipeline. Runs as a background task."""
        from app.database import async_session_factory
        from app.repositories.test_run_repo import TestRunRepository

        logger.info("Starting test run %s for %s", test_run_id, repository_path)

        async with async_session_factory() as session:
            repo = TestRunRepository(session)
            await repo.update_status(test_run_id, "running")
            await session.commit()

        try:
            result = await self._run_pytest(repository_path)
            async with async_session_factory() as session:
                repo = TestRunRepository(session)
                await repo.complete(test_run_id, result, repository_path)
                await session.commit()
            logger.info("Test run %s completed — %d tests", test_run_id, result.total)
        except Exception as exc:
            logger.exception("Test run %s failed: %s", test_run_id, exc)
            async with async_session_factory() as session:
                repo = TestRunRepository(session)
                await repo.fail(test_run_id, str(exc))
                await session.commit()

    async def _run_pytest(self, repository_path: str) -> ParsedTestRun:
        """Execute pytest with JSON report output and parse results."""
        repo_path = Path(repository_path)

        # Build the pytest command — always use --json-report for structured output
        command = [
            "python", "-m", "pytest",
            "--tb=short",
            "--json-report",
            "--json-report-file=/tmp/bugforge_report.json",
            "-q",
        ]

        config = ExecutionConfig(
            command=command,
            working_directory=str(repo_path),
            timeout_seconds=120,
            environment={"PYTHONPATH": str(repo_path)},
        )

        exec_result = await self._executor.execute(config)
        stdout = exec_result.stdout[:_MAX_OUTPUT_BYTES]
        stderr = exec_result.stderr[:_MAX_OUTPUT_BYTES]

        # Try to read the JSON report from stdout embedding (local executor)
        # or reconstruct from output when using Docker
        parsed = self._extract_json_report(stdout)
        if not parsed:
            parsed = self._parse_text_output(stdout, stderr, exec_result.exit_code)

        return parsed

    def _extract_json_report(self, stdout: str) -> ParsedTestRun | None:
        """Attempt to find embedded JSON report in stdout."""
        # pytest-json-report writes to a file; in local mode we read it inline
        # by also passing --json-report-indent=2 which makes it appear in stdout
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("{") and '"tests"' in line:
                try:
                    return parse_pytest_json(line)
                except Exception:
                    pass
        return None

    def _parse_text_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> ParsedTestRun:
        """Fallback: parse basic pass/fail counts from pytest text output."""
        run = ParsedTestRun()
        for line in (stdout + "\n" + stderr).splitlines():
            line = line.strip()
            if " passed" in line or " failed" in line or " error" in line:
                parts = line.split(",")
                for part in parts:
                    part = part.strip()
                    if "passed" in part:
                        try:
                            run.passed = int(part.split()[0])
                        except (ValueError, IndexError):
                            pass
                    elif "failed" in part:
                        try:
                            run.failed = int(part.split()[0])
                        except (ValueError, IndexError):
                            pass
                    elif "skipped" in part:
                        try:
                            run.skipped = int(part.split()[0])
                        except (ValueError, IndexError):
                            pass
                    elif "error" in part:
                        try:
                            run.errors = int(part.split()[0])
                        except (ValueError, IndexError):
                            pass
                run.total = run.passed + run.failed + run.skipped + run.errors
        return run
