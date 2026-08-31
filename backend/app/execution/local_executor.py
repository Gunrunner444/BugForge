"""
Local subprocess executor — for development and CI where Docker is unavailable.

WARNING: This executor does NOT sandbox the executed code.
Never use it on production BugForge instances.
"""
from __future__ import annotations

import asyncio
import logging
import time

from app.execution.base import ExecutionConfig, ExecutionResult, TestExecutor

logger = logging.getLogger(__name__)


class LocalTestExecutor(TestExecutor):
    """Runs commands directly on the host via asyncio subprocess.

    Only suitable for trusted repositories in development environments.
    """

    async def is_available(self) -> bool:
        return True

    async def execute(self, config: ExecutionConfig) -> ExecutionResult:
        start = time.monotonic()
        env = {**config.environment} if config.environment else None

        try:
            proc = await asyncio.create_subprocess_exec(
                *config.command,
                cwd=config.working_directory,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except (OSError, FileNotFoundError) as exc:
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_seconds=time.monotonic() - start,
                error_message=str(exc),
            )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=config.timeout_seconds
            )
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr="Execution timed out",
                duration_seconds=time.monotonic() - start,
                timed_out=True,
            )

        duration = time.monotonic() - start
        return ExecutionResult(
            exit_code=proc.returncode or 0,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            duration_seconds=duration,
        )
