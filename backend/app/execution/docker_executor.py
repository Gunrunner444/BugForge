"""
Docker-backed test executor.

Runs test commands inside disposable, resource-limited containers.
Secrets from the BugForge host environment are never forwarded.
"""
from __future__ import annotations

import asyncio
import logging
import shlex
import time

from app.execution.base import ExecutionConfig, ExecutionResult, TestExecutor

logger = logging.getLogger(__name__)

# The image used to run Python project tests.  Override via executor config if needed.
DEFAULT_PYTHON_IMAGE = "python:3.12-slim"


class DockerTestExecutor(TestExecutor):
    """Executes commands inside short-lived Docker containers."""

    def __init__(self, image: str = DEFAULT_PYTHON_IMAGE) -> None:
        self._image = image

    async def is_available(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "info",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            return proc.returncode == 0
        except (OSError, FileNotFoundError):
            return False

    async def execute(self, config: ExecutionConfig) -> ExecutionResult:
        docker_args = self._build_docker_args(config)
        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=config.timeout_seconds + 10
                )
            except TimeoutError:
                proc.kill()
                await proc.communicate()
                duration = time.monotonic() - start
                return ExecutionResult(
                    exit_code=-1,
                    stdout="",
                    stderr="Execution timed out",
                    duration_seconds=duration,
                    timed_out=True,
                )
        except Exception as exc:
            duration = time.monotonic() - start
            logger.exception("Docker execution failed: %s", exc)
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_seconds=duration,
                error_message=str(exc),
            )

        duration = time.monotonic() - start
        return ExecutionResult(
            exit_code=proc.returncode or 0,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            duration_seconds=duration,
        )

    def _build_docker_args(self, config: ExecutionConfig) -> list[str]:
        args = [
            "docker", "run",
            "--rm",
            "--network", "none" if not config.allow_network else "bridge",
            "--memory", f"{config.memory_limit_mb}m",
            "--cpus", str(config.cpu_limit),
            "--stop-timeout", str(config.timeout_seconds),
            # Read-only filesystem except /tmp
            "--read-only",
            "--tmpfs", "/tmp:rw,size=128m",
            # Drop all capabilities
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-w", config.working_directory,
            "-v", f"{config.working_directory}:{config.working_directory}:ro",
        ]

        # Only forward explicitly allow-listed env vars (never the host environment)
        for key, value in config.environment.items():
            args += ["-e", f"{key}={value}"]

        args.append(self._image)
        # Use sh -c so the command string is interpreted in the container shell
        args += ["sh", "-c", shlex.join(config.command)]
        return args
