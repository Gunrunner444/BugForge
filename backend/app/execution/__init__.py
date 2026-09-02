from __future__ import annotations

import logging
import shutil

from app.execution.base import ExecutionConfig, ExecutionResult, TestExecutor
from app.execution.docker_executor import DockerTestExecutor
from app.execution.local_executor import LocalTestExecutor

logger = logging.getLogger(__name__)

__all__ = [
    "TestExecutor",
    "ExecutionConfig",
    "ExecutionResult",
    "DockerTestExecutor",
    "LocalTestExecutor",
    "ExecutorFactory",
]


class ExecutorFactory:
    """Select the best available executor at runtime.

    Preference order:
      1. DockerTestExecutor — when Docker is installed and reachable.
      2. LocalTestExecutor  — fallback for development environments.

    The LocalTestExecutor runs code directly on the host and is NOT safe for
    production use with untrusted repositories.  It is provided only so that
    local development works without Docker.
    """

    @staticmethod
    def create(prefer_docker: bool = True) -> TestExecutor:
        """Return the best synchronously-detectable executor."""
        if prefer_docker and shutil.which("docker") is not None:
            return DockerTestExecutor()
        if prefer_docker:
            logger.warning(
                "Docker not found; falling back to LocalTestExecutor "
                "(development only — do not use with untrusted code)"
            )
        return LocalTestExecutor()

