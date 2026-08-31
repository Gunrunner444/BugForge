"""
Execution abstraction — all test execution goes through this interface.

Never call subprocess or docker directly from outside this module.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ExecutionConfig:
    """Parameters that control a single sandboxed execution."""

    command: list[str]
    working_directory: str
    timeout_seconds: int = 120
    memory_limit_mb: int = 512
    cpu_limit: float = 1.0  # number of CPUs
    environment: dict[str, str] = field(default_factory=dict)
    # When True the executor may allow outbound network (default off)
    allow_network: bool = False


@dataclass
class ExecutionResult:
    """Result returned by every executor implementation."""

    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    error_message: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class TestExecutor(ABC):
    """Abstract interface for sandboxed test execution.

    Concrete implementations:
      - DockerTestExecutor  (Docker containers — used in production)
      - LocalTestExecutor   (direct subprocess — only for development/testing)
    """

    @abstractmethod
    async def execute(self, config: ExecutionConfig) -> ExecutionResult:
        """Run the command described by config and return the result."""
        ...

    @abstractmethod
    async def is_available(self) -> bool:
        """Return True if this executor backend is usable in the current environment."""
        ...
