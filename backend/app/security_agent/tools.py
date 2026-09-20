"""Controlled tool registry. The AI never invokes subprocess or network directly."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

from app.security_agent.schemas import TOOL_ARG_MODELS, ToolCallRequest
from app.security_testing.errors import RestrictedActivityError, SafetyLimitExceededError

Executor = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    schema: type[BaseModel]
    budget_kind: str = "tool"
    disabled: bool = False


class ToolRegistry:
    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._executors: dict[str, Executor] = {}
        self._disabled: set[str] = set()

    def register(self, spec: ToolSpec, executor: Executor) -> None:
        self._specs[spec.name] = spec
        self._executors[spec.name] = executor

    def disable(self, name: str) -> None:
        self._disabled.add(name)

    def enable(self, name: str) -> None:
        self._disabled.discard(name)

    def known(self) -> tuple[str, ...]:
        return tuple(self._specs)

    def validate(self, request: ToolCallRequest) -> BaseModel:
        if request.tool not in self._specs:
            raise RestrictedActivityError(f"unknown_tool:{request.tool}")
        if request.tool in self._disabled or self._specs[request.tool].disabled:
            raise RestrictedActivityError(f"disabled_tool:{request.tool}")
        model = TOOL_ARG_MODELS.get(request.tool) or self._specs[request.tool].schema
        try:
            return model.model_validate(request.arguments)
        except ValidationError as exc:
            raise RestrictedActivityError(f"invalid_tool_arguments:{request.tool}") from exc

    async def execute(self, request: ToolCallRequest) -> dict[str, Any]:
        parsed = self.validate(request)
        executor = self._executors[request.tool]
        return await executor(parsed.model_dump())

    def catalog(self) -> list[dict[str, object]]:
        return [
            {
                "tool": spec.name,
                "description": spec.description,
                "disabled": spec.name in self._disabled,
            }
            for spec in self._specs.values()
        ]


def default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for name, model in TOOL_ARG_MODELS.items():
        registry.register(
            ToolSpec(name=name, description=name, schema=model),
            _unavailable(name),
        )
    return registry


def _unavailable(name: str) -> Executor:
    async def _run(_arguments: dict[str, Any]) -> dict[str, Any]:
        raise SafetyLimitExceededError(f"tool {name} has no executor bound")

    return _run
