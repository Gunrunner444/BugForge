"""Local AI provider — OpenAI-compatible HTTP backends (Ollama, LM Studio).

A future MLX transport (e.g. Qwen3.6-35B-A3B) can plug in by implementing the
same :class:`LLMProvider` interface or by extending ``backend='mlx'``. That
backend is intentionally not implemented in this phase.
"""

from __future__ import annotations

from app.ai.health import AIHealthStatus, probe_openai_compatible
from app.ai.openai_provider import OpenAIProvider
from app.ai.provider import (
    DebuggingRequest,
    LLMProvider,
    ProviderResponse,
    StructuredTextResponse,
    TestGenerationResponse,
)
from app.plugins.errors import AdapterNotImplementedError

_OLLAMA_DEFAULT_BASE = "http://localhost:11434/v1"
_OPENAI_COMPAT_CHAT = "https://api.openai.com/v1/chat/completions"


class LocalAIProvider(LLMProvider):
    """Local-model facade over an OpenAI-compatible HTTP endpoint.

    ``backend`` selects the transport:
      * ``openai_compatible`` (default) — Ollama, LM Studio, llama.cpp server
      * ``mlx`` — reserved; raises until the later local-model phase
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "",
        max_tokens: int = 2_000,
        temperature: float = 0.1,
        timeout_seconds: int = 60,
        max_retries: int = 2,
        *,
        backend: str = "openai_compatible",
        provider_name: str = "local",
    ) -> None:
        if backend == "mlx":
            raise AdapterNotImplementedError(
                "MLX local backend is reserved for a later phase "
                "(planned: Qwen via MLX). Use backend='openai_compatible' "
                "with Ollama or LM Studio for now."
            )
        if backend != "openai_compatible":
            raise ValueError(
                f"Unknown local AI backend {backend!r}. "
                "Supported: 'openai_compatible'. Reserved: 'mlx'."
            )
        resolved_base = base_url or _OLLAMA_DEFAULT_BASE
        # Local servers often ignore the key; OpenAIProvider still sends a Bearer token.
        resolved_key = api_key or "ollama"
        self._inner = OpenAIProvider(
            api_key=resolved_key,
            model=model,
            base_url=resolved_base,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )
        self._provider_name = provider_name
        self._base_url = resolved_base
        self._api_key = api_key
        self._configured = True

    @classmethod
    def from_settings(cls, settings: object) -> LocalAIProvider:
        from app.core.config import Settings

        assert isinstance(settings, Settings)
        provider_name = settings.ai_provider
        base_url = settings.ai_base_url
        if not base_url and provider_name == "ollama":
            base_url = _OLLAMA_DEFAULT_BASE
        api_key = settings.ai_api_key
        if not api_key and provider_name == "ollama":
            api_key = "ollama"
        return cls(
            api_key=api_key,
            model=settings.ai_model,
            base_url=base_url,
            max_tokens=settings.ai_max_output_tokens,
            temperature=settings.ai_temperature,
            timeout_seconds=settings.ai_timeout_seconds,
            max_retries=settings.ai_max_retries,
            backend="openai_compatible",
            provider_name=provider_name if provider_name != "local" else "local",
        )

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def model_name(self) -> str:
        return self._inner.model_name

    async def is_available(self) -> bool:
        return True

    async def analyze(self, request: DebuggingRequest) -> ProviderResponse:
        response = await self._inner.analyze(request)
        response.provider = self.provider_name
        return response

    async def generate_tests(self, system_prompt: str, user_message: str) -> TestGenerationResponse:
        response = await self._inner.generate_tests(system_prompt, user_message)
        response.provider = self.provider_name
        return response

    async def generate_structured(
        self, system_prompt: str, user_message: str
    ) -> StructuredTextResponse:
        response = await self._inner.generate_structured(system_prompt, user_message)
        response.provider = self.provider_name
        return response

    async def generate_patch(self, system_prompt: str, user_message: str) -> StructuredTextResponse:
        return await self.generate_structured(system_prompt, user_message)

    async def health(self) -> AIHealthStatus:
        base = self._base_url or _OLLAMA_DEFAULT_BASE
        key = self._api_key or ("ollama" if self._provider_name == "ollama" else "")
        return await probe_openai_compatible(
            provider=self.provider_name,
            model=self.model_name,
            base_url=base,
            api_key=key,
            is_local=True,
            configured=True,
        )
