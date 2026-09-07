"""AI provider factory and health-check helpers (v1.1.0).

Centralises provider instantiation so the rest of the codebase
never calls provider constructors directly.

Local AI (Ollama, LM Studio, etc.) is supported via the
OpenAI-compatible endpoint — just set:

  AI_PROVIDER=ollama           (or openai_compatible)
  AI_BASE_URL=http://localhost:11434/v1
  AI_MODEL=qwen2.5-coder:7b   (or any model you have pulled)
  AI_API_KEY=                  (empty is fine for Ollama)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from app.ai.provider import LLMProvider
from app.core.config import Settings

logger = logging.getLogger(__name__)

_OLLAMA_DEFAULT_BASE = "http://localhost:11434/v1"


@dataclass
class AIHealthStatus:
    """Result of a provider health check."""

    provider: str
    model: str
    is_local: bool
    reachable: bool
    configured: bool
    model_available: bool | None  # None = unknown (couldn't verify)
    error: str | None = None
    capabilities: list[str] | None = None


def create_provider(settings: Settings) -> LLMProvider:
    """Return the configured LLM provider instance.

    ollama / openai_compatible both use OpenAIProvider with a custom base_url.
    """
    provider_name = settings.ai_provider
    api_key = settings.ai_api_key
    model = settings.ai_model
    base_url = settings.ai_base_url
    max_tokens = settings.ai_max_output_tokens
    temperature = settings.ai_temperature
    timeout = settings.ai_timeout_seconds
    max_retries = settings.ai_max_retries

    if provider_name == "mock":
        from app.ai.mock_provider import MockLLMProvider
        return MockLLMProvider()

    if provider_name == "anthropic":
        from app.ai.anthropic_provider import AnthropicProvider
        return AnthropicProvider(
            api_key=api_key,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout_seconds=timeout,
            max_retries=max_retries,
        )

    if provider_name in {"openai", "ollama", "openai_compatible"}:
        from app.ai.openai_provider import OpenAIProvider
        # Ollama default base URL when none is configured
        resolved_base = base_url
        if not resolved_base and provider_name == "ollama":
            resolved_base = _OLLAMA_DEFAULT_BASE
        # Ollama accepts empty or "ollama" as the API key
        resolved_key = api_key if api_key else ("ollama" if provider_name == "ollama" else "")
        return OpenAIProvider(
            api_key=resolved_key,
            model=model,
            base_url=resolved_base,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout_seconds=timeout,
            max_retries=max_retries,
        )

    raise ValueError(f"Unknown AI provider: {provider_name!r}")


async def check_ai_health(settings: Settings) -> AIHealthStatus:
    """Probe the configured AI provider and return a health report.

    Never includes API keys in the returned object.
    """
    provider_name = settings.ai_provider
    model = settings.ai_model
    is_local = settings.is_local_ai()
    capabilities = ["analysis", "test_generation", "patch_generation"]

    if provider_name == "mock":
        return AIHealthStatus(
            provider="mock",
            model=model,
            is_local=True,
            reachable=True,
            configured=True,
            model_available=True,
            capabilities=capabilities,
        )

    if provider_name == "anthropic":
        # Anthropic: check that the key is set; we can't easily list models
        configured = bool(settings.ai_api_key)
        return AIHealthStatus(
            provider="anthropic",
            model=model,
            is_local=False,
            reachable=configured,  # assume reachable if key is present
            configured=configured,
            model_available=None,
            error=None if configured else "AI_API_KEY not configured",
            capabilities=capabilities,
        )

    # OpenAI / Ollama / openai_compatible
    base_url = settings.ai_base_url
    if not base_url and provider_name == "ollama":
        base_url = _OLLAMA_DEFAULT_BASE

    if not base_url:
        base_url = "https://api.openai.com/v1"

    configured = bool(settings.ai_api_key) or provider_name in {"ollama", "openai_compatible"}

    # Attempt a cheap HTTP probe
    reachable = False
    model_available: bool | None = None
    error: str | None = None

    try:
        headers: dict[str, str] = {}
        api_key = settings.ai_api_key
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        elif provider_name == "ollama":
            headers["Authorization"] = "Bearer ollama"

        async with httpx.AsyncClient(timeout=10.0) as client:
            # Try to list models (works for both Ollama /v1/models and OpenAI)
            models_url = base_url.rstrip("/").removesuffix("/chat/completions") + "/models"
            resp = await client.get(models_url, headers=headers)
            if resp.status_code in {200, 401, 403}:
                # 401/403 means the server responded (key issue, not connectivity)
                reachable = True
                if resp.status_code == 200:
                    data = resp.json()
                    model_ids: list[str] = []
                    for m in data.get("data", []):
                        if isinstance(m, dict):
                            mid = m.get("id") or m.get("name") or ""
                            model_ids.append(str(mid))
                    # Accept exact match or prefix match (e.g. "qwen3" matches "qwen3:latest")
                    model_available = any(
                        mid == model or mid.startswith(model) or model.startswith(mid.split(":")[0])
                        for mid in model_ids
                    )
                    if model_available is False and not model_ids:
                        model_available = None  # couldn't determine
            else:
                reachable = True  # server responded, even with unexpected status
                error = f"unexpected_status:{resp.status_code}"
    except httpx.ConnectError:
        error = f"connection_refused:{base_url}"
    except httpx.TimeoutException:
        error = f"timeout:{base_url}"
    except Exception as exc:
        error = f"error:{exc}"

    return AIHealthStatus(
        provider=provider_name,
        model=model,
        is_local=is_local,
        reachable=reachable,
        configured=configured,
        model_available=model_available,
        error=error,
        capabilities=capabilities if reachable else None,
    )
