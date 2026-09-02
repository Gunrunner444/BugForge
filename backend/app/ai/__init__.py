from app.ai.anthropic_provider import AnthropicProvider
from app.ai.context_builder import ContextBuilder
from app.ai.mock_provider import MockLLMProvider
from app.ai.openai_provider import OpenAIProvider
from app.ai.prompt_builder import PromptBuilder
from app.ai.provider import (
    AIUsage,
    DebuggingRequest,
    HypothesisResult,
    LLMProvider,
    ProviderResponse,
    SourceFileEvidence,
    StaticFindingEvidence,
    TestFailureEvidence,
)


def get_provider() -> LLMProvider:
    """Return the configured AI provider based on settings."""
    from app.core.config import settings

    provider = settings.ai_provider.lower()
    if provider == "openai":
        return OpenAIProvider(
            api_key=settings.ai_api_key,
            model=settings.ai_model,
            base_url=settings.ai_base_url,
            max_tokens=settings.ai_max_output_tokens,
            temperature=settings.ai_temperature,
            timeout_seconds=settings.ai_timeout_seconds,
            max_retries=settings.ai_max_retries,
        )
    if provider == "anthropic":
        return AnthropicProvider(
            api_key=settings.ai_api_key,
            model=settings.ai_model,
            max_tokens=settings.ai_max_output_tokens,
            temperature=settings.ai_temperature,
            timeout_seconds=settings.ai_timeout_seconds,
            max_retries=settings.ai_max_retries,
        )
    return MockLLMProvider()


__all__ = [
    "LLMProvider",
    "DebuggingRequest",
    "ProviderResponse",
    "HypothesisResult",
    "TestFailureEvidence",
    "StaticFindingEvidence",
    "SourceFileEvidence",
    "AIUsage",
    "MockLLMProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "ContextBuilder",
    "PromptBuilder",
    "get_provider",
]
