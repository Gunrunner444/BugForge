"""Register built-in adapters. Called once when the catalog is first created."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.adapters.evidence.collectors import (
    ReproductionEvidenceCollector,
    SourceCodeEvidenceCollector,
    StaticAnalysisEvidenceCollector,
    TestFailureEvidenceCollector,
)
from app.adapters.languages.known import AUXILIARY_LANGUAGES, PROGRAMMING_LANGUAGE_ADAPTERS
from app.adapters.languages.python import PythonAdapter
from app.adapters.reports.local import LocalReportProvider
from app.adapters.scope.manual import ManualScopeProvider

if TYPE_CHECKING:
    from app.core.config import Settings
    from app.plugins.catalog import PluginCatalog


def register_builtin_adapters(catalog: PluginCatalog) -> None:
    _register_languages(catalog)
    _register_ai_providers(catalog)
    _register_reporting(catalog)
    _register_scope(catalog)
    _register_evidence_collectors(catalog)


def _register_languages(catalog: PluginCatalog) -> None:
    catalog.languages.register_adapter(PythonAdapter())
    for adapter_cls in PROGRAMMING_LANGUAGE_ADAPTERS:
        catalog.languages.register_adapter(adapter_cls())
    for adapter in AUXILIARY_LANGUAGES:
        catalog.languages.register_adapter(adapter)


def _register_ai_providers(catalog: PluginCatalog) -> None:
    from app.ai.anthropic_provider import AnthropicProvider
    from app.ai.local_provider import LocalAIProvider
    from app.ai.mock_provider import MockLLMProvider
    from app.ai.openai_provider import OpenAIProvider

    def mock_factory(settings: Settings | None = None) -> MockLLMProvider:
        return MockLLMProvider()

    def openai_factory(settings: Settings) -> OpenAIProvider:
        return OpenAIProvider(
            api_key=settings.ai_api_key,
            model=settings.ai_model,
            base_url=settings.ai_base_url,
            max_tokens=settings.ai_max_output_tokens,
            temperature=settings.ai_temperature,
            timeout_seconds=settings.ai_timeout_seconds,
            max_retries=settings.ai_max_retries,
        )

    def anthropic_factory(settings: Settings) -> AnthropicProvider:
        return AnthropicProvider(
            api_key=settings.ai_api_key,
            model=settings.ai_model,
            max_tokens=settings.ai_max_output_tokens,
            temperature=settings.ai_temperature,
            timeout_seconds=settings.ai_timeout_seconds,
            max_retries=settings.ai_max_retries,
        )

    def local_factory(settings: Settings) -> LocalAIProvider:
        return LocalAIProvider.from_settings(settings)

    catalog.ai_providers.register(
        "mock", mock_factory, aliases=("testing",), description="Deterministic mock provider"
    )
    catalog.ai_providers.register("openai", openai_factory, description="OpenAI chat completions")
    catalog.ai_providers.register(
        "anthropic", anthropic_factory, description="Anthropic Messages API"
    )
    catalog.ai_providers.register(
        "local",
        local_factory,
        aliases=("ollama", "openai_compatible"),
        description="Local OpenAI-compatible models (Ollama, LM Studio). MLX reserved.",
    )


def _register_reporting(catalog: PluginCatalog) -> None:
    catalog.report_providers.register(
        "local", LocalReportProvider, description="Local markdown report"
    )


def _register_scope(catalog: PluginCatalog) -> None:
    catalog.scope_providers.register(
        "manual", ManualScopeProvider, description="Operator-supplied scope"
    )


def _register_evidence_collectors(catalog: PluginCatalog) -> None:
    catalog.evidence_collectors.register("static_analysis", StaticAnalysisEvidenceCollector)
    catalog.evidence_collectors.register("test_failure", TestFailureEvidenceCollector)
    catalog.evidence_collectors.register("source_code", SourceCodeEvidenceCollector)
    catalog.evidence_collectors.register("reproduction", ReproductionEvidenceCollector)
