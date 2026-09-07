"""
AI provider abstraction — Phase 4 AI Debugging Engine.

All interactions with language models go through this interface.
No AI vendor SDK is imported at the module level; implementations are lazy.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Evidence types sent to the provider
# ---------------------------------------------------------------------------


@dataclass
class TestFailureEvidence:
    node_id: str
    test_file: str | None
    test_name: str
    traceback: str | None
    stdout: str | None
    stderr: str | None
    duration_seconds: float | None


@dataclass
class StaticFindingEvidence:
    category: str
    severity: str
    confidence: str
    file_path: str
    line: int
    message: str
    explanation: str
    evidence: str


@dataclass
class SourceFileEvidence:
    file_path: str
    content: str
    language: str = "python"


@dataclass
class DebuggingRequest:
    """Everything the AI provider receives to produce hypotheses."""

    project_name: str
    repository_path: str
    failing_tests: list[TestFailureEvidence]
    static_findings: list[StaticFindingEvidence]
    source_files: list[SourceFileEvidence]
    max_hypotheses: int = 3


# ---------------------------------------------------------------------------
# Structured hypothesis / response models
# ---------------------------------------------------------------------------


@dataclass
class HypothesisResult:
    root_cause: str
    confidence: float  # 0.0–1.0
    confidence_label: str  # confirmed | highly_likely | likely | possible | insufficient_evidence
    affected_files: list[str]
    affected_symbols: list[str]
    evidence_summary: list[str]
    contradictory_evidence: list[str]
    reproduction_strategy: str
    recommended_tests: list[str]
    explanation: str


@dataclass
class AIUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class ProviderResponse:
    """Raw output from the AI provider, before storage."""

    hypotheses: list[HypothesisResult]
    provider: str
    model: str
    usage: AIUsage
    duration_seconds: float
    raw_json: str = ""
    error: str | None = None


@dataclass
class TestGenerationResponse:
    """Structured response from generate_tests()."""

    candidates_json: str
    provider: str
    model: str
    usage: AIUsage
    duration_seconds: float
    error: str | None = None


@dataclass
class StructuredTextResponse:
    """Raw JSON response from generate_structured()."""

    content: str
    provider: str
    model: str
    usage: AIUsage
    duration_seconds: float
    error: str | None = None


# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------


class LLMProvider(ABC):
    """Abstract interface for all language-model backends.

    Implementations must NOT log API keys or full prompt contents at any level.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Short identifier e.g. 'openai', 'anthropic', 'mock'."""
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        ...

    @abstractmethod
    async def analyze(self, request: DebuggingRequest) -> ProviderResponse:
        """Run AI analysis and return structured hypotheses.

        Must never raise on transient errors; return ProviderResponse with
        error field set instead so callers can distinguish failure types.
        """
        ...

    @abstractmethod
    async def is_available(self) -> bool:
        """Return True if this provider is usable (key set, reachable, etc.)."""
        ...

    @abstractmethod
    async def generate_tests(self, system_prompt: str, user_message: str) -> TestGenerationResponse:
        """Generate test candidates from evidence.

        system_prompt contains BugForge instructions (trusted).
        user_message contains evidence + [REPOSITORY_DATA] tagged untrusted content.
        Returns a TestGenerationResponse with the raw JSON candidates.
        """
        ...

    @abstractmethod
    async def generate_structured(self, system_prompt: str, user_message: str) -> StructuredTextResponse:
        """Generic structured generation for reproduction planning and other tasks."""
        ...

    @abstractmethod
    async def generate_patch(self, system_prompt: str, user_message: str) -> StructuredTextResponse:
        """Generate a repair patch from evidence.

        system_prompt contains BugForge instructions (trusted).
        user_message contains evidence + [REPOSITORY_DATA] tagged untrusted content.
        Returns a StructuredTextResponse whose content is a JSON patch plan.
        """
        ...
