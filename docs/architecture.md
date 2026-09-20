# BugForge Adapter Architecture

BugForge is an evidence-first debugging platform that is growing into an
AI-assisted software security research and vulnerability verification
platform. Phase 1 establishes the adapter foundation so languages, AI
backends, and future security tools can be added without rewriting core
orchestration.

Debugging behavior is unchanged. Security scanning, browser exploitation,
live fuzzing, and HackerOne submission are **intentionally not implemented**
in this phase.

## Layering

```
Domain models          app/domain/
        ↓
Adapter interfaces     app/adapters/*/base.py
        ↓
Implementations        app/adapters/* , app/ai/* , app/analysis/*
        ↓
Plugin catalog         app/plugins/
        ↓
Orchestration          app/analyzers , app/analysis/engine.py , app/ai/factory.py
```

The core domain does not import Burp, HackerOne, OpenAI, or ZAP types.
Adapters translate those systems into domain objects (`Evidence`,
`SecurityFinding`, `HttpExchange`, `ScopeConstraint`).

Lookups go through `PluginCatalog` instead of `if language == ...` /
`if provider == ...` branches.

## Plugin catalog

```python
from app.plugins import get_plugin_catalog

catalog = get_plugin_catalog()
python = catalog.languages.get("python")
provider = catalog.ai_providers.create("mock", settings)
```

Registries:

| Registry | Purpose |
|---|---|
| `languages` | Detection, parsing, static analysis |
| `ai_providers` | Mock, OpenAI, Anthropic, local |
| `security_tools` | Future scanners (empty until implemented) |
| `browsers` | Future browser evidence |
| `proxies` | Future HTTP capture ingestion |
| `fuzzers` | Future in-scope fuzzing |
| `report_providers` | Local structured reports |
| `scope_providers` | Authorized-testing scope |
| `evidence_collectors` | Convert existing artifacts into `Evidence` |

Unknown ids raise `AdapterNotFoundError` and list known ids.

## Language adapters

`LanguageAdapter` is the contract. Capabilities are explicit:

- `DETECTION` — map file extensions to a language id
- `SOURCE` — count as source code in repository classification
- `PARSE` — extract entities/imports
- `STATIC_ANALYSIS` — emit static findings

**Python is fully implemented** (`PythonAdapter`) and wraps the existing
parser (`app/analyzers/python`) and AST rules (`app/analysis/python_analyzer.py`).
Repository analysis and `StaticAnalysisEngine` select it through the registry.

JavaScript, TypeScript, Ruby, C, C++, Go, Rust, Java, PHP, Kotlin, and Swift
are registered for **detection only**. Calling `parse_file` or `analyze_file`
raises `UnsupportedCapabilityError` — they do not pretend to analyze code.

### Adding a language

1. Implement `LanguageAdapter` (start with detection-only if analysis is not ready).
2. Register it in `app/plugins/bootstrap.py` (or at runtime in tests).
3. Do **not** add `if language == "ruby"` branches in orchestration.

```python
from pathlib import Path

from app.adapters.languages.base import LanguageAdapter
from app.domain.language import LanguageCapability
from app.plugins import get_plugin_catalog

class RubyAnalyzerAdapter(LanguageAdapter):
    @property
    def language_id(self) -> str:
        return "ruby"

    @property
    def display_name(self) -> str:
        return "Ruby"

    @property
    def file_extensions(self) -> frozenset[str]:
        return frozenset({".rb"})

    @property
    def capabilities(self) -> frozenset[LanguageCapability]:
        return frozenset({
            LanguageCapability.DETECTION,
            LanguageCapability.SOURCE,
            LanguageCapability.PARSE,
            LanguageCapability.STATIC_ANALYSIS,
        })

    def parse_file(self, file_path: Path, *, context: object | None = None):
        ...  # real Ruby parser

    def analyze_file(self, file_path: Path, source: str):
        ...  # real Ruby rules

# Either replace the detection-only adapter in bootstrap, or:
get_plugin_catalog().languages.register_adapter(RubyAnalyzerAdapter(), replace=True)
```

Unrelated modules (AI factory, Docker executor, GitHub delivery) do not change.

## AI providers

`LLMProvider` (aliased as `AIProvider`) is the interface. Implementations:

| Id | Class | Notes |
|---|---|---|
| `mock` | `MockLLMProvider` | Deterministic, no network |
| `openai` | `OpenAIProvider` | OpenAI chat completions |
| `anthropic` | `AnthropicProvider` | Anthropic Messages API |
| `local` | `LocalAIProvider` | OpenAI-compatible local HTTP |
| `ollama` / `openai_compatible` | aliases of `local` | Backwards compatible |

`create_provider(settings)` and `get_provider()` resolve through the catalog.
Repository content is still wrapped in `[REPOSITORY_DATA]` by `PromptBuilder`.

### Adding an AI provider

1. Subclass `LLMProvider`.
2. Register a factory in `register_builtin_adapters`.
3. Add the id to `Settings` `_VALID_AI_PROVIDERS` if it should be selectable via `AI_PROVIDER`.

`LocalAIProvider(backend="mlx")` is reserved for a later Qwen/MLX phase and
raises `AdapterNotImplementedError` today.

## Security tools

`SecurityToolAdapter` is the future scanner boundary (`collect_passive_evidence`).
Burp, ZAP, and Nuclei are **not** implemented. Register a real adapter when the
tool integration exists; do not ship empty classes that claim to scan.

## Browser / proxy / fuzzing

`BrowserAdapter`, `ProxyAdapter`, and `FuzzingAdapter` define evidence-oriented
contracts (navigation/DOM/screenshots, captured HTTP exchanges, fuzz targets).
They must honor `ScopeProvider`. Live testing against external targets is out
of scope for Phase 1.

## Evidence and findings

BugForge remains evidence-first:

- Static findings (`app.analysis.finding.Finding`) are tool output, not verified vulns.
- `EvidenceCollector` converts static findings, failing tests, source, and
  reproduction artifacts into `Evidence`.
- `SecurityFinding.from_hypothesis()` always creates a **potential** finding.
- `SecurityFinding.verified()` requires a non-empty evidence bundle.

A model-generated hypothesis cannot become a verified finding by itself.

## Reports and scope

- `LocalReportProvider` renders a structured markdown report locally. It does
  not upload anything.
- `ManualScopeProvider` uses operator-supplied allow/deny lists. An empty
  allow-list denies every target.
- HackerOne report submission and remote scope retrieval are reserved.

## Configuration

Existing `AI_PROVIDER` / `AI_MODEL` / `AI_BASE_URL` settings are unchanged.
New optional setting:

| Variable | Default | Meaning |
|---|---|---|
| `LANGUAGE_ANALYZERS` | empty | Comma-separated analyzer ids. Empty = every adapter that implements `STATIC_ANALYSIS` (currently `python`). Unknown ids or detection-only languages raise a useful error. |

Do not set browser/proxy/fuzzer providers until those adapters exist.

## What Phase 2 can build on

- Real analyzers for the detection-only languages
- Local MLX/Qwen `LocalAIProvider` backend
- Security-tool adapters that emit `Evidence`
- Browser/proxy collectors feeding `SecurityFinding`
- In-scope fuzzing gated by `ScopeProvider`
- HackerOne `ReportProvider` / `ScopeProvider` implementations
- A verification engine that promotes potential → verified only with evidence

Phase 2 should not need to rewrite language detection, AI selection, or the
static-analysis engine's file loop.
