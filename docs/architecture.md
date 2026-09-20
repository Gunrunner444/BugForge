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

## Plugin catalog and adapter registration

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

`AdapterRegistry` identifies adapters by a normalized (strip + lowercase)
canonical id plus optional aliases. Registration **rejects**:

- duplicate canonical ids
- a canonical id that is already an alias of another adapter
- an alias that matches another adapter's canonical id
- an alias that is already claimed by another adapter

Aliases are never overwritten silently. Use `replace=True` to swap an
adapter you own. `unregister` drops the factory and all of its aliases.
Unknown lookups raise `AdapterNotFoundError` and list known ids.

`LanguageRegistry.register_adapter(..., replace=True)` validates the new
adapter first, removes the previous adapter's extension mappings, then
installs the new ones. If installation fails, the previous mappings are
restored. An extension belonging to the old adapter never remains after a
successful replacement.

## Language-neutral parse contract

`LanguageAdapter.parse_file()` returns `app.domain.source.LanguageParseResult`,
a language-neutral contract with:

- file path and language id
- line count and parse errors
- generic imports (`ParsedImport`) and entities (`ParsedEntity`)

`RepoAnalyzer.FileAnalysisResult.parse_result` uses the same type. Core
orchestration must not import `app.analyzers.python.parser.ParseResult`.

Python keeps a richer `ParseResult` subclass for AST-specific work. That
subclass satisfies the neutral contract, so `PythonAdapter.parse_file()`
can return it.

Static-analysis rule overrides go through `LanguageAdapter.with_static_rules()`.
`StaticAnalysisEngine` does not import `PythonAdapter` or branch on language
name. Languages that cannot apply a given override keep their built-in rules.

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
        ...  # real Ruby parser returning LanguageParseResult

    def analyze_file(self, file_path: Path, source: str):
        ...  # real Ruby rules

    def with_static_rules(self, rules):
        ...  # optional rule-override support

# Either replace the detection-only adapter in bootstrap, or:
get_plugin_catalog().languages.register_adapter(RubyAnalyzerAdapter(), replace=True)
```

Unrelated modules (AI factory, Docker executor, GitHub delivery) do not change.

## AI abstraction

`LLMProvider` (aliased as `AIProvider`) is the interface. Debugging methods
(`analyze`, `generate_tests`, `generate_structured`, `generate_patch`) remain
for compatibility.

Generic, provider-neutral entry points:

- `complete(CompletionRequest) -> CompletionResponse` — chat / structured
  generation / later evidence analysis and report drafting
- `capabilities() -> AICapabilities` — per-backend features such as
  structured output, tool calls, thinking, max context, and output token
  limits

Not every provider has the same capabilities. Callers must consult
`capabilities()` instead of assuming an OpenAI-shaped backend. Tool calling
and model thinking are **interface-ready but not implemented**.

| Id | Class | Notes |
|---|---|---|
| `mock` | `MockLLMProvider` | Deterministic, no network |
| `openai` | `OpenAIProvider` | OpenAI chat completions |
| `anthropic` | `AnthropicProvider` | Anthropic Messages API |
| `local` | `LocalAIProvider` | OpenAI-compatible local HTTP |
| `ollama` / `openai_compatible` | aliases of `local` | Backwards compatible |

`create_provider(settings)` and `get_provider()` resolve through the catalog.
Repository content is still wrapped in `[REPOSITORY_DATA]` by `PromptBuilder`.

`LocalAIProvider.is_available()` probes the configured endpoint. It is not
unconditionally true. `health()` remains the richer diagnostic and never
includes API keys. `LocalAIProvider(backend="mlx")` is reserved for a later
Qwen/MLX phase and raises `AdapterNotImplementedError` today.

### Adding an AI provider

1. Subclass `LLMProvider` (implement debugging methods; override `complete`
   / `capabilities` when the backend differs).
2. Register a factory in `register_builtin_adapters`.
3. Add the id to `Settings` `_VALID_AI_PROVIDERS` if it should be selectable via `AI_PROVIDER`.

## Evidence provenance and verification invariant

An AI hypothesis never becomes a verified finding by itself.

`Evidence.provenance` (`EvidenceProvenance`) records where an item came from:

| Provenance | Typical kind | Can verify? |
|---|---|---|
| `ai_hypothesis` | `ai_analysis` | **No** |
| `static_analysis` | `static_analysis` | **No** |
| `source_observation` | `source_code`, generated tests | **No** |
| `execution` | test failures, logs | Yes |
| `reproduction` | reproduction engine | Yes |
| `browser_observation` | browser / screenshot | Yes |
| `http_observation` | proxy / HTTP | Yes |
| `scanner_observation` | scanner | Yes |
| `api_test` | API test | Yes |
| `fuzzing_result` | fuzzer | Yes |

AI text is forced to `ai_hypothesis` even if a caller tries to label it as
execution. Evidence records are frozen so provenance cannot be rewritten.

`SecurityFinding` is frozen. Status is not a mutable field. Use constructors
and transitions:

- `potential` / `from_hypothesis` → `potential`
- `verify(evidence)` / `verified(evidence)` → `verified` only when the bundle
  contains at least one verifying provenance
- `reject` → `rejected`
- `with_review` → human review state without changing verification

This sequence is rejected:

```
AI claim → Evidence.from_ai(...) → SecurityFinding.verified(...)
```

Static hints and source excerpts are also insufficient. Verification is a
state transition backed by independent observational or executable evidence.

## Scope separation

`is_in_scope(target)` means the host is on the allow-list (optional method
filter). It does **not** authorize active testing.

| Check | Meaning |
|---|---|
| `is_in_scope` | Host (and optional method) is allowed |
| `is_method_permitted` | HTTP method is allowed |
| `is_active_testing_permitted` | In scope **and** `allow_active_testing` |
| `rate_limit_per_minute` | Reserved for a later richer engine |

`ManualScopeProvider` uses operator-supplied allow/deny lists. An empty
allow-list denies every target. Remote HackerOne scope retrieval is not
implemented.

Browser `navigate`, fuzzer `fuzz`, and security-tool `active_scan` call
`require_active_testing` before any implementation hook. Proxy
`fetch_exchanges` is passive: it filters captured traffic to in-scope hosts
and does not send requests. Implementations override `_navigate`,
`_fuzz`, `_fetch_captured_exchanges`, or `_active_scan` so they cannot skip
the public authorization wrapper by accident.

## Reports

`LocalReportProvider.render()` writes a local markdown document that
distinguishes potential, verified, and rejected findings and records human
review state. `submitted_remotely` is always false. `submit()` raises
`AdapterNotImplementedError` — local rendering is not remote submission.
HackerOne upload is reserved for a later phase.

## Security tools

`SecurityToolAdapter` is the future scanner boundary (`collect_passive_evidence`,
`active_scan`). Burp, ZAP, and Nuclei are **not** implemented. Register a real
adapter when the tool integration exists; do not ship empty classes that claim
to scan.

## Configuration

Existing `AI_PROVIDER` / `AI_MODEL` / `AI_BASE_URL` settings are unchanged.
New optional setting:

| Variable | Default | Meaning |
|---|---|---|
| `LANGUAGE_ANALYZERS` | empty | Comma-separated analyzer ids. Empty = every adapter that implements `STATIC_ANALYSIS` (currently `python`). Unknown ids or detection-only languages raise a useful error. |

Do not set browser/proxy/fuzzer providers until those adapters exist.

## What remains deferred to Phase 2

Phase 1 does **not** implement:

- Real analyzers for detection-only languages
- Qwen/MLX local backend, thinking-mode execution, or tool calling
- Burp / ZAP / Nuclei (or any live scanner)
- Browser driving, exploitation, or live navigation
- Live fuzzing against external targets
- HackerOne API scope sync or report submission
- Rate-limit enforcement and a full HackerOne-compatible scope engine
- A security agent that promotes findings beyond the domain invariant

Phase 2 should not need to rewrite language detection, AI selection, the
static-analysis engine's file loop, or the verification/scope contracts.
