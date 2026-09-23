# BugForge

**Evidence-first AI software debugging, automated test generation, and automated code repair.**

BugForge analyzes software repositories, runs tests, performs static analysis, collects evidence, uses AI to reason about bugs, generates reproducers, and proposes verified repair patches. Every AI conclusion is labeled as a hypothesis — never as a confirmed fact — until executable evidence supports it.

---

## Phase Status

| Version | Description | Status |
|---|---|---|
| v0.1.0 | Repository Analyzer | ✅ Complete |
| v0.2.0 | Test Runner | ✅ Complete |
| v0.3.0 | Static Analysis | ✅ Complete |
| v0.4.0 | AI Debugging Engine | ✅ Complete |
| v0.5.0 | Automatic Test Generation | ✅ Complete |
| v0.6.0 | Bug Reproduction Engine | ✅ Complete |
| v0.7.0 | Repair Engine | ✅ Complete |
| v0.8.0 | Patch Verification | ✅ Complete |
| v0.9.0 | GitHub Integration | ✅ Complete |
| v1.0.0 | Full AI Debugging Platform | ✅ Complete |
| v1.1.0 | Autonomous Discovery | ✅ Complete |
| Phase 1 | Adapter foundation (languages, AI, security tooling) | ✅ Complete |
| Phase 2 | Local AI + multi-language security analysis | ✅ Complete |
| Phase 3 | Authorized security testing infrastructure | ✅ Implemented (execution + hardening in Phase 4) |
| Phase 4 | HackerOne program integration | ✅ Implemented (gated submission; mock-tested) |
| Phase 5 | HackerOne production readiness | ✅ Implemented (persistent state, numeric weaknesses, operator authorization) |
| Phase 6 | Guided AI security research agent | ✅ Implemented (planner; Phase 7 executes authorized tools) |
| Phase 7 | Production security agent execution + evidence-driven verification | ✅ Implemented (lab-capable; live-capable with human approval; not unrestricted hacking) |
| Phase 8 | Advanced security research + verification intelligence | ✅ Implemented (orchestrator, identities, replay, memory; AI remains advisory) |
| Phase 9 | Security research workbench + end-to-end validation | ✅ Implemented (hardening + researcher workflow; live remains human-controlled) |
| Phase 10 | Native polyglot analysis parity (Tree-sitter + scope-aware taint) | ✅ Implemented |
| Phase 11 | Semantic dataflow & polyglot quality parity | ✅ Implemented |
| Phase 12 | Deep semantic analysis, cross-file flow, and repository validation | ✅ Implemented |
| Phase 13 | Repository semantic graph (unique symbols, aliases, path maps) | ✅ Implemented |
| Phase 14 | Bounded field-sensitive dataflow (constant fields, keys, indexes) | ✅ Implemented |
| Phase 15 | Framework-aware sources, sinks, and syntactic routes | ✅ Implemented |
| Phase 16 | Evidence correlation without automatic verification | ✅ Implemented |
| Phase 17 | In-memory incremental parse cache with clean-scan equivalence | ✅ Implemented |
| Phase 18 | Stable finding identity, explanations, and duplicate suppression | ✅ Implemented |
| Phase 19 | Go, Java, and Kotlin local interprocedural imports | ✅ Implemented |
| Phase 20 | Adversarial semantic checks and shadowed-builtin handling | ✅ Implemented |
| Phase 21 | Evidence correlation and finding lifecycle integration | ✅ Implemented |
| Phase 22 | Production security lifecycle and evidence integrity | ✅ Implemented |
| Phase 23 | Verification authority and evidence provenance | ✅ Implemented |
| Phase 24 | Security coverage, precision, and verification trust | ✅ Implemented |
| Phase 25 | Verification binding and adversarial detection | ✅ Implemented |
| Phase 26 | Polyglot security coverage and semantic target binding | ✅ Implemented |
| Phase 27 | Multi-engine discovery and Solidity analysis | ✅ Implemented |
| Phase 28 | Discovery hardening and Solidity deep analysis | ✅ Implemented |
| Phase 29 | CFG-aware Solidity analysis, runtime bridges, and protected CI | ✅ Implemented |

See [docs/architecture.md](docs/architecture.md) for the adapter/plugin architecture and how to add languages, AI providers, and future security tools.

---

## Architecture

BugForge is organized around **adapters registered in a plugin catalog**. Core
orchestration looks up languages, AI backends, and future security tools by id
instead of hard-coded conditionals. Python keeps its CPython AST quality
analysis. Other programming languages parse through Tree-sitter into the same
`SyntaxGraph`. Taint is flow-sensitive at the use site (not path-sensitive),
with bounded same-file and cross-file propagation when a callee, re-export,
default export, or method resolves uniquely. Constant object fields, dict keys,
and list indexes are separate symbols up to a configured depth. Unknown calls,
dynamic keys, partial callees, and profile fallback are not treated as dataflow.
Every full-analysis language has a syntax-aware **code quality** catalog,
separate from **security** observations. Parser fallback is labeled
`PROFILE_FALLBACK` and never advertised as AST. C# and Shell are full analysis
languages. HTML, CSS/SCSS, and SQL have specialized analysis. Solidity has its own
security and quality catalogs. Foundry, Slither, Echidna, Medusa, Halmos, and
Wake are optional executables and do not invent results when they are absent.
R, Scala, Dart, Lua, and Elixir remain detection-only. See
[docs/polyglot-analysis.md](docs/polyglot-analysis.md),
[docs/language-capability-matrix.md](docs/language-capability-matrix.md),
[docs/phase12-semantic-analysis.md](docs/phase12-semantic-analysis.md),
[docs/phase13-repository-semantic-graph.md](docs/phase13-repository-semantic-graph.md), and
[docs/phase14-field-sensitive-dataflow.md](docs/phase14-field-sensitive-dataflow.md), and
[docs/phase15-framework-aware-analysis.md](docs/phase15-framework-aware-analysis.md), and
[docs/phase16-evidence-correlation.md](docs/phase16-evidence-correlation.md), and
[docs/phase17-incremental-analysis.md](docs/phase17-incremental-analysis.md), and
[docs/phase18-finding-intelligence.md](docs/phase18-finding-intelligence.md), and
[docs/phase19-polyglot-interprocedural.md](docs/phase19-polyglot-interprocedural.md), and
[docs/phase20-adversarial-validation.md](docs/phase20-adversarial-validation.md), and
[docs/phase21-evidence-lifecycle.md](docs/phase21-evidence-lifecycle.md), and
[docs/phase22-production-security-lifecycle.md](docs/phase22-production-security-lifecycle.md), and
[docs/phase23-verification-authority.md](docs/phase23-verification-authority.md), and
[docs/phase24-security-coverage-precision.md](docs/phase24-security-coverage-precision.md), and
[docs/phase25-verification-binding-adversarial.md](docs/phase25-verification-binding-adversarial.md), and
[docs/phase26-polyglot-security-coverage.md](docs/phase26-polyglot-security-coverage.md), and
[docs/phase27-multi-engine-solidity.md](docs/phase27-multi-engine-solidity.md), and
[docs/phase28-solidity-deep-analysis.md](docs/phase28-solidity-deep-analysis.md).

Phase 2 adds:

- **Shared syntax graphs** (CPython AST for Python, Tree-sitter for other
  analysis languages, labeled profile fallback only if a grammar is missing).
- **Framework registry** (Django, Flask, FastAPI, Express, Next.js, NestJS, Rails, …).
- **Security rule engine** with taint-aware source→sink hypotheses.
- **Local MLX provider** at `http://127.0.0.1:8080/v1`, configurable model
  (default `Qwen3.6-35B-A3B-8bit`), thinking enabled/disabled.
- **Context selection** so repositories are not dumped into the model.
- **Potential / corroborated** findings only — never verified from static or AI.

Phase 3 adds **authorized, scope-aware security testing**. Every active
operation must pass `ScopeGuard` → `SafetyController` → `RateLimiter`.
External scanners run only inside a BugForge execution envelope. Phase 4
adds HackerOne program lookup, structured scope sync, and a human-gated
report workflow with dry-run (no report created) before optional real
submission. Phase 5 persists that HackerOne state, binds approval to
payload hashes, and uses program-specific numeric weakness IDs. Phase 6
adds a guided `SecurityResearchAgent` that plans tool actions. Phase 7
executes those tools through the existing adapters, persists the evidence
graph, and restores sessions after restart. Phase 8 adds an advanced
research orchestrator, two-identity authorization comparison, replay,
research memory, checkpoints, and evidence export. Phase 9 hardens that
stack (identity secret references, authorization oracles, replay restoration,
checkpoint revalidation, deterministic export) and adds a researcher
workbench. Deterministic BugForge
controls remain authoritative. Tools that lack a binary (ZAP, Nuclei,
Playwright) report `UNAVAILABLE` or ingest-only results — they are not
stubs pretending to have scanned. Live HackerOne sessions default to dry-run
with scanners and fuzzing disabled.

Cursor-controlled mode is a separate controller. The Cursor model plans the
research. BugForge does not call its own language model in that mode, and
ScopeGuard, SafetyController, RateLimiter, and human approval stay in force.
See [docs/cursor-control.md](docs/cursor-control.md).

Details: [docs/architecture.md](docs/architecture.md),
[docs/security-testing.md](docs/security-testing.md),
[docs/scope-model.md](docs/scope-model.md),
[docs/tool-integrations.md](docs/tool-integrations.md),
[docs/hackerone.md](docs/hackerone.md),
[docs/reporting.md](docs/reporting.md),
[docs/security-agent.md](docs/security-agent.md),
[docs/cursor-control.md](docs/cursor-control.md),
[docs/agent-tools.md](docs/agent-tools.md),
[docs/agent-safety.md](docs/agent-safety.md),
[docs/research-workbench.md](docs/research-workbench.md),
[docs/identity-testing.md](docs/identity-testing.md),
[docs/evidence-workflow.md](docs/evidence-workflow.md). Do not point this stack at
real-world targets without an operator-approved program scope.

```
Repository
  └─ Repository Analyzer (Phase 1)
       ├─ Language detection (30+ extensions)
       ├─ Framework detection
       ├─ Python AST parsing
       ├─ Code entity extraction
       └─ Import graph

  └─ Test Runner (Phase 2)
       ├─ pytest discovery & execution
       ├─ JSON report collection (pytest-json-report)
       ├─ LocalTestExecutor (dev/trusted repos)
       ├─ DockerTestExecutor (isolated containers)
       └─ ExecutorFactory (production guard — raises if Docker unavailable)

  └─ Static Analysis (Phase 3)
       ├─ StaticAnalysisEngine (extensible rule pipeline)
       ├─ Python AST rules (6 rules)
       └─ Finding persistence (repo-relative paths)

  └─ Evidence Layer
       ├─ Failing tests with tracebacks
       ├─ Static findings
       └─ Source file context

  └─ AI Debugging (Phase 4)
       ├─ LLMProvider abstraction (Mock / OpenAI / Anthropic / local)
       ├─ Generic complete() / capabilities() (security agents not implemented)
       ├─ ContextBuilder (minimum-context selection)
       ├─ PromptBuilder (prompt-injection defense)
       ├─ DebuggingSession persistence
       └─ Structured hypothesis output

  └─ Automatic Test Generation (Phase 5)
       ├─ TestGenerator (AI-based candidate generation)
       ├─ TestValidator (syntax + safety + import checks)
       ├─ Quality scorer
       ├─ Sandbox execution via TestExecutor
       └─ GeneratedTest persistence

  └─ Bug Reproduction Engine (Phase 6)
       ├─ ReproductionPlanner (AI-generated reproducers with prompt-injection defense)
       ├─ TestValidator (rejects dangerous imports and calls)
       ├─ Evidence-based classification (matches expected failure, not just exit code)
       ├─ Multiple attempts with reproducibility classification
       │    not_reproduced | inconclusive | intermittent | reproduced | consistently_reproduced
       ├─ Docker executor with repository mount (read-only)
       └─ BugReproductionSession / BugReproductionAttempt persistence

  └─ Automated Repair (Phase 7)
       ├─ PatchPlanner (AI-generated patches with prompt-injection defense)
       ├─ PatchValidator (path traversal + dangerous code checks)
       ├─ RepairWorkspace (disposable copy — NEVER modifies original repo)
       ├─ Pre-patch baseline (confirms bug reproduces in workspace)
       ├─ Patch application (unified diff)
       ├─ Post-patch verification (confirms bug no longer reproduces)
       ├─ Existing test suite regression check
       ├─ Composite scoring (bug_fixed 0.7 + no_regressions 0.3)
       ├─ Candidate ranking
       └─ RepairSession / PatchCandidate persistence

  └─ Patch Verification (Phase 8)
       ├─ Evidence-first verification pipeline
       ├─ Baseline + post-patch test execution with explicit status
       │    (success / timeout / environment_error / report_error / not_run)
       ├─ Static analysis with identity-based finding comparison
       │    (analyzer:category:file — stable across line-number shifts)
       ├─ Security validation (dangerous patterns, CI config modification)
       ├─ Strengthened decision logic — ALL stages must succeed for 'verified'
       ├─ Infrastructure failures → 'inconclusive', never 'verified'
       ├─ Execution metadata persistence (executor type, duration, status)
       └─ PatchVerification persistence with full evidence record

  └─ GitHub Integration (Phase 9)
       ├─ GitHubProvider / GitHubService abstraction
       ├─ Server-side token credential (GITHUB_TOKEN env var, never in DB)
       ├─ GitHubRepository — associates projects with GitHub repos (1:1)
       ├─ Verified-only delivery — unverified/rejected/inconclusive blocked
       ├─ Patch hash verification — delivered hash MUST match verified hash
       ├─ Git operations via subprocess with argument arrays (no shell interpolation)
       ├─ Branch creation (bugforge/fix/{candidate_id_short})
       ├─ Branch name sanitization (injection prevention)
       ├─ Final pre-push test verification
       ├─ Commit creation with sanitized, evidence-based message
       ├─ Push to delivery branch (default branch never modified)
       ├─ PR creation via GitHub REST API (httpx)
       ├─ Duplicate PR prevention
       ├─ Token sanitization from all error messages and logs
       ├─ Delivery idempotency (no duplicate active deliveries)
       ├─ Complete delivery record persistence (GitHubDelivery)
       └─ Delivery status separate from verification status
```

---

## Quick Start

### With Docker

```bash
cp .env.example .env
docker compose up --build
# API: http://localhost:8000/docs
# Frontend: http://localhost:3000
```

### Local development

```bash
# Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
DATABASE_URL=postgresql+asyncpg://bugforge:bugforge_dev@localhost:5432/bugforge \
  alembic upgrade head
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
```

---

## AI Configuration

Set in `.env` or environment variables:

| Variable | Default | Description |
|---|---|---|
| `AI_PROVIDER` | `mock` | `mock` / `openai` / `anthropic` / `ollama` / `openai_compatible` / `local` / `mlx` |
| `AI_MODEL` | `gpt-4o-mini` | Model name (override; for MLX prefer `MLX_MODEL`) |
| `AI_API_KEY` | *(empty)* | API key — never commit this. Not required for MLX |
| `AI_BASE_URL` | *(empty)* | Override; MLX defaults to `http://127.0.0.1:8080/v1` |
| `MLX_BASE_URL` | `http://127.0.0.1:8080/v1` | Local MLX OpenAI-compatible endpoint |
| `MLX_MODEL` | `Qwen3.6-35B-A3B-8bit` | Configurable local model id |
| `AI_THINKING_ENABLED` | `false` | Request model thinking traces (stripped from the answer) |
| `AI_NATIVE_JSON_MODE` | `false` | Send OpenAI `response_format` (off by default for local models) |
| `AI_MAX_CONTEXT_TOKENS` | `8192` | Practical context budget for local models |
| `AI_TEMPERATURE` | `0.1` | Sampling temperature |
| `AI_TIMEOUT_SECONDS` | `60` | Request timeout |
| `LANGUAGE_ANALYZERS` | *(empty)* | Comma-separated quality-analyzer language ids (`STATIC_ANALYSIS`). Empty = every adapter that implements code-quality analysis (Python and all full-analysis languages). Detection-only languages cannot be listed. |

The **mock provider** is always safe for development — no API key required.

---

## Running Tests

```bash
cd backend
pytest tests/ -v          # in-memory SQLite (no Postgres needed)
pytest tests/ --cov=app   # With coverage
```

### Sample project (known failures)

```bash
cd examples/sample_python_project
python3 -m pytest tests/ -v
# 29 passing, 8 failing by design
```

---

## API Reference

Full docs: `http://localhost:8000/docs`

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/projects` | Create project |
| GET | `/api/v1/projects/{id}` | Get project |
| POST | `/api/v1/projects/{id}/analyze` | Trigger analysis (202) |
| POST | `/api/v1/projects/{id}/tests/run` | Run tests (202) |
| GET | `/api/v1/analyses/{id}/findings` | Static findings |
| POST | `/api/v1/projects/{id}/debug` | Start AI debugging (202) |
| GET | `/api/v1/debugging/{id}` | Debugging session + hypotheses |
| POST | `/api/v1/projects/{id}/test-generation` | Generate tests (202) |
| GET | `/api/v1/ai/status` | AI provider, model, local/cloud, thinking, analyzers |
| GET | `/api/v1/security/status` | Language analyzers and security rules |
| GET | `/api/v1/security/findings` | Potential/corroborated security findings |

---

## Security Model

- **No code executed on the host** from untrusted repositories. All test execution uses `DockerTestExecutor` when Docker is available, or `LocalTestExecutor` only for trusted development repos.
- **Prompt injection defense**: All repository content (source, comments, test names) is wrapped in `[REPOSITORY_DATA]` tags and labeled as untrusted data that cannot override system instructions.
- **AI keys are never logged**, committed, or exposed to the frontend.
- **Path traversal prevention**: All file paths validated as repo-relative using `Path.is_relative_to()`.
- **Generated tests are never applied** to the repository automatically — they are candidates for human review.

### Docker sandbox limitations

- Network disabled by default during execution
- Read-only repository mount
- CPU and memory limits enforced
- No Docker socket mounted (containers cannot spawn sibling containers)
- Seccomp/AppArmor profiles not applied beyond Docker defaults

---

## Roadmap

There are two roadmaps. Do not mix them.

### Original debugging roadmap (complete)

Repository analysis, test runner, static analysis, AI debugging, test
generation, reproduction, repair, verification, GitHub integration, and
autonomous discovery. That work is the **debugging** product.

### Security testing roadmap

| Phase | What it actually does |
|---|---|
| 1 | Adapter contracts and plugin catalog |
| 2 | Local AI + multi-language **static** security analysis (potential/corroborated only) |
| 3 | Authorized testing: ScopeGuard, SafetyController, lab vs live, gated HTTP, optional scanner **execution** when binaries exist |
| 4 | HackerOne Hacker API: program lookup, structured scope sync, finding→draft, human review, dry-run, gated real submission |
| 5 | Persistent HackerOne state, numeric weaknesses, operator authorization, payload-bound approvals |
| 6 | Guided `SecurityResearchAgent` planner. The AI cannot verify, approve, or submit |
| 7 | Production tool execution through existing adapters, persisted evidence graph, session restore. ZAP/Nuclei/Playwright are live-capable **only when their binaries are present** |
| 8 | Advanced research orchestrator, two-identity testing, replay, memory, checkpoints, evidence export. Live mode remains dry-run and human-controlled |

In-memory `RateLimiter` is **per process**. Multiple API workers do not share
a global per-target budget; production live mode should run one worker or
place a shared limiter in front of BugForge.

Deliberately **not** automatic:

- Unrestricted autonomous scanning or a "hack everything" action
- Treating AI, scanner plans, or scanner alerts as verified vulnerabilities
- Driving the Burp GUI or treating ZAP/Nuclei's own scope as authoritative
- Submitting HackerOne reports without HUMAN_APPROVED
- Using HackerOne Report Assistant output as BugForge verified evidence

Use Local Lab mode against loopback fixtures. Do not use this against live
external targets until a human has configured structured scope, enabled
active testing, and accepted the conservative rate limits.

---

## License

MIT
