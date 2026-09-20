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

See [docs/architecture.md](docs/architecture.md) for the adapter/plugin architecture and how to add languages, AI providers, and future security tools.

---

## Architecture

BugForge is organized around **adapters registered in a plugin catalog**. Core
orchestration looks up languages, AI backends, and future security tools by id
instead of hard-coded conditionals. Python analysis and the existing AI
providers run through that catalog today; other languages are detected but not
yet analyzed. Details: [docs/architecture.md](docs/architecture.md).

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
       ├─ LLMProvider abstraction (Mock / OpenAI / Anthropic)
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
| `AI_PROVIDER` | `mock` | `mock` / `openai` / `anthropic` / `ollama` / `openai_compatible` / `local` |
| `AI_MODEL` | `gpt-4o-mini` | Model name |
| `AI_API_KEY` | *(empty)* | API key — never commit this |
| `AI_TEMPERATURE` | `0.1` | Sampling temperature |
| `AI_TIMEOUT_SECONDS` | `60` | Request timeout |
| `LANGUAGE_ANALYZERS` | *(empty)* | Comma-separated analyzer ids. Empty = all analyzers that implement static analysis (currently `python`) |

The **mock provider** is always safe for development — no API key required.

---

## Running Tests

```bash
cd backend
pytest tests/ -v          # 130 tests, in-memory SQLite (no Postgres needed)
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
| GET | `/api/v1/test-generation/{id}/tests` | Generated test candidates |

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

- **Phase 6 — Bug Reproduction Engine**: Convert AI hypotheses into executable reproductions with multi-attempt verification
- **Phase 7 — Automated Repair**: Generate and verify patches in isolation
- **Phase 8 — GitHub Integration**: Analyze issues, open PRs with verified patches

---

## License

MIT
