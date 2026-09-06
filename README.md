# BugForge

**Evidence-first AI software debugging and automated test generation.**

BugForge analyzes software repositories, runs tests, performs static analysis, collects evidence, and uses AI to reason about bugs and generate new tests. Every AI conclusion is labeled as a hypothesis — never as a confirmed fact — until executable evidence supports it.

---

## Phase Status

| Phase | Description | Status |
|---|---|---|
| 1 | Repository Analyzer | ✅ Complete |
| 2 | Test Runner | ✅ Complete |
| 3 | Static Analysis | ✅ Complete |
| 4 | AI Debugging Engine | ✅ Complete |
| 5 | Automatic Test Generation | ✅ Complete |
| 6 | Bug Reproduction Engine | 🚧 In progress |
| 7 | Automated Repair | Planned |
| 8 | GitHub Integration | Planned |

---

## Architecture

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
       └─ ExecutorFactory (selects best available)

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
       ├─ TestValidator (syntax + safety check)
       ├─ Quality scorer
       ├─ Sandbox execution via TestExecutor
       └─ GeneratedTest persistence
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
| `AI_PROVIDER` | `mock` | `mock` / `openai` / `anthropic` |
| `AI_MODEL` | `gpt-4o-mini` | Model name |
| `AI_API_KEY` | *(empty)* | API key — never commit this |
| `AI_TEMPERATURE` | `0.1` | Sampling temperature |
| `AI_TIMEOUT_SECONDS` | `60` | Request timeout |

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
