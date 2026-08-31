# BugForge

**AI-powered software debugging, testing, and automated code repair.**

BugForge analyzes software repositories, identifies potential bugs, runs tests, reasons about root causes, proposes patches, and verifies whether they actually fix the problem without introducing regressions. Every conclusion is backed by evidence, never just an LLM's assertion.

---

## Architecture

```
BugForge/
├── backend/          Python 3.12 · FastAPI · SQLAlchemy · PostgreSQL
│   ├── app/
│   │   ├── analyzers/   Repository walker, language detector, Python AST parser
│   │   ├── api/         Versioned REST API (v1)
│   │   ├── models/      SQLAlchemy ORM models
│   │   ├── repositories/ Database access layer
│   │   ├── schemas/     Pydantic v2 request/response schemas
│   │   └── services/    Business logic, analysis orchestration
│   ├── alembic/      Database migrations
│   └── tests/        pytest + pytest-asyncio (51 tests)
├── frontend/         Next.js 14 · TypeScript · Tailwind CSS
│   └── src/app/      App Router pages (projects list, detail, analysis results)
├── examples/
│   └── sample_python_project/   Intentionally buggy Python project (8 known failures)
└── docker-compose.yml
```

## Phase Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Repository Analyzer | ✅ Complete & tested |
| 2 | Test Runner | Planned |
| 3 | Static Analysis | Planned |
| 4 | AI Debugging Engine | Planned |
| 5 | Automatic Test Generation | Planned |
| 6 | Bug Reproduction | Planned |
| 7 | Automated Repair | Planned |
| 8 | GitHub Integration | Planned |

## Quick Start

### Prerequisites

- Docker & Docker Compose
- (Optional, for local dev) Python 3.12+, Node.js 20+

### With Docker Compose

```bash
# 1. Copy and configure environment
cp .env.example .env

# 2. Start everything (PostgreSQL + backend + frontend)
docker-compose up --build

# API:      http://localhost:8000
# Docs:     http://localhost:8000/docs
# Frontend: http://localhost:3000
```

### Local Development (backend)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Start PostgreSQL first (or point DATABASE_URL at your instance)
# Then run migrations
DATABASE_URL=postgresql+asyncpg://bugforge:bugforge_dev@localhost:5432/bugforge \
  alembic upgrade head

# Start the API server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Local Development (frontend)

```bash
cd frontend
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
# → http://localhost:3000
```

## Running Tests

```bash
cd backend
source .venv/bin/activate
pytest tests/ -v          # All 51 tests (uses in-memory SQLite, no Postgres needed)
pytest tests/ --cov=app   # With coverage
```

### Sample project (known failures)

```bash
cd examples/sample_python_project
python3 -m pytest tests/ -v
# 29 passing, 8 failing (by design — these are the bugs BugForge will diagnose)
```

## API Reference

Full OpenAPI docs: `http://localhost:8000/docs`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/api/v1/projects` | Create a project |
| `GET` | `/api/v1/projects` | List projects |
| `GET` | `/api/v1/projects/{id}` | Get project |
| `DELETE` | `/api/v1/projects/{id}` | Delete project |
| `POST` | `/api/v1/projects/{id}/analyze` | Trigger analysis (async, returns 202) |
| `GET` | `/api/v1/projects/{id}/analyses` | List analyses for a project |
| `GET` | `/api/v1/analyses/{id}` | Get analysis status + summary |
| `GET` | `/api/v1/analyses/{id}/files` | Paginated file list |
| `GET` | `/api/v1/analyses/{id}/entities` | Paginated code entities |
| `GET` | `/api/v1/analyses/{id}/imports` | Paginated import records |

## What Phase 1 Delivers

- Walk a local repository, skip build artifacts, caches, and VCS directories
- Detect programming languages by file extension
- Detect common frameworks (Django, Flask, FastAPI, pytest, SQLAlchemy, Next.js, …)
- Parse Python files with the built-in `ast` module
- Extract functions, async functions, classes, methods, and async methods
- Extract docstrings, decorators, parameters with type annotations and defaults
- Classify imports as `stdlib` / `third_party` / `relative` / `local`
- Identify source vs test vs config vs other files
- Store everything in PostgreSQL via SQLAlchemy async + Alembic migrations
- REST API with pagination, structured JSON responses, and OpenAPI docs
- Next.js frontend with project management, analysis triggering, and result browsing

## Security Notes

- Never execute repository code on the host — all code execution will go through a Docker sandbox (Phase 2+)
- API keys are never stored in source code; use `.env` or environment variables
- See [SECURITY.md](SECURITY.md) for the responsible disclosure policy

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

