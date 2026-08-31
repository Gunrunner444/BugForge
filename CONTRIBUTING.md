# Contributing to BugForge

Thank you for considering contributing! Please read these guidelines before opening issues or pull requests.

## Development Setup

See [README.md](README.md) for installation and local development instructions.

## Code Standards

- **Python**: type hints throughout, formatted with `ruff`, checked with `mypy`
- **TypeScript**: strict mode, no `any` unless unavoidable
- Every significant feature must include tests
- Business logic belongs in services/analyzers, not in API route handlers
- Do not add fake/mock implementations; prefer a smaller working feature

## Pull Request Process

1. Fork the repository and create a branch from `main`
2. Make your changes with tests
3. Ensure `pytest tests/ -v` passes (backend)
4. Ensure `npm run type-check && npm run lint` passes (frontend)
5. Submit a PR with a clear description of the change and the motivation

## Reporting Bugs

Open a GitHub Issue with:
- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment (OS, Python version, etc.)

## Security Vulnerabilities

Please do **not** file public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md).
