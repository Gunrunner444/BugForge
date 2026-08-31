# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in BugForge, please report it privately.

**Do not file a public GitHub Issue.**

Send a description of the issue to the maintainers by opening a private security advisory on GitHub, or email the project owner directly.

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

We will acknowledge receipt within 48 hours and aim to release a fix within 14 days for critical issues.

## Security Considerations

BugForge executes user-supplied code as part of its debugging workflow. The following mitigations are in place or planned:

- **Phase 1**: No code execution on the host — analysis is read-only AST parsing
- **Phase 2+**: All test execution runs inside ephemeral Docker containers with CPU, memory, and filesystem limits
- API keys are never stored in source code; use environment variables or a secrets manager
- The frontend never receives or exposes backend credentials
