# Security Research Agent

The Phase 6 **SecurityResearchAgent** is a planner and research assistant.
It is **not** the scope authority, **not** the final vulnerability verifier,
**not** the report approver, and **not** an unrestricted autonomous hacker.

Deterministic BugForge controls remain authoritative:

- `ScopeGuard` decides whether a target is in scope.
- `SafetyController` enforces request limits, methods, and forbidden activity.
- Finding verification still requires independent observational/executable evidence.
- HackerOne report approval and submission still require a human operator token.

## Loop

The agent loop is explicit and restartable:

Observe → Analyze → Hypothesize → Plan → Request tool → Authorization →
Execute → Collect evidence → Analyze result → Update hypothesis → Repeat →
Reproduce → Verify (human/deterministic) → Human review

States: `CREATED`, `RECON`, `ANALYZING`, `HYPOTHESIS_CREATED`, `PLAN_READY`,
`WAITING_FOR_APPROVAL`, `EXECUTING`, `OBSERVING`, `CORRELATING`,
`REPRODUCING`, `VERIFIED`, `REJECTED`, `PAUSED`, `FAILED`, `COMPLETED`.

## Local lab vs live HackerOne

**Local lab** uses the same tool APIs against loopback fixtures (OWASP Juice Shop
style apps and `tests/fixtures/lab_app`). Lab permissions never apply to live
HackerOne projects.

**Live HackerOne** requires structured scope, explicit active testing, conservative
limits, ScopeGuard + SafetyController on every tool action, human approval gates,
and final finding verification. There is no fully autonomous HackerOne mode.

## Models

Qwen3.6-35B-A3B (MLX, default 8-bit) can plan with thinking enabled for complex
reasoning and disabled for simple classification. Thinking traces are never
evidence and never report content. Structured tool calls are validated before
execution.

## Persistence and budgets

Research sessions persist project, target, program, state, model configuration,
hypotheses, tool calls, approvals, evidence links, findings, timestamps, and
errors. Secrets are never stored. Every session has a budget; the AI may
*request* more budget but cannot grant it.

## Human override

At any point a researcher can pause, stop, reject an action, change limits,
disable a tool, or reject a finding. The agent must respect those decisions.

See [agent-tools.md](agent-tools.md) and [agent-safety.md](agent-safety.md).
