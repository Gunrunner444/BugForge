# Security Research Agent

The **SecurityResearchAgent** is a planner and research assistant.
It is **not** the scope authority, **not** the final vulnerability verifier,
**not** the report approver, and **not** an unrestricted autonomous hacker.

Deterministic BugForge controls remain authoritative:

- `ScopeGuard` decides whether a target is in scope.
- `SafetyController` enforces request limits, methods, and forbidden activity.
- Finding verification still requires independent observational/executable evidence.
- HackerOne report approval and submission still require a human operator token.
- Tool risk comes from `ToolSpec` metadata, never from the model guessing a name.

## Status

| Area | State |
|---|---|
| Planner / structured tool calls | **implemented** |
| HTTP, source, evidence, proxy tools | **executable** (lab + live with scope) |
| Browser (`PlaywrightBrowserAdapter`) | **executable** when Playwright is installed; otherwise **unavailable** (not a fake navigation) |
| ZAP / Nuclei | **executable** when the binary is present; otherwise **results-ingestible** / **unavailable**. Authorization is never treated as a scan result |
| Fuzzing / API tests / reproduction | **executable** through `FuzzingEngine`, `APITestRunner`, `ReproductionEngine` |
| Live HackerOne sessions | **live-capable**, **human approval required**, blocked unless persisted structured scope exists |
| Fully autonomous live hacking | **not implemented** (by design) |

## Loop

Observe → Analyze → Hypothesize → Plan → Request tool → Authorization →
Execute → Collect evidence → Analyze result → Update hypothesis → Repeat →
Reproduce → Verify (human/deterministic) → Human review

Session states include `CREATED`, `RECON`, `ANALYZING`, `HYPOTHESIS_CREATED`,
`PLAN_READY`, `WAITING_FOR_APPROVAL`, `EXECUTING`, `OBSERVING`, `CORRELATING`,
`REPRODUCING`, plus explicit termination reasons:

`COMPLETED_SUCCESS`, `COMPLETED_NO_FINDINGS`, `MAX_ITERATIONS`,
`BUDGET_EXHAUSTED`, `USER_STOPPED`, `USER_PAUSED`, `FAILED`, `INCONCLUSIVE`.

## Cursor-controlled mode

`controller=cursor` means the Cursor model is the planner. BugForge stores
`provider=cursor_external` and does not call `MockLLMProvider`, OpenAI,
Anthropic, local, or MLX providers for that session. `POST .../step` is
rejected. Cursor submits decisions to `POST .../decision`, and BugForge
still authorizes every tool. See [cursor-control.md](cursor-control.md).
A selected model name such as `grok-4.7` is only the Cursor-controlled model
label. BugForge does not call Grok or xAI and does not store a Grok API key.
`exploratory_test` is an additional lab-only tool. The model proposes a test;
BugForge validates it, runs it in Docker with the network off, and records
evidence. A Foundry test is copied into a disposable project under the sandbox
output mount. The source repository is mounted read-only and is not the forge
root. Generated-test failure is not verification, and `COMPILATION_FAILED` is
a toolchain failure rather than a product bug. The Docker result uses
`provenance=sandbox_execution`, which cannot verify a finding or mark code safe.
Attempts are stored on the session and restored with it. Replay uses the exact
test bytes, or it is refused when those bytes were not kept. The model still cannot
supply the command, Docker flags, Foundry flags, or network access. The generic
identical-call guard does not classify exploratory retries; the exploratory
engine does. Live smart-contract testing requires an explicit target manifest
and stays off by default.

## Local lab vs live HackerOne

**Local lab** uses the same tool APIs against loopback fixtures
(`tests/fixtures/lab_app`). Lab permissions never apply to live HackerOne
projects.

**Live HackerOne** requires:

1. A synchronized structured scope for the session's program handle.
   Empty `ProgramScope` is refused (`LIVE_SCOPE_MISSING`).
2. Explicit operator `ENABLE_ACTIVE_TESTING` (the AI cannot grant it).
3. Tool-specific approvals (`START_LIVE_SCAN`, `ENABLE_FUZZING`,
   `HIGH_RISK_SCANNER`, `SEND_POC_REQUEST`) where `ToolSpec` requires them.
4. Conservative limits, ScopeGuard + SafetyController on every tool action.

There is no fully autonomous HackerOne mode.

## Models

Qwen3.6-35B-A3B (MLX, default 8-bit) can plan with thinking enabled for complex
reasoning and disabled for simple classification. Thinking traces are never
evidence and never report content. The model receives full tool JSON schemas
generated from `ToolSpec`, not bare names. Planner output is validated as
untrusted structured input (`PlannerOutput`).

## Persistence, restore, and budgets

Research sessions persist project, target, program, state, model configuration,
hypotheses, tool calls, approvals, evidence graph nodes/edges, privilege
snapshots, findings, timestamps, and errors. Exploratory attempts are stored
in `research_exploratory_attempts` and restored on reconstruct, including the
hashes used for dedup, parent checks, replay, and flaky history. A row records
`replayable` separately from the test hash. Secrets, provider credentials, and
the process environment are never stored. If redaction would change the test,
the stored test is empty and replay is refused.

`GET /security-agent/sessions/{id}` reconstructs the agent from the database
after restart and requires the local operator token. Restored privileges are
intersected with the current program scope: weaker current authorization wins.
Stale active-testing approvals are not revived. Provider/model configuration
is restored from the snapshot without API credentials.

Phase 8 sits `AdvancedResearchOrchestrator` above the agent. It selects a
research strategy, explains the next active action, compares isolated
identities A/B, and never creates a second execution pipeline. Replay uses
recorded results with **no live network**. Research memory stores sanitized
observations only. Live HackerOne defaults: dry-run, scanners/fuzz disabled,
human approval for higher-risk actions. The AI cannot change scope, enable
active testing, grant approval, increase total budget, verify a finding, or
submit a report.

Phase 9 adds a researcher workbench (dashboard, timeline, next-action review,
identity/evidence explorers) and hardens identity secret handling, replay
executor restoration, checkpoint revalidation, and deterministic export.
Mutating session endpoints authenticate the operator token **and** check
that the token identity owns the session. See [research-workbench.md](research-workbench.md),
[identity-testing.md](identity-testing.md), and
[evidence-workflow.md](evidence-workflow.md).

Every session has a budget loaded from settings (`max_tokens`,
`max_scan_seconds`, tool/request/browser/fuzz/iteration caps). The AI may
*request* more budget but cannot grant it. Provider token usage is consumed
when the backend reports it.

## Human override

At any point a researcher can pause, stop, reject an action, change limits,
disable a tool, or reject a finding. Pause/stop set a cancellation flag that
in-flight tool executors check. Terminal sessions (`USER_STOPPED`,
`COMPLETED_*`, `FAILED`) do not resume automatically.

See [agent-tools.md](agent-tools.md) and [agent-safety.md](agent-safety.md).
