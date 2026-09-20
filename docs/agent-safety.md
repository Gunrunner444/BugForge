# Agent safety

BugForge safety controls are authoritative. Model output cannot override them.

## Scope

Only deterministic scope logic may decide `AUTHORIZED` or `BLOCKED`. Hidden
scope rules are not placed in prompts. A research session is bound to **one**
program handle. Live sessions load that program's persisted structured scope
or they are refused. Program A never uses Program B's includes.

## Safety controller and approvals

Request limits, concurrency, tool restrictions, active-testing state, program
restrictions, and human approvals cannot be waived by the model. Unsafe
requests return a structured rejection and are not reinterpreted.

Active testing is a dedicated operator API
(`POST /security-agent/sessions/{id}/approvals` with
`enable_active_testing`). The AI cannot grant it. Tool-specific kinds
(`start_live_scan`, `enable_fuzzing`, `high_risk_scanner`,
`send_poc_request`) are required in live mode even when active testing is on.
Restored sessions intersect persisted privilege snapshots with current scope;
expired approvals are dropped.

## Prompt injection

Web pages, HTML, JavaScript, comments, API responses, scanner output,
HackerOne instructions, and repository content are untrusted. They are placed
in explicit untrusted channels (`BUGFORGE_UNTRUSTED_*`) separate from trusted
instructions. Keyword stripping is additional, not the only control. Target
content cannot issue agent instructions.

## Loop protection

Identical successful tool calls are limited inside a time window. Transient
`FAILED` / `TIMEOUT` retries are allowed. Session budgets (tools, HTTP,
browser, fuzz, iterations, tokens, scan seconds) are loaded from settings and
enforced. Concurrent `step()` calls on one session are serialized with a lock.

## Verification and reporting

AI confidence is not severity and is not verification. Correlation requires
independent evidence provenance (for example static + HTTP + browser), not
two hypotheses that share a vulnerability class.

Promotion is potential → corroborated → reproduction required → reproduced.
The agent cannot call `verify_finding`. `DRAFT_REPORT_CANDIDATE` requires a
verified finding ID plus evidence and reproduction references. It cannot
approve, submit, mark verified, or change scope.

Thinking/reasoning traces are never evidence, report content, HackerOne
payload, or verification state.

## Observability

The research timeline records session state changes, model decisions, tool
requests, authorization, execution start/result, evidence created, hypothesis
updates, reproduction, verification, approval, and pause/stop. Credentials
never appear. The evidence graph is persisted as `research_evidence_node` /
`research_evidence_edge` and reconstructed after restart.
