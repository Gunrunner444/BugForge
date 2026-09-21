# Security Research Workbench

Phase 9 turns the existing `SecurityResearchAgent` and
`AdvancedResearchOrchestrator` into a researcher-facing workflow. It does
**not** introduce a second agent or an unrestricted autonomous hacking loop.

| Area | State |
|---|---|
| Research project lifecycle | **implemented** |
| Dashboard / timeline / control panel | **implemented** |
| Finding / evidence / identity workbenches | **implemented** |
| Next-action review before higher-risk tools | **implemented** (approval still required where `ToolSpec` says so) |
| Local lab end-to-end | **lab-only**, **implemented** |
| Live HackerOne | **live-capable**, **requires approval**, never autonomous |
| Qwen/MLX planner | **optional**; CI does not require the model |
| ZAP / Nuclei / Playwright | **unavailable without external binary** |

## Project lifecycle

`CREATE` → `CONFIGURE` → `SCOPE_SYNCED` → `READY` → `RESEARCHING` →
`PAUSED` → `FINDINGS` → `REVIEW` → `HANDOFF` → `COMPLETE`

These states are local to BugForge. They are not HackerOne remote report
states.

## Dashboard

`GET /api/v1/security-agent/sessions/{id}/dashboard` shows project, program,
target, mode, scope, strategy, current hypothesis, evidence completeness,
contradictions, current tool, remaining budget, approvals, research state,
and termination reason.

Session kind is **LAB** or **LIVE**. Execution mode is **DRY-RUN** or
**ACTIVE**. Installed ≠ enabled ≠ approved ≠ authorized.

## Controls

Operator-authenticated actions: pause, stop, resume, disable/enable tool,
change limits, reject action, reject finding, change strategy. Each action
validates session ownership and is written to the audit timeline.

## Next action review

Higher-risk tools surface: what BugForge wants to do, why, target, tool,
expected evidence, estimated requests (an **estimate**, not a guarantee),
risk, whether approval is required, and the current scope decision.

Estimates use the same units as budget consumption (`http_request` → 1
request, `fuzz count=20` → 20 fuzz requests, `api_test max_tests=8` → 8
requests). Scanner review still shows a **request envelope estimate** for
the operator; the session consumes one tool call plus measured scan
duration after execution, not the full envelope up front. Planned,
reserved, and consumed counters are tracked separately.

Operator-authenticated workbench actions validate session ownership
(`session_operator_mismatch` if another operator token is presented).
Research projects persist to `security_research_projects` and reconstruct
after process restart.

## Local lab

Start `tests/fixtures/lab_app`, create a lab research project, choose a
strategy, and step the agent. No external network target is required.
Reproduction evidence may promote a finding to verified only when
deterministic observational evidence exists. The AI never marks verified.
