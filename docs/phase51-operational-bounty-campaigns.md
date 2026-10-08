# Phase 51: operational bounty campaigns

Phase 49 (adaptive multi-engine research orchestration) and Phase 50 (program-aware
bounty research) were library-only: the orchestrator, the bounty engines, `BountyGate`,
findings, VFCS plans, advisories, and the report pack existed and were tested, but no
API route or MCP tool reached them. Phase 51 closes that gap. It makes a bounty campaign
**operational** while reusing the existing stack and introducing no parallel session
type, evidence store, or authority model.

## What was added

- `app/discovery/bounty/service.py` — `BountyCampaignService`, an in-process registry of
  campaigns. Each campaign is a Phase 49 `Orchestrator` over a `DiscoveryScheduler` that
  carries `BugforgeStaticEngine` plus `build_bounty_engines(manifest)` (the Phase 50
  research and compiler-differential engines). Identity is `CampaignIdentity` derived from
  the `BountyManifest`; the gate is `BountyGate`; persistence is `MemoryStore`.
- `app/api/v1/endpoints/bounty_campaign.py` — operator-authenticated REST routes under
  `/api/v1/bounty`:
  create, inspect, state, analyze, next-action, execute, suggest, findings, evidence,
  repro, advisories, report, approvals, pause, resume, stop.
- `app/cursor_control/mcp_server.py` — nine bounty MCP tools (`bugforge_create_campaign`,
  `bugforge_campaign_state`, `_analyze`, `_execute`, `_next_action`, `_findings`,
  `_evidence`, `_repro`, `_report`). The server allow-lists the `/api/v1/bounty/` prefix,
  blocks the approvals path, and extends its forbidden-tool set.

## Flow

```
Cursor MCP tool  ->  /api/v1/bounty/...  ->  BountyCampaignService
   ->  Orchestrator (Phase 49)  ->  DiscoveryScheduler
   ->  BugforgeResearchEngine / BugforgeStaticEngine / compiler-diff (Phase 50)
   ->  typed evidence  ->  next capability  ->  findings  ->  report pack
```

## Security invariants (unchanged and enforced)

- Every request must carry the manifest's program-context identity; `BountyGate` refuses a
  mismatch (`SAFETY_BLOCKED`).
- An out-of-scope target stops the campaign (`scope_blocked`) before any engine runs.
- Fork validation needs an in-scope asset, a program that allows fork testing, the exact
  pinned fork from the manifest, **and** an operator approval. Approval is a human-only REST
  route; the AI operator identity is refused and the MCP server cannot reach the path.
- A Cursor/operator suggestion is validated like any candidate. It cannot widen scope, raise
  a budget, enable a gated capability, or verify anything.
- No result is ever marked verified or submitted. The report pack states "Not verified" and
  "Not submitted". `llm_invoked` stays false.
- Optional tools (`solc`, `forge`) report UNAVAILABLE and never fabricate a result.

## Limitations

- The campaign registry and `MemoryStore` are per-process (like the Phase 49 note on the
  synchronous `SqlStore`). Multiple API workers do not share campaigns.
- The compiler-differential engine stays UNAVAILABLE without `solc`; fork and fuzz engines
  stay UNAVAILABLE without their binaries. A campaign on a bare host exercises the static and
  semantic capabilities and stops with `environment_unavailable` rather than inventing a
  runtime result.

## Tests

`backend/tests/test_phase51/`:
- `test_campaign_service.py` — service-level behaviour (identity reuse, capability coverage,
  determinism, scope block, approval gating, suggestions cannot widen authority).
- `test_campaign_api.py` — full REST flow end to end, operator-auth enforcement, operator-only
  approval, invalid manifest, unknown campaign.
- `test_mcp_bounty.py` — MCP tool-call path driving the real API through a bridged transport,
  blocked approvals path, forbidden tools, and token redaction.

## Phase 51 hardening

The first Phase 51 cut was operational but in-memory and partly stubbed. The
hardening pass made it real:

- **Durable persistence.** Campaigns now persist on the existing SQL store via
  `app/services/bounty_campaign_store.py` (a `RunnerSqlStore` over the Phase 49
  `SqlStore` plus a `CampaignRecordStore` with optimistic-revision conflict
  detection) and Alembic migration `028`. A campaign — manifest, identity, operator,
  approvals, control state, background job, and artifacts — survives a restart. No
  new session or evidence database was introduced.
- **Real pause / stop / resume.** `StopReason.OPERATOR_PAUSED` (resumable) and
  `OPERATOR_STOPPED` (final) and `Orchestrator.halt(...)` route operator control
  through the actual Phase 49 state machine between rounds. A concurrent `execute`
  cannot bypass a pause, and a stopped campaign refuses resume.
- **Deployment-aware scope identity.** A campaign carries deployment identity end to
  end (chain, address, contract, source commit, runtime digest, compiler, proxy /
  implementation / beacon / diamond / clone). Empty extension fields stay out of the
  identity digest, so existing identities are unchanged. Ambiguous deployments stay
  ambiguous.
- **Real source selection.** `select_sources(...)` drives the analysis path with
  explicit truncation, keeps every file that declares a same-named contract (no
  silent first-alphabetical binding), and runs bounded follow-up over dropped
  high-priority files.
- **Honest report backends.** The compiler differential uses a real `solc` backend
  when one is installed, the stored prior result otherwise, and `UNAVAILABLE` when
  neither — never a hard-coded `NoCompilerBackend`.
- **Correct classification.** The `high_value` family now maps per detector:
  read-only reentrancy → reentrancy, transient-storage misuse → business-logic,
  EIP-7702 EOA assumption → authorization (previously all were labelled reentrancy).
- **Complete MCP.** The loopback, operator-token MCP server adds source selection,
  scope identity, advisories, VFCS feedback, background progress, and real
  pause/resume/stop. Every tool is a read or a state-machine control; none can grant
  an approval, widen scope, raise a budget, verify, or submit.
- **Async-safe API.** Every heavy route runs off the FastAPI event loop via
  `run_in_threadpool`, and expensive analysis runs as a background job with progress.
