# Phase 52: closed-loop stateful verification

Phase 50 and Phase 51 produce *candidates*: semantic findings, deterministic VFCS
call sequences, advisories, and a report pack. Nothing was ever executed. Phase 52
closes the loop. The call sequences a campaign discovers are compiled into a local
Foundry harness and **actually executed** with `forge`, the result is interpreted
honestly, and that observation feeds back into sequence mutation, re-execution,
minimisation, and an independent re-check before a reproducible artifact bundle is
written. Everything is local; nothing runs against any network; and when the tools
are not installed the executor reports `UNAVAILABLE` rather than inventing a result.

This reuses the Phase 44–51 stacks. There is no second session type, no second
evidence store, no second fuzzer, and no second authority model.

## What was added

- `app/discovery/bounty/stateful.py` — the stateful execution core.
  - `build_harness(...)` compiles the executable primitives of a VFCS into a Foundry
    `Test` contract and a property check. Constructs it cannot express faithfully
    (unknown constructor arguments, interface-only targets, unexpressible argument
    types) are reported `INCONCLUSIVE`, never faked.
  - `StatefulExecutor` scaffolds a throwaway Foundry project pinned to the host
    `solc` (`auto_detect_solc = false`), offline, with `ffi = false`, runs
    `forge test`, and interprets the output into an `Outcome`:
    `property_violated`, `property_held`, `sequence_executed`, `sequence_reverted`,
    `inconclusive`, or `unavailable`. A tiny local `Test` + `vm` shim is used so no
    `forge-std` is vendored.
  - `run_feedback_loop(...)` executes a sequence, observes the outcome, feeds it into
    VFCS mutation, re-executes the mutated frontier, minimises a violating sequence,
    and runs a **second independent check** with the optimizer disabled before it
    accepts the observation. It writes a reproducible bundle (sources, harness,
    foundry config, and the exact command) so a human can replay it.
  - `tool_status()` / `execution_enabled()` report tool availability truthfully.

- `app/discovery/bounty/service.py` — `BountyCampaignService.stateful_execute(...)`
  runs the loop as a bounded, async-safe background job over the persistent campaign
  and records the outcome as campaign state.

- `app/api/v1/endpoints/bounty_campaign.py` — `POST /campaigns/{id}/stateful-execute`
  (operator-authenticated, bounded rounds, off the FastAPI event loop via
  `run_in_threadpool`).

## Honesty and safety

- No network: the Foundry project is offline, `ffi` is disabled, and no RPC is used.
- No fabricated results: a sequence that cannot be expressed or compiled is
  `INCONCLUSIVE`; absent tools are `UNAVAILABLE`.
- Nothing is marked verified or submitted, and the AI/MCP cannot grant approvals,
  widen scope, or raise a budget.

## Tooling

Local execution needs `forge` and a matching `solc` on `PATH`. When they are
present the executor distinguishes a property violation from a property that holds
from a sequence that merely executes; when they are absent every result is
`UNAVAILABLE` and the rest of the campaign is unaffected.
