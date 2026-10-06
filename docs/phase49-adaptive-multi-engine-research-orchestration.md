# Phase 49: adaptive multi-engine research orchestration

Phase 49 decides which discovery engine to run next, and why, from the
evidence a campaign already holds. It reuses `DiscoveryScheduler`, the engine
adapters, `DiscoveryCorpus`, and the Phase 41 to 48 identity (project, source
snapshot, compiler configuration, contract, function). It adds no engine and
no analysis of its own.

Development stays on `main`. There is no phase branch and no stacked pull
request. Phase 50 is not started.

## Boundaries

- Cursor is the only AI controller. BugForge does not call any model.
  `llm_invoked` is always false, and the package imports no network, process,
  or model module (a test checks the imports). No API key or model endpoint
  was added.
- Nothing is verified. There is no verified evidence quality, no verified
  field on campaign state, and no code path that sets one.
  `recommend_verification_review` is a flag for Cursor to look at a
  corroborated candidate. It changes nothing and approves nothing.
- Nothing escalates. A campaign cannot raise a budget, widen scope, grant an
  approval, enable network access, or add a private key. Limits only tighten.
  Approvals come from the caller on every run and are never written to state.
- Missing tools stay unavailable. Nothing is fabricated for an engine that did
  not run.

## Shape

One engine runs per round. A round is:

1. assess which capabilities the evidence still lacks (`assess.py`)
2. build and rank candidates (`planner.py`)
3. gate the best candidate (`gate.py`)
4. reserve budget, mark the execution `started`, and persist
5. run exactly that engine through `DiscoveryScheduler.run_engine`
6. settle budget, classify the result, and fold evidence into typed state
   (`evidence.py`)
7. record a sealed decision, persist, and either continue or stop

`Orchestrator` (`orchestrator.py`) owns the loop. `step()` advances at most one
engine run. `run()` loops until the campaign stops. A terminal or stopped
campaign does nothing when called again.

```python
orchestrator = Orchestrator(scheduler, request, store=SqlStore(session))
state = orchestrator.run()
report = orchestrator.report()
```

## State machine

`created -> baseline -> planning -> ready -> executing -> observing ->
correlating -> continue -> planning`, with `blocked`, `stopping`, and the end
states `stopped`, `completed`, `inconclusive`, and `failed`.

Only declared moves are legal (`TRANSITIONS`). `blocked` is visited only for a
resumable stop. `stopped` returns to `planning` only on an explicit resume.
`completed`, `inconclusive`, and `failed` have no exits. An internal error
moves the campaign to `failed`, records the reason, and stops. A persistence
or resume error is raised to the caller instead of being hidden as a failure.

## Capability needs

`assess()` turns evidence and request flags into `CapabilityNeed` records with
a status (`missing`, `partial`, `satisfied`, `blocked`, `unavailable`,
`redundant`, `high_value_followup`, `low_value_followup`), a fixed integer
weight, reasons, and uncertainties.

| Need | Raised by | Weight |
|---|---|---|
| contradiction discriminator | an open contradiction | 80 |
| static analysis | no static baseline yet | 100 |
| fuzzing | a candidate (70) or a named target (55) | 70 / 55 |
| fuzz follow-up | a symbolic counterexample became a corpus seed | 65 |
| divergence follow-up (fork) | a deterministic divergence | 58 |
| symbolic execution | `difficult`, or a stalled fuzz or test round | 60 |
| test execution | an encoded property or a harness | 60 |
| runtime validation | `runtime` flag, a `sequence_id`, or an economic observation | 55 |
| cross-contract analysis | `protocol` flag, or a reentrancy, external-call, or authorization candidate | 50 |
| economic simulation | `economic` flag or a `case` | 50 |
| fork / differential validation | `fork` / `differential` flag | 45 |

An exercised capability is satisfied. It becomes a follow-up only when new
evidence justifies one, and the repeat then has to pass duplicate prevention.

Stalled means the last completed fuzz or test round added no new evidence.
Unknown history is never stalled.

## Candidates, ranking, and complementarity

For every actionable need the planner considers every registered engine that
declares the capability, in `(engine_rank, engine_id)` order. Engine
registration order does not matter. A candidate is rejected with a stable
reason, checked in this order:

1. `environment:language`, `environment:engine_unavailable`
2. `prerequisite:capability_not_selectable`: the engine would not actually run
   the requested capability for the request the planner built
3. prerequisites and identity (below)
4. `scheduler:<code>`: the scheduler's own preconditions (`DiscoveryScheduler.decide`)
5. `environment:circuit_open`: two consecutive failures from that engine
6. `duplicate:execution_key` or `environment:failed_attempt`
7. `budget:<dimension>`
8. `gate:safety`, `gate:scope`, `gate:approval`

Score is the sum of recorded components: need weight, complementarity, minus
cost, minus engine rank, plus a diversity bonus for an engine not yet used,
minus a health penalty, plus 5 for an accepted suggestion. Ties break by lower
engine rank, then engine id, then capability.

Complementarity is `contradiction_resolving` (+30), `discriminative` (+25),
`novel` (+20), `prerequisite_generating` (+18), `coverage_expanding` (+15),
`corroborative` (+10), or `redundant` (-50).

The orchestrator sets exactly one request field, `extra["mode"]`, to select
the capability, and the shared corpus. It never sets `network`, `state_reset`,
fork parameters, chain id, or block number. Those come from the caller's
request and are checked, not invented.

### Prerequisites and identity

| Capability | Needs |
|---|---|
| fuzzing, symbolic, test, property, invariant | a contract, function, source file, or harness |
| cross-contract, economic, runtime family | source snapshot and compiler configuration |
| economic simulation | an economic `case` |
| runtime family | contract and function, and a `sequence_id` |
| fork validation | `chain_id`, `fork_block`, and `state_snapshot` (a pinned fork) |
| differential validation | `state_reset == "true"` supplied by the caller |

A missing prerequisite is reported. It is not guessed, defaulted, or created.

## Budget

`new_ledger()` builds limits from `scheduler.max_engines` and
`scheduler.max_rounds` (rounds are also capped at 16). `max_rounds`, `caps`,
and `runtime_seconds` can only lower a limit. Dimensions: `attempts`,
`engines`, `rounds`, `executions`, `runtime_executions`, `runtime_seconds`,
`fuzz_runs`, `symbolic_runs`, `test_runs`, `economic_runs`, `protocol_runs`.

A candidate reserves before it runs. Settling releases the reservation and
consumes what was used. Work that never started (unavailable, unsupported,
refused) consumes one attempt only. A run that executed consumes its full
cost. An unknown outcome (the engine raised, or the process stopped after the
start was recorded) keeps its whole reservation. Use above the reservation or
above a limit is kept and flagged as an overrun. A scheduler that already ran
engines starts with that consumption.

## Duplicate prevention and idempotency

An execution key is a digest of the target digest, engine, capability, input
digest, and retry count. The input digest covers the request fields, the
caller's extras (without volatile ids), the corpus refs for seeded
capabilities, and the evidence ids from other capabilities that the run
depends on. An unchanged input never repeats. A changed input (a new
symbolic seed, new upstream evidence) is allowed.

Execution phases are `planned`, `started`, `completed`, `timed_out`, `failed`,
`unavailable`, `unsupported`, `blocked`, `unknown`, and `superseded`. A
`started` record is saved before the engine runs. If the process stops there,
the next load marks it `unknown`, keeps its cost, and never re-runs it by
itself. `grant_retry()` supersedes one unknown, timed-out, or
infrastructure-failed execution so it can run again with a new key. It is
limited to two grants per input, and the retry still needs budget and a gate
pass.

## Evidence

Results become typed `EvidenceItem` records with a quality:
`unavailable`, `unsupported`, `incomplete`, `unknown`, `observation`,
`candidate`, and `corroborated`. There is no verified level.

- Evidence ids are content hashes. The same engine reporting the same thing
  again adds nothing.
- Raw stdout and stderr are never copied. Attributes are short strings.
- A result that names another engine, language, campaign id, source snapshot,
  or compiler configuration is not attributed to the campaign. It is recorded
  as a failed execution with failure class `identity` and adds no evidence.
- Identity is contract plus function. A bare function name has no identity. A
  name without a signature cannot select one overload of a target that names a
  signature.
- Corroboration needs a distinct engine and a distinct capability, the same
  identity, and the same detector family. It is still not verification.
- Negative evidence ("this bounded run reported no candidate") has
  `proves_safety` false. The loader rejects a document where it is true.
  Timeouts, unavailable tools, and failures produce no negative evidence.

### Contradictions

A positive candidate against a runtime-family result that did not reproduce
it, or a deterministic divergence against a same-result run in another mode,
is a contradiction. It records both evidence ids, both engines, and the
capabilities that could discriminate. It stays `open` until a discriminator
has run, then `unresolved`. It is never marked resolved and neither side is
chosen. An unresolved contradiction ends the campaign as `inconclusive`.

### Evidence delta

Each decision records what was new: evidence, findings, protocol paths, state
transitions, sequences, runtime, economic, and differential observations,
corpus seeds, contradictions, negative evidence, coverage, and uncertainty
added or removed. `informative` is evidence-based. Removing an uncertainty
alone is not informative, which is what lets a stalled fuzz round be noticed.

## Stop reasons

| Reason | Ends in | Resumable |
|---|---|---|
| `rounds_exhausted`, `execution_cap_exhausted`, `budget_exhausted` | stopped | no |
| `safety_blocked`, `scope_blocked` | stopped | no |
| `approval_required`, `environment_unavailable`, `prerequisites_unavailable` | stopped | yes |
| `deterministic_identity_missing`, `unresolved_uncertainty` | inconclusive | no |
| `all_capabilities_exercised`, `no_useful_capability`, `redundant_evidence`, `completed_bounded_research` | completed | no |

When several things block the campaign the order is safety, scope, approval,
identity, budget, prerequisite, environment. `redundant_evidence` is two
consecutive completed rounds of the same capability that added nothing.
`completed_bounded_research` means the round budget was spent and no need
remained.

## Persistence and resume

`ResearchState` serializes to canonical JSON (sorted keys, sorted sets, no
timestamps in any hash) and carries `schema_version` and a state hash.
`load_state()` is strict. It refuses unknown fields, wrong types, unknown
enum values, a future or old schema, a hash mismatch, broken decision history,
negative budget values, and negative evidence that claims safety. Each
failure is a `ResumeError` with a status (`corrupt`, `unsupported_version`,
`migration_required`, `stale_identity`).

Stores: `MemoryStore` for tests and `SqlStore` (two tables, Alembic revision
`027`). `SqlStore` uses an optimistic revision check, refuses to overwrite a
campaign it did not load, and treats decision rows as insert-only history.

On resume, `Orchestrator` revalidates the document:

- a changed target, source snapshot, or compiler configuration is
  `stale_identity` and nothing is reused
- limits are merged with `min`, consumption with `max`, reservations are
  dropped, and a `started` execution becomes `unknown` with its cost kept
- an interrupted round is walked back to a point that can plan
- a persisted next step is cleared and planned again, never executed directly
- a `stopped` campaign moves only on `start(explicit_resume=True)` and only
  for a resumable reason. An engine that was unavailable and is available
  again has its record superseded so it can be planned
- approvals are not in the document, so the caller has to grant them again

## Decision records

Every round and every stop writes a sealed `DecisionRecord`: sequence,
round, source (`planner`, `external_suggestion`, `retry`, `recovery`),
previous state, state hash before, evidence summary, uncertainties, missing
capability, all needs, all candidates considered with rejections and score
components, the selection and rationale, prerequisites, budget before,
reserved and consumed cost, execution key, input digest, result status,
evidence delta, next capability, stop reason, fork reference, differential
summary, identity digest, snapshot, compiler, and orchestrator version.
`created_at` is audit-only and excluded from every hash.

## External suggestions

`Orchestrator.suggest(capability, engine="")` queues a request from Cursor
(at most eight pending). It is validated against the known orchestratable
capabilities and registered engines. A valid suggestion becomes a
low-value candidate with a small bonus. It still faces prerequisites,
duplicate prevention, budget, and the gate. An invalid one is dropped and
recorded by a hash of its text, not the text.

## What is not covered

- Scenarios and unit tests use scripted engines. No Foundry, Slither, Echidna,
  Medusa, Halmos, Wake, ItyFuzz, or Docker runtime ran for these tests.
- Phase 48 runtime integration still needs Docker and the runtime image to run
  for real. It reports unavailable otherwise.
- The `SqlStore` is synchronous. Wiring it into the async API is not part of
  this phase.
- There is no UI or API route for orchestration yet.
- Phase 50 (production bounty-research workflow) is not started.
