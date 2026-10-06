# Phase 48: runtime, fork, and differential validation

Phase 48 connects a static or protocol candidate to a controlled execution
and compares repeated runs. A runtime observation is evidence. It is not
verification, a vulnerability, or proof of safety. Development stays on
`main`. There is no phase branch and no stacked pull request.

Cursor remains the only AI controller. BugForge does not call Grok, xAI,
OpenAI, Anthropic, or any other model. `llm_invoked` stays false. No API key
and no model endpoint were added.

## Chain

The implemented chain is:

static candidate, or the `bugforge-protocol` graph, then a bounded sequence,
then `bugforge-runtime` inside Docker, then normalized trace, event, and
storage observations, then an economic observation only when the runtime
document establishes one, then a differential comparison. The result remains
`candidate` or `unknown`.

The scheduler selects `runtime_validation`, `fork_validation`, or
`differential_validation` when the request asks for that evidence. Adaptive
planning across engines is Phase 49 (`docs/phase49-adaptive-multi-engine-research-orchestration.md`).

## Execution identity and manifest binding

A loop index is a run number, not a transaction identity. Every execution is
bound to a `RuntimeRequest` (`app/parsing/solidity_runtime.py`) that carries:

- project, source snapshot, compiler configuration, runtime configuration
- target, contract, function identity, deployment address
- sequence id, transaction index, actor
- chain id, block number, state snapshot
- mode (`local` or `fork`) and the requested capability
- a fork reference (a hash, never the fork source) in fork mode

A field the request did not establish is empty and is not compared. Empty is
unknown, not "probably the same". Sequence id and transaction index are always
required. Without both, the container is not started and the result is
`UNSUPPORTED` with `binding=deterministic_identity_missing:...` and
`observation_status=incomplete`.

The request travels to the sandbox as a read-only JSON manifest
(`bugforge-runtime-input-v1`), mounted as the container working directory. The
command is an argument array and holds no request values:

`bugforge-runtime --input <manifest> --output /bugforge-output/runtime.json`

The manifest carries `request_identity` (a hash of every bound field, which is
the same for both runs of a comparison) and a per-run `execution_id`
(`<request_identity>:run<N>`). The only shell form is the existing
`sh -c <shlex.join(argv)>` of `DockerTestExecutor`. A hostile actor string
stays data inside the manifest.

## Transaction selection and output validation

`runtime.json` must echo `request_identity`, `execution_id`, `mode`, and
`target`, and each transaction must carry `sequence_id` and `index`.
`select_observation` then:

1. matches by `(sequence_id, transaction_index)` and never by array position
2. returns `not_found` when no transaction has the requested identity, and it
   never clamps to the last observation
3. returns `ambiguous` when two transactions share the identity, and it never
   picks the first
4. requires the echoed `request_identity` and `execution_id` to match
5. requires every field the request established (project, source snapshot,
   compiler configuration, runtime configuration, target, contract, function
   identity, deployment address, actor, chain id, block, state snapshot, mode)
   to equal the observation

Any failure gives `UNSUPPORTED`, `observation_status` of `incomplete` or
`unknown`, a `binding` reason such as `mismatch:project`, no
`runtime_evidence`, and `tool_status` evidence that does not contribute to
verification. A missing, negative, boolean, zero-padded, or non-numeric
transaction index is empty and cannot match. There is no positional fallback
for the index or the execution id. A document with more than 32 transactions
is rejected rather than truncated.

A differential run executes the same `RuntimeRequest` twice, selects the same
`(sequence, transaction)` from each document, and compares them. A different
transaction on each side never compares. A comparison also needs the same
transaction index, contract, and function identity on both sides.

## Success and revert semantics

`RuntimeObservation.success` is one of `true`, `false`, `missing`,
`malformed`, `unknown`. `normalize_success` accepts a JSON boolean or the exact
words `true` and `false` (case-insensitive). Python truthiness is never used,
so the string `"false"` is not success. A missing key is `missing`, JSON null
is `unknown`, and anything else (`"yes"`, `"1"`, numbers, lists) is
`malformed`. Construction normalizes the value, so a direct construction
cannot carry an unnormalized string.

An observation is `observed` only when success is `true` or `false`, a state
snapshot is present, and the sequence and transaction identity are present.
A comparison with an unknown success on either side is
`incomplete comparison` with status `incomplete`.

A reverted transaction is a valid observation when the tool succeeded. The
result records `transaction_success=false`, `transaction_outcome=reverted`, and
`vulnerability=unknown`. A revert is not a vulnerability.

## Process exit status

The exit status is authoritative. `process_outcome` is the decision matrix:

| Process | Document | Result |
| --- | --- | --- |
| exit 0 | valid and identity-bound | accepted: `INGESTED`, candidate evidence |
| exit 0 | missing, invalid, or unbound | `UNSUPPORTED`, no evidence |
| exit nonzero | valid-looking | `TOOL_FAILURE`; document is diagnostic only (`document_attributed=false`) |
| exit nonzero | none | `TOOL_FAILURE` |
| timeout | any | `TIMEOUT`, no observation |
| did not start | none | `FAILED`, not counted as executed |

A revert inside an accepted document is a transaction result. A failed process
is a tool result. They are never conflated. Failure and unsupported results
carry `evidence_class=tool_status`, which maps to `tool_status` evidence and
never to a log or runtime observation.

## Local runtime

`bugforge-runtime` is registered in the existing discovery catalog. It does
not use a second orchestrator.

The execution path is `DockerTestExecutor`. BugForge accepts only the
`bugforge-runtime-v1` schema. Any other output is `UNSUPPORTED` and produces
no observation.

The image setting is `security_agent_runtime_image`. It defaults to empty.
Availability also requires Docker and a locally present image. BugForge does
not pull an image. A missing image is `UNAVAILABLE`. Host `anvil`, `forge`,
and `cast` are not fallbacks. `LocalTestExecutor` is not used.

The sandbox keeps the existing limits: network `none` by default, 512 MB
memory, 1 CPU, a 60 second timeout, a read-only source mount, a writable
scratch output directory, a `PATH`-only environment, and no Docker socket.
Request text cannot set `allow_network`.

A parsed document can record project, source snapshot, compiler
configuration, runtime environment, sequence, transaction index, actor,
deployment address, contract identity, function identity, success or revert,
return data, revert reason, gas, events, storage changes, nested calls, call
type, block number, timestamp, chain id, state snapshot, duration, and tool
identity. Fields the document omits stay empty. Empty is unknown, not a
guess.

## Fork validation

Fork mode is separate from local mode. The default is no public RPC, no
discovered fork URL, and no network.

A fork runs only when both operator settings are set:
`security_agent_fork_enabled` and `security_agent_fork_source`. The model
cannot set those, and a `fork_url` in the request is not the fork source.

A deterministic fork also needs a numeric block, a chain id, and a state
snapshot. `latest` is not a pinned block. An unconfigured fork is
`UNAVAILABLE`. An unpinned fork is `UNSUPPORTED`, with
`deterministic=false`, and the container is not started. A request that
carries a URL-like value or key (`fork_url`, `https://...`) is `FAILED` before
any container starts, and wallet material (`private_key`, `mnemonic`,
`wallet`, `secret`) is refused.

The result metadata records the network that was actually used:

| Case | `network` | `runtime_mode` |
| --- | --- | --- |
| local run, or any run that never started | `none` | `local` or `fork` |
| pinned controlled fork that started a container | `controlled-fork` | `fork` |

Fork metadata also records `chain_id`, `fork_block`, and `fork_reference`, a
hash of the fork source, chain, block, and snapshot. The fork source itself is
written only to the read-only manifest of a fork run. It is not in result
metadata, evidence, or the command line. A fork run uses a bridge network. The
operator's `security_agent_fork_source` is therefore trusted configuration.
BugForge does not restrict egress beyond refusing to start without that
configuration, so treat the fork image as trusted operator infrastructure.

Two runs are comparable only when chain id, block, state snapshot, runtime
configuration, compiler configuration, source snapshot, sequence, transaction
index, contract, function identity, actors, project, and deployment addresses
all match and are non-empty. A different
block, target address, or source snapshot is a different state. Evidence
from those runs is not merged.

## Traces, events, and storage

Traces keep caller, callee, and child nesting. `CALL`, `STATICCALL`,
`DELEGATECALL`, `CREATE`, `CREATE2`, `RETURN`, and `REVERT` stay distinct
when the document supplies them. Anything else is `unknown`. A selector is
not turned into a source function unless `identity_established` is true and
the function identity is present. An unresolved selector stays unresolved.

Events keep address, topic, transaction index, log index, raw data, and
decoded arguments only when decoding is marked successful. Contract and
source identity are kept only when that identity was established for the
deployment. A `Transfer` name is not evidence of a token. A `Swap` name is
not evidence of an AMM. An event name does not prove a state transition.

Storage changes keep address, slot, before, after, transaction, and
execution context. Slots are treated as the same location only when both
sides have an established layout, the same contract identity, and the same
address. A shared numeric slot across contracts is not aliasing. Unknown
layout stays unknown.

## Binding to earlier phases

A runtime call binds to a Phase 47 edge only when the contract identity, the
function identity, and the edge id all match an edge whose function signature
is resolved. A function name is not enough.

A storage change binds to a Phase 41 transition only when contract, function,
and storage identities all match. A partial match stays unbound.

A balance becomes an economic delta only when its provenance is
`runtime-execution` and the actor, token, kind, transaction, snapshot, and
contract are present. Caller-supplied numbers are rejected. Actors and tokens
stay separate. A positive delta is not profit and is not an exploit. The
Phase 46 accounting rules still apply.

## Differential validation and replay

`compare_executions` compares two observations of one sequence. It records
differences in success, return data, events, call structure, storage, and
gas. A difference is `candidate` and `deterministic divergence`. Matching
output is `candidate` and `deterministic same result`. Neither status is
`safe` or `verified`.

The caller states whether the starting state was reset (`state_reset=true`).
BugForge does not infer a reset. If it was not reset, the classification is
`state-dependent divergence`. If the state identities differ, the
classification is `incomplete comparison` or `environmental divergence`.
Those comparisons are `unknown`.

A replay that lacks success data is an `incomplete comparison`. Intermittent
behavior is not labeled an exploit. `failure_is_vulnerability` is false for
a revert and for a failed run.

Metamorphic checks cover equivalent ABI encoding, a repeated call, reordered
independent observations, and the same sequence from the same snapshot.
The expectation is `expected-equivalent` only when the caller establishes
that the transformation preserves behavior. Otherwise it is `unknown`.

Differential and replay runs are capped by `MAX_EXECUTIONS` (8). A comparison
uses at most two executions. `clamp_runtime_executions` and
`clamp_protocol_bounds` cannot be raised by a planner. Follow-up, protocol
analysis, runtime validation, and differential validation share `max_engines`.
Unavailable and unsupported results are not counted as exercised evidence.

## Protocol paths

`expand_paths_report` keeps every valid bounded path. It returns the paths and
whether the hard cap hid others (`truncated`). Each `ProtocolPath` has the
existing `path_id` (ordered nodes and edges) and a `stable_id`, a hash of the
project, source snapshot, compiler configuration, and `path_id`. The id never
depends on list position or memory address, and it changes when the source
snapshot changes.

`ProtocolEvidence` carries all paths and `paths_truncated`. Result metadata
holds `paths`, `path_ids` (sorted stable ids as JSON), and `paths_truncated`.
`ProtocolEvidence.path` holds an id only when exactly one path exists.
Caps (`MAX_PROTOCOL_EXPANSION` and the others) are not raised by a planner. A
path is a candidate. Its existence is not exploitability and not verification.

## Deterministic scheduler capability

`DiscoveryScheduler._decide` reports `capability_for(engine, request)`, which
calls `engine.selected_capability(request)`. That method names the capability
the operation will execute: `static_analysis` for an engine that declares it
(it runs `analyze_target`), otherwise the engine's campaign capability, and
otherwise the first declared capability in the fixed `CAPABILITY_ORDER`. For
`bugforge-runtime` the capability follows the request mode (`fork`,
`differential` or `replay`, otherwise `runtime_validation`). Set iteration
order is never used. A decision never names a capability the engine lacks.

## Tests and integration limits

The Phase 48 tests are split by what they exercise:

- `test_runtime.py`: parser, schema, binding helpers, and engine behavior with
  a scripted executor
- `test_runtime_binding.py`: identity, manifest, and selection (scripted
  executor)
- `test_success_and_process.py`: success semantics and the exit matrix
  (scripted executor)
- `test_fork_and_scheduler.py`: fork gating, metadata, and capability reporting
- `test_protocol_paths.py`: path preservation
- `test_runtime_executor.py`: the real `DockerTestExecutor` argument builder,
  mounts, exit-status mapping, and artifact collection with a stand-in for the
  Docker process. It runs no container and no EVM, and it is not the
  integration test
- `test_runtime_integration.py`: real Docker. It runs only when Docker exists
  and `security_agent_runtime_image` is a locally present image. Otherwise the
  engine reports `UNAVAILABLE`, the live test is skipped, and nothing is
  simulated as a pass

`tests/fixtures/runtime_image` holds a contract fixture (not an EVM) that
echoes the request identity, so the Docker plumbing can be exercised without
Foundry. Build it locally. Tests never build or pull an image. In this
repository's CI no such image is present, so the live test is skipped there.

## Evidence and authority

Runtime and differential results use `runtime_observation`. Protocol results
use `protocol_observation`. Neither provenance is in the live verification
set. Metadata records `verified=false` and `vulnerability=unknown`.

Phase 48 does not write `verified=true`. ScopeGuard, SafetyController,
RateLimiter, human approval, evidence binding, and the existing reproduction
path are unchanged.

## What this does not establish

Phase 48 does not establish:

- universal exploitability
- universal safety
- production impact
- economic profit without the existing accounting requirements
- equivalence of arbitrary contracts
- correctness of arbitrary public-chain state
- validity of an unpinned fork
- source mapping for unresolved bytecode
- safety from a lack of observed divergence

A missing runtime image, an unrecognized runtime interface, an unparsed
document, and a document for a different transaction do not become
observations. Phase 50 is not started.
