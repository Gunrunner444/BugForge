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

Phase 49 adaptive planning is not implemented. The scheduler only selects
`runtime_validation`, `fork_validation`, or `differential_validation` when
the request asks for that evidence.

## Local runtime

`bugforge-runtime` is registered in the existing discovery catalog. It does
not use a second orchestrator.

The execution path is `DockerTestExecutor`. The command is the pinned local
entrypoint:

`bugforge-runtime --mode local --chain-id 31337 --block 1 --timestamp 0`

The container writes `/bugforge-output/runtime.json`. BugForge accepts only
the `bugforge-runtime-v1` schema. Any other output is `UNSUPPORTED` and
produces no observation.

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
`deterministic=false`, and the container is not started.

Two runs are comparable only when chain id, block, state snapshot, runtime
configuration, compiler configuration, source snapshot, sequence, actors,
project, and deployment addresses all match and are non-empty. A different
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

If the starting state was not reset, the classification is
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

A missing runtime image, an unrecognized runtime interface, and an unparsed
document do not become observations. Phases 49 and 50 are not started.
