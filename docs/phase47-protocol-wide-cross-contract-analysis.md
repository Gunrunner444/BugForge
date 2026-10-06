# Phase 47: protocol-wide cross-contract analysis

Phase 47 connects contracts that the semantic model already relates. It does
not treat similarly named contracts as one protocol, and it does not turn a
path into an exploit. Development stays on `main`. There is no phase branch
and no stacked pull request.

Cursor remains the only AI controller. BugForge does not call Grok, xAI,
OpenAI, Anthropic, or any other model. `llm_invoked` stays false.

## Protocol graph

`build_protocol_graph` records contract nodes and interaction edges from
parser facts. A node keeps the project, source snapshot, compiler
configuration, source file, contract declaration, and the declaration span.
The span is the contract, interface, or library declaration. It is not the
first function span. A missing declaration span stays empty. An address is
stored only when the local analysis supplies one. The same Solidity name in
two files is two nodes. A source identity and an address stay separate.

Node kinds come from the declaration (`contract`, `interface`, `library`).
Roles such as token, oracle, proxy, implementation, or callback are added
only from an established edge, not from the contract name.

Edges are created only when a call resolves or an explicit link is supplied.
The kinds are external call, internal call, delegatecall, staticcall, token
transfer, `transferFrom`, approval, permit, callback, oracle read, price
dependency, storage dependency, authorization dependency, proxy
implementation, and event-to-state. Every edge keeps its provenance. Two
contracts are not linked because their names look alike. A price dependency
is created only from a `PriceLink` that names the oracle edge, a computation,
a valuation, the asset edge, a non-empty span, and provenance. Two calls in
the same function do not create that edge. An authorization dependency is
created only from a `TrustBoundary` with caller-controlled input, established
missing caller authorization, an established privileged callee, cross-contract
propagation, and a semantic relationship. A normal call into an authorized
function is not that evidence.

Unresolved and dynamic calls stay in `unresolved`. The graph does not invent
a callee. Delegatecall is a different kind from an ordinary external call.
A proxy-to-implementation edge requires an `ImplementationLink` with a
non-empty implementation, matching source files, and a provenance string.
An unknown implementation stays unknown.

## Canonical identity

Function identity is the parser function: project, source snapshot, compiler
configuration, source file, contract, signature, line, and span. The displayed
signature comes from that function's own header, so `foo(uint256)` stays
`foo(uint256)`. Overloads do not collapse to a shared name. A header that
cannot be parsed stays `unresolved`. Sequence and harness lookup use that
identity when a semantic program is present. Without a program, a name is
accepted only when the contract declares it once. An ambiguous overload is
not called.

## Cross-contract dataflow and transitions

`cross_flows` walks established edges. A flow step uses the edge kind and
the function or call identity. It does not synthesize a callee for a dynamic
call, and it does not treat every external call as an exploit path.

Storage guidance uses declaration identity. `same_storage` is true only when
both sides name the same non-empty declaration. Shared variable names are
not aliasing. A storage edge also requires the writer and reader function
identities and a provenance string.

## Sequences

Protocol sequences reuse the Phase 45 caps. `MAX_EXECUTIONS` stays 8 and
`MAX_SEQUENCE_LENGTH` stays 4. Additional hard caps are:

| Cap | Default |
|---|---|
| Distinct contracts | 8 |
| Cross-contract edges | 24 |
| Path expansion | 16 |
| Callback depth | 2 |

`clamp_protocol_bounds` and `clamp_bounds` only tighten. A planner cannot
raise them. Expansion is a deterministic breadth-first walk ordered by edge
kind: storage, asset movement, oracle, callback, authorization, delegatecall,
then ordinary calls. The walk keeps the exact edge-id sequence. Parallel
edges between the same nodes stay distinct, and the path id includes those
edge ids. It is not a random walk and it does not later search for some edge
from A to B.

`plan_protocol_calls` emits a call only when the function signature and the
argument generator can build it. A step may be `(contract, name)` in one
program or `(file, contract, selector)` across programs. Each file is resolved
from its own semantic program. A missing signature, an ambiguous overload, or
an unsupported argument rejects the whole plan. There is no placeholder call.

## Actors

`user`, `attacker`, `callback`, and `admin` are labels. `actor_privilege`
returns `established` only when semantic authorization is `established`.
The label itself grants nothing. A callback edge is not proof of
authorization. External callability is not attacker control.

## Economics

Protocol deltas go through the hardened Phase 46 layer. Attacker, victim,
and protocol amounts stay separated by actor, token, kind, transaction index,
snapshot, contract, and source. Observations from different states are not
treated as duplicates. A second token
without an explicit conversion is `unknown`. No USD price is invented. A
positive balance is not profit, and a loss is not a vulnerability. The
evidence kind is `economic_observation`. It cannot verify a finding.

Fee-on-transfer accounting requires a negative sender delta and a positive
receiver delta. Exact-transfer `balanced` requires the requested amount, the
sender decrease, the receiver increase, and any accounted amount to agree.
ERC-4626 preview checks are per operation and directional. A mismatch is not
automatically exploitable. Asynchronous vault semantics are unsupported
unless separately established, and even then they are not treated as ordinary
ERC-4626. Lending reconciliation is `incomplete` unless the semantics say
repayment is the only debt change, or every component (principal, interest,
fees, repayment, bad debt) is present. A debt drop by itself is not an
invariant violation.

## Events and traces

`correlate_modalities` matches static, runtime, and state-transition operation
identities only when those identities are equal, unambiguous, and carry both
a source marker and a signature. An event name is not a match. A bare function
name is not a match when the overload or source file is ambiguous. A match
stays a candidate. It does not prove the static property, and the economic
status stays an observation. A caller-supplied trace has an empty
executable-input field. A forbidden status such as `verified` is rewritten
to `candidate`.

ItyFuzz traces stay in stdout, stderr, and diagnostic metadata. They are not
`minimized_input` and they are not discovery-corpus seeds. Stdout and stderr
are parsed independently. ItyFuzz still cannot promote itself to reproduction
or verification.

## Scheduler

`missing_capability` can report `cross_contract_analysis` when the request
asks for protocol evidence and that capability has not been exercised.
`bugforge-protocol` is registered for that capability and is prepended only
then. `choose_next` returns the same capability for `cross-contract` or
`protocol` uncertainty. The default engine order does not change, and
BugForge does not run every installed engine. This is not the Phase 49
orchestrator. Missing tools stay unavailable. An unavailable or unsupported
result is not recorded as exercised evidence. Follow-up execution shares
`max_engines` with the initial selection. `target_from_static` keeps project, snapshot, compiler, campaign,
source file, target, contract, function, mode, and existing extra metadata.
Coverage keys include project, source snapshot, and compiler configuration,
so one build's coverage is not reused for another.

## Evidence

A protocol candidate carries project, source snapshot, compiler
configuration, contracts, function identities, edges, path, sequence, actors,
locations, engines, environment, assumptions, and uncertainty. Its status is
`candidate`. The discovery engine places that candidate on the normal evidence
lifecycle as `protocol_observation`. That provenance is not in the live
verification set. It cannot mark itself verified, proved, reproduced,
confirmed, safe, or exploited.

Static analysis, economic calculation, ItyFuzz, a sequence plan, and a
finished bounded expansion do not verify a vulnerability and do not prove
safety. Only the existing authorized verification and reproduction mechanisms
can set their existing statuses.

## Sandbox

Default operation is local. Phase 47 does not add a public RPC, a public
fork, live-target exploitation, bounty submission, wallet handling, or a host
process for untrusted target code. ItyFuzz remains Docker-only, with the
network disabled, bounded CPU, memory, and wall clock, and no image pull. If
the configured image is not local, the result is unavailable. Economic
calculation stays in-process. ScopeGuard, SafetyController, RateLimiter,
human approval, and evidence binding are unchanged.

## What remains unsupported

- Phase 49 adaptive multi-engine orchestration
- Phase 50 production bounty workflow
- Turning a protocol candidate into a runtime observation without a separate sandboxed execution
- Arbitrary dynamic-dispatch callees
- Treating a name match as a deployment or an address binding
- Invented prices, merged actor balances, or profit from a positive delta
- Proof that a candidate path is exploitable or that the absence of a path
  means the protocol is safe
- Asynchronous ERC-7540 vault accounting inside ordinary ERC-4626 checks
- Executable calls whose ABI arguments cannot be constructed
