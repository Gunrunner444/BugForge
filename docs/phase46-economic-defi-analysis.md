# Phase 46: economic and DeFi analysis

Phase 46 asks whether a bounded transaction sequence changes assets in a way
the semantic model can describe. It is an evidence layer. It is not a protocol
simulator, not an EVM, and not an exploit generator for live protocols.

Development is on `main` only. There is no phase branch and no stacked phase
pull request. Cursor is the planner. BugForge does not call a model API for
this analysis, and `llm_invoked` stays false in Cursor-controlled mode.

## What it can establish

Given observations that already name a token, an actor, a unit, and an amount,
BugForge can record:

- a state snapshot and a before/after delta
- native ETH, ERC-20, share, debt, reserve, fee, and actor-specific deltas
- net change as final assets minus initial assets, explicit costs, explicit
  fees, and explicit repayments
- a cross-asset figure only when a typed conversion is supplied
- flash-loan principal as an obligation rather than attacker-owned profit
- ERC-4626 rounding, and a preview relation only for a named operation
  (`previewDeposit`, `previewMint`, `previewWithdraw`, `previewRedeem`,
  `convertToShares`, `convertToAssets`) using that operation's rounding direction
- a donation or inflation effect when an execution observation exists
- a fee-on-transfer discrepancy when transfer semantics were established and
  the sender decrease is negative and the receiver increase is positive
- an oracle dependency when a state write is tied to the oracle input
- a constant-product reserve observation when that model was established
- a lending relation when the debt-changing operations were established
  (`repayment-only` or `with-interest`); otherwise the result stays incomplete
- an event correlation that stays distinct from static semantics

Allowed oracle statuses are `potential_positive_delta`, `potential_loss`,
`invariant_violation`, `balanced`, `non_profitable`, `unknown`, `unsupported`,
and `incomplete`.

## What it cannot establish

- that a positive delta is an exploit, or that a loss is a vulnerability
- that a contract is safe, verified, proved, or exploited
- a USD price, or a comparison of USDC with ETH, unless a conversion source
  is explicit
- that every vault is ERC-4626, every pair is Uniswap, or every price feed is
  manipulable
- that a fuzzer result or a static relationship is verification
- live exploitation, a public fork, or a public RPC call

Unknown stays unknown. A passing test is not a proof of safety. A reproduced
Foundry observation is still not mathematical proof. Only the existing
reproduction lifecycle can promote bound Foundry evidence, and it does not
promote an economic oracle by itself.

## Execution

Economic analysis runs in-process. It does not shell out, and the default path
does not open a network connection. An in-process calculation is not a protocol
execution: `executed` stays false, provenance is `economic-calculation`, and
caller-supplied amounts are `externally-supplied` observations. They are not
runtime evidence, reproduction evidence, or execution evidence. A dedicated
`economic_observation` evidence kind cannot satisfy verification by itself.

Numeric parsing does not raise. Malformed, negative (where a magnitude is
required), or overflow-like values become `unknown`, `unsupported`, or
`incomplete`.

Observations are bound to project, target, source snapshot, compiler
configuration, sequence, contract, function when one was named, transaction
index, actors, tokens, snapshots, deltas, conversion provenance, oracle
provenance, source location, engine, and environment. Missing bindings
downgrade the result to `incomplete`. Strings in `request.extra` cannot relabel
themselves as runtime facts.

ItyFuzz campaigns use the existing Docker executor: network disabled, bounded
CPU, memory, and wall clock, a minimal environment, a read-only working
directory, and a writable scratch mount. The setting is
`security_agent_ityfuzz_image`. If it is empty, or Docker cannot see that
image locally, the status is `UNAVAILABLE`. Host ItyFuzz is not a fallback,
and BugForge does not pull an image. A textual trace stays in stdout or
diagnostic metadata. It is not `minimized_input` and it is not inserted into
the executable discovery corpus. Stdout and stderr are parsed separately, so
a banner in either stream is kept.

The adapter targets the fuzzland/ityfuzz off-chain stdout interface inspected
on 2026-09-28 (`ityfuzz-stdout-v1`): local `.abi` and `.bin` files, the
`Found vulnerabilities` banner, Description and Trace sections, and
non-finding Stats, corpus, and coverage logs. JSON is not treated as a
finding. The command is an argv array. ItyFuzz interprets the artifact glob.

Replay through Docker is `forge-sandbox`. That identity can become
`reproduced` only when the generated harness, specification, source, project,
dependency, compiler configuration, and sequence all match, the fail token
matched, and the run was the controlled Foundry execution. A simulated runner
cannot.

## Sequences and budgets

An economic action is emitted only when the function exists and the semantic
model established that action. A prefix such as donate, swap, borrow,
withdraw, or permit is an executable `PlannedCall` only when the parser or
ABI supplies a signature and bounded arguments. Otherwise it stays an
abstract hypothesis and is not inserted as a call. `clamp_bounds` still only
tightens limits. Follow-up runs share `max_engines` with the initial
selection. An economic strategy cannot raise that budget or the exploration
caps.

The scheduler selects the missing capability: economic simulation, fuzzing,
symbolic execution, Foundry execution, or static analysis. It does not run
every engine on every target.

Feedback refinement is a fixed table. A share-balance observation can justify
a later withdraw only when withdraw is established. There is no model call.

## Benchmarks

`ECONOMIC_BENCHMARKS` documents local fixture families: Damn Vulnerable DeFi,
ERC-4626 scenarios, SmartBugs Curated, and operator-supplied historical
fixtures. Every entry is local-only. A normal scan does not download them and
does not contact a public RPC.

## Evidence

`EconomicEvidence` is built on the engine path. It binds the project, target,
sequence, contract, function identity, actors, tokens, states, deltas,
conversion, oracle, invariant, status, assumptions, source locations, engine,
tool version, environment, source snapshot, and compiler configuration.
`bound` is false when any required field is missing, and the public status
becomes `incomplete`. A forbidden conclusion status is stored as `unknown`.
