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
- ERC-4626 rounding and preview relations when those semantics were established
- a donation or inflation effect when an execution observation exists
- a fee-on-transfer discrepancy when token semantics say a fee is possible
- an oracle dependency when a state write is tied to the oracle input
- a constant-product reserve observation when that model was established
- a lending or liquidation relation when debt, repayment, and health are known
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
does not open a network connection.

ItyFuzz campaigns use the existing Docker executor: network disabled, bounded
CPU, memory, and wall clock, a minimal environment, a read-only working
directory, and a writable scratch mount. The setting is
`security_agent_ityfuzz_image`. If it is empty, the status is `UNAVAILABLE`.
Host ItyFuzz is not a fallback, and BugForge does not pull an image.

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
model established that action. Mutations cover amounts, order, actor, and a
few justified prefixes such as a donation before conversion. `clamp_bounds`
still only tightens limits. An economic strategy cannot raise `max_engines`
or the exploration caps.

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

`EconomicEvidence` binds the project, target, sequence, actors, tokens,
states, deltas, conversion, oracle, invariant, status, assumptions, source
locations, engine, tool version, environment, source snapshot, and compiler
configuration. A forbidden conclusion status is stored as `unknown`.
