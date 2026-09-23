# Phase 29 — audit, Solidity CFG, runtime bridges, and CI

Phase 29 audits Phase 28 before adding surface area. External tools and static
rules still produce evidence. They do not set a finding to verified.

## Audit fixes

Foundry and Medusa no longer treat a passing run, or the mere presence of a
coverage percent, as new coverage. `coverage_percent`, `coverage_delta`,
`new_coverage`, `coverage_available`, and `coverage_source` are separate.
The scheduler compares a percent only with a percent it already observed for
that engine, or with an explicit tool comparison. A first sample is not
"new".

Process execution records `started`, `timed_out`, `return_code`, `stdout`,
`stderr`, and `available`. A missing binary, a spawn failure, a timeout, and
a non-zero exit are different. Adapters do not treat exit 127 as the only
way a process can fail to start.

Assertion, property, symbolic counterexample, sanitizer, and crash results
keep an evidence kind and an oracle type. `verified` stays false.

## Solidity

ABI dynamic classification is recursive. `(uint256,address)` is static.
`(string,address)` and `(uint256[],address)` are dynamic. Fixed arrays follow
their element type.

Same-file structs are indexed before function selectors, including structs
that appear after a contract when their fields can be resolved. Ambiguous
imported names stay unresolved.

A lightweight intra-procedural CFG models straight-line statements, `if` /
`else`, loops, `return`, `revert`, `require`, and `unchecked` blocks. A guard
counts only when it dominates the sensitive operation. An external call and a
later state write are a reentrancy candidate only when a path connects them.
An internal call is not, by itself, reentrancy.

Loop findings are split: `sol.unbounded_loop` requires an external call.
`sol.unbounded_state_loop` is a storage write. A fixed-size array is not
reported as unbounded. Oracle freshness follows an actual `latestRoundData`
or `latestAnswer` call. A name, comment, or string does not create a finding.

Foundry commands are `forge build`, `forge test`, `forge coverage`, and a
fuzz or invariant run only when a real test name is known. A generic
`forge test` is not labeled as fuzzing. Echidna prefers JSON. A passing
property campaign means no counterexample in that run, not a proof. Halmos
uses `--match-test` for a Foundry-style test and returns `NOT_IMPLEMENTED`
when the target is not one. Slither keeps each element that has a source
location.

## Other languages

Vyper is registered for detection. Native parsing and native security rules
stay unsupported. Slither's language set includes Vyper when that executable
exists.

Go test, Cargo test, native coverage fuzzing, and sanitizer builds are
registered adapters. They run only when the tool is installed and the request
names a real target or harness. Otherwise the result is `UNAVAILABLE` or
`NOT_IMPLEMENTED`.

## CI

`.github/workflows/required-ci.yml` runs on every pull request. Backend and
frontend suites run only when those trees change. The stable check name is
`Required CI`. Documentation-only pulls still pass the gate. A failed relevant
job fails the gate. Path-filtered backend and frontend workflows are not
themselves required, because a filtered workflow can stay pending.

The tools `slither`, `forge`, `echidna`, `medusa`, `halmos`, and `wake` were
not installed in the environment that produced this phase. Tests do not mock
them as successful.
