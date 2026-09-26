# Phase 44 — project-aware stateful verification and replay

Phase 44 turns one candidate path into a bounded transaction sequence and,
where the sequence can be encoded, a Foundry test. It does not add heuristic
detectors. A sequence is not a finding. A passing test is not a proof.

## Sequence

`prepare_replay` builds a `TransactionSequence` of at most four steps.
`sequence_limit` accepts a smaller cap and ignores a larger one. Each step
records the contract, function, caller, typed arguments, value, source
location, and the call text. Setup is separate: a parameterless `new Contract()`, or no harness when the
constructor has arguments. `initialize` is not added as setup. A mint-style
candidate does not call it. A sequence step that is already `initialize`
is emitted as that step.

Actors are `attacker` for a reentrancy path, `owner` for an authorization
path, and `user` otherwise. The attacker permission is `caller`, not
`owner`.

Arguments are one literal per parameter: `1` for integers, `address(1)`,
`true`, or `bytes32(0)`. Other types are `unsupported`. No combination
search is performed.

## Harness

`encoded` requires an equality or monotonic predicate, publicly readable
variables, externally callable functions, and a unique deployment. The
assertion is the candidate relation, on the line after
`// BUGFORGE_ASSERTION <specification hash>`, reverting with
`bugforge-fail:<specification hash>`. There is no `assertTrue(true)` and no
`vm.store`.

A reentrancy path is encoded only when the function is public or external,
parameterless, not payable, contains `msg.sender.call`, and the
specification carries an equality or monotonic predicate. The test calls
`attacker.attack()`. The reentrant call is in `receive()`, not a second
call from the test.

Oracle paths stay `unsupported` with environment `environmental/model`. No
oracle is replaced. Proxy and upgrade paths stay `unsupported` because
proxy, implementation, admin, and initializer are not established together.
Cross-contract sequences are `unsupported`. Fork replay returns
`unavailable` and does not contact public infrastructure.

## Project

If the source has a parent `foundry.toml`, the harness imports the analyzed
file and execution copies a bounded snapshot with
`prepare_foundry_workspace`. The user's tree is not modified. `.env` is not
copied. Lines in the copied `foundry.toml` that look like keys, mnemonics,
or passwords are dropped. An import that does not resolve to a file inside
that project is `unsupported`. There is no fallback to a toy project when a
Foundry root exists.

Without a Foundry root, a self-contained source is compiled in an isolated
temporary project that sets only `src`, `test`, and empty `libs`. Imports
without a project are `unsupported`.

## Results

`classify_output` never returns `reproduced`. `promote` returns
`reproduced` only for a bound `candidate_violation` from execution `forge`
in environment `real-target`. Simulated runners stay
`candidate_violation`. `executed_no_violation` is not `proved_safe`.
`compile_failed`, `setup_failed`, `unavailable`, and `timeout` stay
themselves.

`binds_replay` recomputes the manifest digest and a binding over the path,
specification hash, harness digest, source digest, project id, compiler
configuration, dependency id, and sequence id. Changing any of those
invalidates the binding. Evidence is reproduction only for a bound Foundry
`reproduced` result. `lifecycle_effect` is `none`.

## Not claimed

Argument literals are placeholders, not protocol-valid inputs. Authorization
replay does not impersonate an owner. Oracle, proxy, and fork candidates
are not executed as real-target reproductions. A unit test that supplies
runner output is simulated. Live Forge tests run only when `forge` is on
`PATH`. No LLM API is called from this layer.
