# Phase 39 — path-sensitive Solidity dataflow

Phase 39 is a bounded, deterministic value-flow layer on the parser semantic IR.
It is not sound, not fully semantic, and not verification.

## Model

Each state occurrence is classified from the statement that contains it:

- read
- write
- read-modify-write

Scalar names and indexed paths are both operations. `balances[user1]` and
`balances[user2]` stay different paths. Declaration identity stays on the base
variable. A parameter or local with the same name is not that state variable.
A local declared in a nested block does not hide a state write outside that block.

Unknown symbol resolution stays unknown. Overloads are not chosen by name.

## Provenance

Values use `attacker`, `state`, `external`, `oracle`, `authority`,
`trusted_constant`, `derived`, and `unknown`. Unknown is not safe. A delegatecall
target is attacker only when the expression is a parameter or message field,
state when it loads storage, derived when it is a call result, and unknown for
a conditional or unresolved expression.

## Queries

`reads_before_call` and `writes_after_call` use source order around one call id.
A short function name resolves only when exactly one summary has that name.
A missing or ambiguous id returns no facts, which is unknown, not safe.

## Limits

Function count, access/block count, call depth, fixed-point iterations, value
count, and edge count stop the analysis and set an incomplete reason.

## Not modeled

Compiler SSA, symbolic key equality, full inheritance resolution, Yul expression
provenance, and Foundry profile execution. Compiler profiles match normalized
source paths, not basenames. `solc`, `forge`, and `semgrep` are used only when
installed. Semgrep hits stay untrusted static evidence.

## Authority

Semantic dataflow does not verify a finding. Chain verification does not treat
a graph `lifecycle` field or a finding id that merely equals an evidence id as
authority.
