# Phase 40 — cross-contract security flow

Phase 40 is bounded static analysis. A property result is not a finding and
not verification.

## Value graph

Each load, store, local, and call uses an operation id that includes the
source span. Two identical `balances[user]` loads are different nodes.
Dependency edges are kept only when both endpoints are nodes in the value
graph.

## CFG

Each function is analyzed on the existing CFG. Block environments map locals
to value ids and are joined from predecessors until they stabilize or the
iteration limit is reached. A limit marks the summary incomplete.

`reads_before_call` and `writes_after_call` mean **may**: a read that can
reach the call, or a write the call can reach. They are not must-on-all-paths
facts.

## Properties

`analyze_reentrancy`, `analyze_authorization`, `analyze_delegatecall`, and
`analyze_asset_flow` return `potential`, `satisfied`, `unknown`, or
`incomplete`. Unknown means the analysis did not establish the property. It
does not mean the code is safe.

## Not modeled

Symbolic aliasing, full library and inheritance dispatch, compiler SSA, and
proofs of value conservation. External contracts without a local summary stay
unknown. `solc`, `forge`, and `semgrep` are optional and were not required to
build these facts.

## Authority

Semantic results may support a potential observation. They cannot verify a
finding, raise an evidence tier, or replace FindingLifecycleService.
