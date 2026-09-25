# Phase 38 — Solidity semantic dataflow

Phase 38 hardens the parser-backed semantic IR and adds a bounded dataflow
layer. It is **partial**. It is not fully semantic, not sound, and not a
verifier.

## States

| Capability | State |
| --- | --- |
| Read and write of the same state variable | implemented |
| Declaration identity from parser symbols | partial |
| Mapping, array, and member access paths | partial |
| Authorization from CFG and resolved modifiers | partial |
| Path status from the existing CFG | implemented |
| Internal and external call sites | partial |
| Explicit function-limit incompleteness | implemented |
| Source spans on semantic objects | partial |
| Compiler profiles attached by identity | partial |
| Standard JSON optimizer, viaIR, EVM version | implemented |
| Unpinned import closure | partial |
| Proxy pairing without a named implementation | removed |
| Chain verification via existing lifecycle | implemented |
| Typed lead hypothesis, finding, and semantic ids | implemented |
| Local Semgrep ruleset | implemented |
| Intraprocedural and bounded interprocedural dataflow | partial |
| Compiler SSA | unavailable |
| Forge | unavailable unless the host binary is present |

Unknown is not safe. A hypothesis is not a finding. Static evidence is not
verification. Planner reasoning is not authority.

## False negatives recorded in this phase

* A state update such as `totalAssets -= amount` was previously only a write.
* A proxy beside exactly one other contract was previously treated as that
  contract's implementation.
