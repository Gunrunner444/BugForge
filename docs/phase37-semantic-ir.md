# Phase 37 — Solidity semantic IR

The semantic IR is analysis data. It does not verify findings. Cursor remains the only planner. No second model provider was added.

## Authority fixes from Phase 36

- `assess_chain` only records a proposal. A caller-supplied evidence id or tier cannot verify a chain.
- `verify_chain` reads the session evidence graph. The node must belong to that session and project. Reproduction stays reproduced. Static and scanner provenance stay static. `verified` requires provenance `execution` or `reproduction` plus lifecycle `verified` on the graph node.
- Restoring a chain snapshot forces `proposed` unless the chain was rejected.
- Storage comparisons require the proxy source to name the implementation contracts. A delegatecall elsewhere does not pair unrelated contracts. An unresolved target is incomplete, not a collision.
- Methodology findings match contract, exact function name, and source line.
- Compiler groups no longer assign unpinned or conflicting sources to `0.8.34`. Those sources are omitted and the project model is `INCOMPLETE`. Mixed groups keep a profile per version instead of pretending one compiler compiled every file.
- `foundry.toml` optimizer, via-IR, EVM version, and solc fields are read as text and included in the configuration cache identity. The file is not executed.
- Hypothesis ids stay in `related_ids`. They are not stored as observation ids.
- Semgrep local scans must resolve inside the authorized repository root. A binary name is available only when it is on `PATH` or is a real file.
- OOB availability comes from the provider. The default provider is unavailable. There is still no interactsh client, and the ledger is not persisted across process restarts.

## Semantic IR

`build_semantic_program` reads the Tree-sitter syntax graph.

Implemented from the parser:

- contract and function identity, including line
- visibility, modifiers, and a guarded/unguarded/unknown authorization mark
- state reads and writes for names declared as state variables
- low-level external calls found in the function text
- a deterministic text snapshot

Unavailable unless a compiler profile says otherwise:

- compiler IR, IR AST, and SSA
- transient storage layout from the compiler
- bytecode source maps

`compiler_ir_status` is `unavailable` when no compiler IR was supplied. Parser facts are marked `origin=parser`. Partial programs stay `partial`.

Solidity detectors that walk functions use this identity set, so `withdraw` is not `withdrawAll`. Accounting comparison also unions those semantic write sets with the older coupled-name check. Storage collision, reentrancy, and signature rules still use their existing syntax-graph logic and now ignore functions the IR cannot name.

## Not claimed

- Full ERC-4626 or flash-loan proofs
- Compiler SSA
- Forge inside the exploratory image
- Public-network transactions
- Semgrep as a live network scanner
