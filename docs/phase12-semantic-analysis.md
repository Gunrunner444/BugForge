# Phase 12 — Deep semantic analysis

Phase 12 extends the Phase 11 flow-sensitive taint model. It does not add a
second dataflow engine. Static observations remain `POTENTIAL` or
`CORROBORATED`. They are never `VERIFIED`.

## What is supported

Python, JavaScript, and TypeScript graphs with `parser_tier=full_ast` only.

* Unique module-level functions.
* Argument index mapping, including a receiver shift for Python `self` / `cls`.
* Return summaries, including `str`, `format`, `sprintf` / `Sprintf`, and `c_str`.
* Re-exports when every hop is unique: Python `from pkg import name` through
  `__init__.py`, and JavaScript/TypeScript `export { name } from "./mod"`.
* Alias and namespace imports (`import helpers`, `import * as helpers`).
* Methods when the class is uniquely imported and the receiver is
  `instance.method(...)`, `Class.method(...)`, or `Class().method(...)`.
* `@staticmethod` and `@classmethod` when the decorator is written in source.
* Kind-specific sanitizer summaries. An HTML sanitizer does not clear `eval`
  or SQL.
* Whole-value container flow: if a dict, list, or object binding is tainted,
  a later use of that name is tainted. Keys and indexes are not tracked.
* Branch merges stay conservative and are labeled `merge:` / `branch_merge=true`.
  The analysis is not path-sensitive.

Stable edge identifiers are `file::symbol`. They do not use memory addresses.

## What is not supported

* Third-party or unresolved modules. No guessed implementations.
* Star imports and `export *`.
* Dynamic imports, `getattr`, and other computed names.
* Inheritance and dynamic dispatch. Two methods with the same name are not
  the same method.
* Partial, truncated, or profile-fallback callees. Those files are not
  cross-file summaries. The walk is marked incomplete.
* Key-sensitive heap analysis.
* Arbitrary wrappers. An unknown call does not preserve taint.
* Path-sensitive pruning of dead branches.

Other languages stay intra-file. R, Scala, Dart, Lua, and Elixir stay
detection-only.

## Limits

| Setting | Effect when reached |
|---|---|
| `taint_max_files` | Later files are omitted. Local findings in the kept files remain. |
| `taint_max_import_depth` | Deeper call summaries are not exported. |
| `taint_max_cross_file_rounds` | `0` runs no round. Exhausting the fixpoint records `cross_file_incomplete`. |
| `taint_max_cross_file_edges` | Stops before another edge. `0` exports nothing. |
| `taint_cross_file_budget_ms` | `0` or a timeout stops before further propagation. |

Same-file analysis uses `MAX_TAINT_ROUNDS`, `MAX_INTERPROC_DEPTH`, and
`MAX_DEFINITIONS` in `app/security/taint.py`. A depth cap that still added an
edge marks the taint state incomplete instead of calling the result complete.

Diagnostics and semantic ids are sorted. The same repository content produces
the same observations, diagnostics, and edge ids.

## Security invariants

Static analysis and AI still cannot verify findings, approve them, change
scope, bypass ScopeGuard, SafetyController, or rate limits, or submit
HackerOne reports. Repository code is not executed to produce these results.
Profile fallback is not advertised as AST or dataflow.
