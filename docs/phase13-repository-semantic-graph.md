# Phase 13 — Repository semantic graph

Phase 13 extends the Phase 11/12 semantic model. It does not add a second
dataflow engine. Static observations remain `POTENTIAL` or `CORROBORATED`.
They are never `VERIFIED`. High confidence means a unique static identity, not
a verified exploit.

Repository code is not executed to build the graph. TypeScript configuration
is read as JSON. It is never evaluated.

## Symbol identity

Every semantic id is `file::module::class::symbol`, using repository-relative
paths and `/` separators.

| Kind | Example |
|---|---|
| Function | `pkg/helpers.py::pkg.helpers::::run_code` |
| Method | `pkg/helpers.py::pkg.helpers::Executor::run` |
| Class | `pkg/helpers.py::pkg.helpers::Executor::` |

`__init__.py` uses the package directory as the module name. Two files, two
classes, or a function and a method do not share an id. Ids do not contain
memory addresses, `id()`, or randomized hashes. Parsing the same files twice
produces the same ids.

## Edge kinds

| Kind | Meaning | Counts against `taint_max_cross_file_edges` |
|---|---|---|
| `import` | Named import of a unique function | Yes |
| `default` | Default import of a unique function | Yes |
| `re_export` | The defining file is not the imported file | Yes |
| `alias` | A name assigned once to a unique callable | Yes |
| `class_import` | Unique class import | Yes |
| `call` | A call site that uses one of the bindings above | Yes |
| `method_owner` | Method belongs to its class | No |

An import edge is not itself a taint edge. Taint follows `call` edges whose
callee summary has a sink or a return effect. Unresolved and ambiguous names
produce a diagnostic and no edge.

## Supported import forms

Python, only when one repository file matches:

* `import helpers` and `from helpers import run_code`
* `from .helpers import run_code`, `from . import helpers`
* packages and nested packages via `__init__.py`
* aliases (`from helpers import run_code as go`)
* re-export chains through `__init__.py`, bounded by `taint_max_import_depth`

JavaScript and TypeScript, only for local files already in the scan:

* `import { name } from "./mod.js"` and `import { name as local } from "./mod.js"`
* `import * as ns from "./mod.js"`
* `import name from "./mod.js"` when `mod` has one default-exported function or class
* `export { name } from "./mod.js"` and `export { name as other } from "./mod.js"`
* `import { name as local } from "./mod.js"` followed by `export { local as public }`
* extensionless specifiers that match exactly one of
  `.js`, `.jsx`, `.mjs`, `.ts`, `.tsx`, `index.js`, `index.jsx`, `index.mjs`,
  `index.ts`, `index.tsx`

If both `helpers.js` and `helpers.ts` match, or a file and an index file
match, the import is ambiguous. BugForge does not prefer one extension.

Default export forms that resolve:

```javascript
export default function runCode(value) { eval(value); }
function runCode(value) { eval(value); }
export default runCode;
export default class Executor { run(value) { eval(value); } }
```

`export default function (value) {}` and two different default exports do not
resolve.

## TypeScript path aliases

Checked-in `tsconfig.json` is parsed with `json.loads`. Comments, `extends`,
and JavaScript config files are not supported. A comment makes the file
invalid JSON, so aliases stay unresolved.

A mapping is used only when `compilerOptions.paths` gives that pattern exactly
one string target. `baseUrl` is prefixed. One `*` in the pattern is substituted
into one `*` in the target. The rewritten path must be one local source file
under the same suffix rules as relative imports. Two matching patterns or two
matching files are ambiguous. Targets that leave the repository or enter
`node_modules` are ignored. Unmapped bare specifiers stay unresolved and are
not looked up in a package registry.

## Callable aliases and callbacks

```python
from helpers import run_code
alias = run_code
alias(user_input)
```

The same shape works for a same-file function (`callback = helper`) and for a
single JavaScript `const alias = runCode` binding. The alias is followed only
when all of these hold:

* the name is assigned exactly once
* the right-hand side is one identifier, not a call, attribute, or subscript
* every call of that name is in the same scope as the assignment
* the identifier is one function or class

A later assignment drops the alias. An assignment inside a branch is not an
alias. `getattr`, `eval`, dictionary lookups, and computed attributes are not
followed. A default export whose name is reassigned after the export is
unresolved.

## Methods

These resolve when the class is unique:

* `obj = Executor(); obj.run(user_input)`
* `Executor().run(user_input)` and `new Executor().run(user_input)`
* `Executor.run(Executor(), user_input)`
* `@staticmethod` and `@classmethod` written in source

The receiver shift is the same as Phase 12: Python `self` / `cls` moves the
user argument by one, except `@staticmethod`. JavaScript methods have no
implicit parameter. Inheritance may appear in source, but a subclass does not
inherit a call target. Two unrelated classes with `run` stay distinct.
`method_owner` records method-to-class identity and is not a call.

## Async

`await helper(user_input)` and `return helper(value)` use the callee that the
parser already recorded. Taint is preserved only when that callee is a unique
function with a summary. An unknown `await` does not preserve taint. A later
assignment such as `result = "safe"` clears the value at the next use. This is
not a general model of promises, callbacks passed into libraries, or
framework schedulers.

## Summaries

Cross-file observations include:

* `defining_file`, `defining_symbol`
* `caller_file`, `caller_symbol` when the call is inside a function or method
* `parameter_index`, `callee_line`, `cross_file_depth`
* `parser_complete`, `relationship`, `re_export`, `class_method`
* `semantic_id`

`relationship` is `import`, `default`, `re_export`, `alias`, or `method`.
Same-file aliases use `taint_scope=alias`. Other resolved calls use
`taint_scope=cross_file`.

## Limits

`0` disables that step. Negative values are rejected by `Settings`. A
`CrossFileLimits` built directly clamps negatives to `0`. Zero never indexes
the file list and never creates a semantic edge.

| Setting | Zero |
|---|---|
| `taint_max_files` | No cross-file files, edges, or callees |
| `taint_max_import_depth` | No import, re-export, or alias hop |
| `taint_max_cross_file_rounds` | No propagation round |
| `taint_max_cross_file_edges` | No budgeted edge. The check happens before the next edge is kept |
| `taint_cross_file_budget_ms` | Stop before propagation |

A positive file cap keeps the first N paths in sorted order and records
`cross_file_incomplete`. A re-export or alias hop that remains after
`taint_max_import_depth` iterations records `cross_file_depth_limited` and
does not invent the missing hop. A positive edge cap keeps at most N budgeted edges
(`call` first, then alias, default, import, re-export, class import) and drops
callees whose call edge was not kept. Same-file `MAX_INTERPROC_DEPTH` still
marks the file incomplete when a further hop was added on the last allowed
round. An incomplete walk is not a clean repository. Local findings in files
that were analyzed remain.

## Intentionally unsupported

* `export *` and Python `import *`
* dynamic `import()`, `importlib.import_module`, and `getattr`
* third-party packages and `node_modules` resolution
* ambiguous package suffixes (`one/pkg/helpers.py` and `two/pkg/helpers.py`)
* default exports whose identity is anonymous or conflicting
* reassigned callable aliases
* inheritance dispatch, duck typing, monkey-patching, and metaclasses
* computed exports and arbitrary higher-order functions
* `tsconfig` comments, `extends`, and multi-target `paths` entries
* path-sensitive branch pruning
* treating static analysis as exploit verification
