# Phase 14 — Field-sensitive dataflow

Phase 14 extends the existing taint engine with bounded, constant field paths.
It is not a heap analysis and not a second dataflow engine. Static observations
remain `POTENTIAL` or `CORROBORATED`. They are never `VERIFIED`.

## What flows

A field path is its own symbol when every step is a static attribute, a
constant identifier-like string key, or a constant non-negative index:

| Expression | Symbol |
|---|---|
| `obj.payload` | `obj.payload` |
| `obj["payload"]` | `obj["payload"]` |
| `items[0]` | `items[0]` |
| `obj.a.b` | `obj.a.b` |

`eval(obj.payload)` is tainted only when that path's reaching definition is
tainted. A different field, a different index, or a different object is not.

A tainted container still taints a use of the container itself. `obj = source`
followed by `eval(obj["other"])` stays tainted because the base value is
tainted. That is whole-value behavior, not a guess that every field is the
source.

## What stays unresolved

- Computed keys: `data[key]`, `obj[user_supplied_key]`
- Dynamic attributes and reflection
- A field read in a callee when the caller passed the whole object
- Two instances that happen to use the same field name
- Conditional aliases and names that are assigned more than once
- Dictionary or call results used as the object (`alias = obj["x"]`, `alias = factory()`)

Unknown stays unknown. A dropped field fact is not rewritten into an all-key alias.

## Aliases

`alias = obj` copies field facts between those names only when all of the
following hold:

- `alias` is assigned exactly once
- the assignment is not conditional
- the right-hand side is a single plain name
- each hop toward the root was assigned no later than the hop that captured it

The copy becomes visible at the later of the field write and the alias
assignment. `taint_max_alias_edges` bounds the hops and the number of names
updated. Zero disables alias copies. The field binding itself (`eval(alias.payload)`
after `alias.payload = source`) does not need an alias.

## Sanitizers and reassignment

Sanitizer kinds stay vulnerability-specific. `html.escape` on `obj.payload`
clears XSS uses of that path and does not clear `eval`, and it does not clear
`obj.other`.

A later literal assignment clears only that path from that program point.
The inverse order taints only the later use.

## Limits

| Setting | Default | Zero |
|---|---|---|
| `taint_max_field_depth` | 4 | field flow disabled |
| `taint_max_field_bindings` | 2000 | no field facts recorded |
| `taint_max_alias_edges` | 32 | no alias copies |

Negative values are rejected. When a path is deeper than the depth limit, or
when a file has more field definitions than the binding cap, that definition
is not recorded. Earlier findings on other paths are kept. Observations from
that file include `analysis_incomplete` (`field depth limit`, `field binding
limit`, or `field alias limit`). A capped later write is not applied, so a
sanitizer past the cap does not clear an earlier fact. The incomplete flag is
the signal that the result is partial.

## Languages

Python records these paths from the CPython AST. JavaScript and TypeScript
record `member_expression` and `subscript_expression` paths from Tree-sitter.
Other languages are not given speculative field paths. Profile fallback is not
field-sensitive dataflow.

## Cross-file

Cross-file field flow uses the existing summaries. It applies when the value
that crosses the file is the field expression itself (`helper(obj.payload)`,
`return obj.payload`) and the callee is already a unique, complete summary.
Passing `obj` and reading `.payload` in another function is not modeled.
Partial callees still do not become complete summaries.
