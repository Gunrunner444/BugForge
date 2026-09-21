# Polyglot analysis

Phase 13 keeps BugForge’s polyglot analysis flow-sensitive and honest about
parser fallback. The security engine never depends on a specific parser. Every
backend fills the same `SyntaxGraph`, and cross-file reasoning uses one
repository semantic graph rather than a second dataflow engine.

## Architecture

```
source code
    → native syntax tree (CPython AST or Tree-sitter)
        → normalized SyntaxGraph (entities, imports, calls, bindings, scopes, spans)
            → lexical scopes + definition versions
                → flow-sensitive taint at the use site (not path-sensitive, bounded interprocedural)
                    → argument-aware sources / sanitizers / sinks
                        → static security hypothesis + evidence
```

Python keeps CPython `ast` as the primary backend (`parser_backend=cpython_ast`,
`parser_tier=full_ast`). Other full-analysis languages use Tree-sitter
(`parser_backend=tree_sitter`). Grammars are loaded from the pinned
`tree-sitter-language-pack` (tested with `tree-sitter==0.26.0` and
`tree-sitter-language-pack==1.20.0`). Analysis never downloads grammars from
the network.

## Runtime parser truth

Installed capability (`parser_tier_for`, `/security/status`) reports whether a
native grammar is available in this process.

Each parsed file reports the parser that **actually** ran:

| Graph field | Meaning |
|---|---|
| `parser_backend` | `cpython_ast` / `tree_sitter` / `profile` |
| `parser_tier` | `full_ast` / `profile_fallback` / `specialized` |
| `diagnostics.status` | `native_parser_available` / `native_parser_unavailable` / `profile_fallback_used` / `parser_failure` |

The regex profile scanner is **only** an explicitly labeled fallback. Fallback
graphs never advertise `AST`, `SCOPE_ANALYSIS`, or `DATA_FLOW`. Fallback is not
equivalent to native analysis.

## Capability tiers

| Tier | Meaning |
|---|---|
| `FULL_AST` | Real syntax tree, entities with end spans, nested lexical scopes |
| `SPECIALIZED` | Real syntax for HTML/CSS/SQL; not application-language taint parity |
| `PROFILE_FALLBACK` | Regex/profile scanner; never advertised as AST |
| `DETECTION_ONLY` | Extension mapping only |

## Taint precision

Taint is **flow-sensitive at the use site** and **not path-sensitive**.
Bounded same-file inter-procedural analysis applies only when the callee is
uniquely resolved.

* A sink uses the definition reaching that call's source position. Later
  reassignments of the same name do not taint an earlier sink, and an earlier
  tainted definition still taints a sink that occurs before a later safe write.
* Sequential reassignment replaces the reaching definition: `q = input; q = "safe"; sink(q)` is not tainted.
* Branch/loop assignments merge conservatively: if either path may taint `q`, later uses stay tainted.
* Sibling function scopes never share locals. Nested `let`/`const` (JS/TS) and block-scoped declarations are distinct symbols.
* Same-file inter-procedural propagation maps actual arguments onto the matching formal parameter, and only when the callee is uniquely resolved.
* Cross-file propagation is bounded and only for Python, JavaScript, and TypeScript full-AST graphs. A local import must resolve to exactly one repository file. Callees may be a unique module-level function, a unique re-export of one, or a method whose class identity is unique. Ambiguous names, unresolved third-party modules, star imports, profile fallback, and partial callee graphs produce no edge.
* An unknown call does not pass taint through to its result. `b = forward(q)` is tainted only when `forward` is uniquely resolved and its return flows from that argument or from a source.
* Sanitizers apply when a callee of the relevant argument at that call has a matching sanitizer kind, or when the reaching definition is the result of a known effective sanitizer. HTML encoding does not sanitize SQL or `eval`. A later assignment replaces that definition.
* Static analysis never claims a demonstrated directory escape. Path findings are `user_controlled_path`, `unsafe_path_construction`, or `possible_path_traversal`.

## Security vs code quality

Security rules emit `SecurityObservation` records. Status is `POTENTIAL` or
`CORROBORATED` — never `VERIFIED` from static analysis, taint, or AI.

Code quality rules use `Finding.catalog = code_quality`. The UI labels them
**CODE QUALITY**, separate from **SECURITY**.

Every full-analysis language has a syntax-aware quality catalog. Quality rules
are language-appropriate and do not duplicate security sinks:

| Language | Representative quality rules |
|---|---|
| Python | mutable defaults, bare except (CPython AST) |
| JavaScript / TypeScript | `==`, `var`, `with` (mode-aware), `debugger` |
| Ruby | empty `rescue`, shadowing, `for`/`in` |
| C / C++ | `gets`/`strcpy`/`sprintf`, `goto` |
| Go | `panic`, discarded `_` results |
| Rust | `unwrap`/`expect`, `panic!` |
| Java | empty catch, `printStackTrace` |
| PHP | empty catch, `mysql_query` |
| Kotlin / Swift | force-unwrap |
| C# | empty catch, `goto` |
| Shell | unquoted `$var`, POSIX `[` |

## Languages

Full analysis: Python, JavaScript, TypeScript, Ruby, C, C++, Go, Rust, Java,
PHP, Kotlin, Swift, C#, Shell.

Specialized: HTML, CSS, SCSS, SQL.

Detection-only: YAML, JSON, TOML, Markdown, reStructuredText, R, Scala, Dart,
Lua, Elixir. Tree-sitter grammars exist for R/Scala/Dart/Lua/Elixir in the
language pack, but they are **not** promoted: BugForge does not yet have a
quality catalog, taint vocabulary, or fixture matrix that meets the analysis
contract. Detection-only is explicit, not implied support.

## Parser installation

```bash
cd backend
pip install -e ".[dev]"
```

`tree-sitter` and `tree-sitter-language-pack` are pinned to a tested compatible
range in `pyproject.toml`. Grammars for official languages are bundled in the
pack. If a grammar is missing at runtime, analysis uses labeled profile fallback
or reports `parser_failure` — it does not fetch parsers from the network.

## Configuration

`LANGUAGE_ANALYZERS` is a comma-separated list of language ids that implement
`STATIC_ANALYSIS` (code quality). Empty means every adapter that actually
implements static analysis (Python plus every full-analysis language with a
quality catalog). Detection-only languages cannot be enabled this way.

## Limits

Parse size, walk nodes, nesting, taint rounds, same-file inter-procedural
depth, and cross-file files/import depth/edges/time are hard-capped
(`taint_max_files`, `taint_max_import_depth`, `taint_max_cross_file_rounds`,
`taint_max_cross_file_edges`, `taint_cross_file_budget_ms`). Hitting a cap
records a diagnostic (`cross_file_incomplete`, `cross_file_depth_limited`, or
`cross_file_partial`) and marks the project walk incomplete. A zero round,
edge, or time budget does not run an extra step. Truncated or erroneous
callee graphs are not exported as summaries. Same-file taint that stops at
`MAX_INTERPROC_DEPTH` while a further hop was still being added sets
`analysis_incomplete` on observations from that file.

## Known limitations

* Taint is not path-sensitive. A branch merge that keeps taint is labeled `merge:` and `branch_merge=true`.
* Cross-file taint is limited to uniquely resolved Python and JavaScript/TypeScript functions, default exports, re-exports, once-assigned callable aliases, and methods in the same repository. TypeScript `paths` are read from JSON `tsconfig.json` only. Inheritance and dynamic dispatch are not guessed. Container uses taint the whole value, not a specific key or index. Unknown calls do not preserve taint. `str`, `format`, `sprintf`/`Sprintf`, and `c_str` do.
* Ambiguous same-named callees are not linked.
* PHP `echo`/`print` XSS requires HTML output context.
* Generic APIs (`Write`, `send`, `JSON.parse` as code-exec) are not treated as
  those vulnerability classes.
* AI context is advisory and cannot verify, approve, change scope, or submit
  HackerOne reports.
