# Polyglot analysis

Phase 11 makes BugForge’s polyglot analysis flow-sensitive and honest about
parser fallback. The security engine never depends on a specific parser. Every
backend fills the same `SyntaxGraph`.

## Architecture

```
source code
    → native syntax tree (CPython AST or Tree-sitter)
        → normalized SyntaxGraph (entities, imports, calls, bindings, scopes, spans)
            → lexical scopes + definition versions
                → flow-sensitive taint (not path-sensitive)
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

Taint is **flow-sensitive** and **not path-sensitive**.

* Sequential reassignment replaces the reaching definition: `q = input; q = "safe"; sink(q)` is not tainted.
* Branch/loop assignments merge conservatively: if either path may taint `q`, later uses stay tainted.
* Sibling function scopes never share locals. Nested `let`/`const` (JS/TS) and block-scoped declarations are distinct symbols.
* Same-file inter-procedural propagation maps actual arguments onto the matching formal parameter, and only when the callee is uniquely resolved.
* Sanitizers apply only when a callee of the relevant argument has a sanitizer kind that matches the sink (HTML encoding does not sanitize SQL).
* Static analysis never claims a demonstrated directory escape. Path findings are `user_controlled_path`, `unsafe_path_construction`, or `possible_path_traversal`.

## Security vs code quality

Security rules emit `SecurityObservation` records. Status is `POTENTIAL` or
`CORROBORATED` — never `VERIFIED` from static analysis, taint, or AI.

Code quality rules use `Finding.catalog = code_quality`. The UI labels them
**CODE QUALITY**, separate from **SECURITY**.

Every full-analysis language has a syntax-aware quality catalog. Quality rules
are language-appropriate (unwrap in Rust, `goto` in C, `var`/`==`/`with` in JS)
and do not duplicate security sinks.

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

Parse size, walk nodes, nesting, taint rounds, and same-file inter-procedural
depth are hard-capped. Truncated or erroneous parses remain visible in
diagnostics; they are not reported as clean analysis.

## Known limitations

* Taint is not path-sensitive and not inter-file.
* Ambiguous same-named callees are not linked.
* PHP `echo`/`print` XSS requires HTML output context.
* Generic APIs (`Write`, `send`, `JSON.parse` as code-exec) are not treated as
  those vulnerability classes.
* AI context is advisory and cannot verify, approve, change scope, or submit
  HackerOne reports.
