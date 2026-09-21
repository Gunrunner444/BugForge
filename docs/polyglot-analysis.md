# Polyglot analysis

Phase 10 makes BugForge’s programming-language analysis syntax-aware. The
security engine never depends on a specific parser. Every backend fills the
same `SyntaxGraph`.

## Architecture

```
LanguageAdapter
    → SyntaxParser (registry lookup by language id)
        → Tree-sitter CST  or  CPython AST  or  labeled profile fallback
            → normalized SyntaxGraph
                → scope-aware data flow
                → SecurityRule catalog
                → CodeQualityRule catalog
```

Python keeps CPython `ast` as the primary backend (`parser_backend=cpython_ast`,
`parser_tier=full_ast`). Other analysis languages use Tree-sitter
(`parser_backend=tree_sitter`). Grammars are cached once per process. Source
size and walk depth are bounded.

The regex profile scanner (`parse_with_profile`) is **not** the primary backend.
If a Tree-sitter grammar cannot be loaded, the adapter reports
`PROFILE_FALLBACK` instead of pretending to have a full AST.

## Capability tiers

| Tier | Meaning |
|---|---|
| `FULL_AST` | Real syntax tree, entities with end spans, scope-aware symbols |
| `SPECIALIZED` | Real syntax for HTML/CSS/SQL; not application-language taint parity |
| `PROFILE_FALLBACK` | Regex/profile scanner; never advertised as AST |
| `DETECTION_ONLY` | Extension mapping only |

## Security vs code quality

Security rules emit `SecurityObservation` records. Status is `POTENTIAL` or
`CORROBORATED` — never `VERIFIED` from static analysis.

Code quality rules (`mutable_default_argument`, `js_loose_equality`, …) use
`Finding.catalog = code_quality`. The UI labels them **CODE QUALITY**, separate
from **SECURITY**.

## Taint

Symbols are `scope_id::name`. `function A`’s `q` is not `function B`’s `q`.
Sources and sinks are matched on syntax nodes (calls, member access,
identifiers). String literals and comments cannot become sources or sinks.
Template interpolations remain code.

Path sinks emit `potential_path_traversal` with
`path_issue_kind=possible_path_traversal`. Static analysis never claims a
demonstrated directory escape. `JSON.parse` emits
`potential_unsafe_deserialization` (indicator), not confirmed gadget execution.

## Languages

Full analysis (Tree-sitter or CPython): Python, JavaScript, TypeScript, Ruby,
C, C++, Go, Rust, Java, PHP, Kotlin, Swift, C#, Shell.

Specialized: HTML, CSS, SCSS, SQL.

Detection-only: YAML, JSON, TOML, Markdown, reStructuredText, R, Scala, Dart,
Lua, Elixir.

## Tests

- Language contract: `tests/test_analyzers/test_language_contract.py`
- Cross-language semantic corpus: `tests/test_phase10/test_polyglot_native.py`
- Lexical fixtures (raw strings, heredocs, templates): `tests/test_phase10/test_lexical_fixtures.py`
- False-positive corpus: comments, strings, parameterization, sibling scopes

Unsupported categories (for example SSRF in C) are asserted as unsupported
rather than faked.

## Known limitations

- Inter-procedural taint is limited to unique same-file callees.
- Macros and preprocessor expansion are not modeled.
- A recognized sanitizer lowers confidence; it is only treated as effective
  when the vocabulary marks it `effective=True`.
- Framework detection is advertised only for registries covered by tests.
