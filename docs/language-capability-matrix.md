# Language capability and test matrix

This matrix records what BugForge **actually implements and tests**. Parser
backend is taken from runtime diagnostics, not README claims. Security-family
status (`tested`, `existing-suite`, `limited`, `unsupported`) lives in
`backend/app/security/coverage.py` and is the source of truth. Phase 26
fixtures cover JavaScript, TypeScript, Go, Java, Kotlin, PHP, C#, Ruby, and
Rust. A `tested` cell means a dedicated security fixture, not only a parser
test. Cross-file taint remains Python and JavaScript/TypeScript only.

Parser backend:

| Language | Graph builder | Parser tier | Quality |
|---|---|---|---|
| Python | CPython AST (`python_graph.py`) | FULL AST | Yes (`python_analyzer.py`, CODE QUALITY) |
| JavaScript / TypeScript | Tree-sitter | FULL AST | Yes (`javascript_analyzer.py` + quality catalog) |
| Ruby, C, C++, Go, Rust, Java, PHP, Kotlin, Swift, C#, Shell | Tree-sitter | FULL AST | Yes (language-appropriate quality catalog) |
| HTML, CSS, SCSS, SQL | Tree-sitter | SPECIALIZED | Format-specific security only |
| Detection-only set | None | DETECTION ONLY | No |

The regex profile scanner is a labeled **PROFILE FALLBACK** only. It is not
equivalent to Tree-sitter or CPython AST analysis. Status fields distinguish
`native_parser_available`, `native_parser_unavailable`, `profile_fallback_used`,
and `parser_failure`.

Taint is flow-sensitive at the use site (not a file-final symbol map) and not
path-sensitive. Same-file inter-procedural analysis maps arguments by index
when the callee is unique, and stops with an explicit incomplete state when the
interprocedural depth bound is still producing new edges. Cross-file analysis
adds bounded import edges for Python and JavaScript/TypeScript full-AST graphs
only: one unique local module, module-level functions, unique re-exports
(`__init__.py`, `export { name } from`), and methods of a uniquely imported
class. No third-party guessing, no star-import edges, no profile-fallback
dataflow, and no summary from a partial callee. Other full-analysis languages
stay intra-file. R, Scala, Dart, Lua, and Elixir stay detection-only.

## Analysis languages

| Language | detect | parse | AST | imports | entities | scopes | calls | data flow | malformed | sources | SQL | cmd | path | SSRF | XSS | deser | eval | redirect | crypto | quality | negatives |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Python | yes | yes | CPython | yes | yes | yes | yes | flow-sensitive | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| JavaScript | yes | yes | Tree-sitter | yes | yes | nested | yes | flow-sensitive | yes | yes | yes | yes | yes | yes | yes | indicator JSON.parse | yes | yes | yes | yes | yes |
| TypeScript | yes | yes | Tree-sitter | yes | yes | nested | yes | flow-sensitive | yes | yes | yes | yes | yes | yes | yes | indicator | yes | yes | yes | yes | yes |
| Ruby | yes | yes | Tree-sitter | yes | yes | yes | yes | flow-sensitive | yes | yes | yes | yes | yes | yes | yes | yes | eval (not `send`) | yes | yes | yes | yes |
| C | yes | yes | Tree-sitter | yes | yes | block | yes | flow-sensitive | yes | yes | yes | yes | yes | unsupported | unsupported | unsupported | unsupported | unsupported | yes | yes | yes |
| C++ | yes | yes | Tree-sitter | yes | yes | block | yes | flow-sensitive | yes | yes | yes | yes | yes | unsupported | unsupported | unsupported | unsupported | unsupported | yes | yes | yes |
| Go | yes | yes | Tree-sitter | yes | yes | block | yes | flow-sensitive | yes | yes | yes | yes | yes | yes | `template.HTML` only | indicator json | unsupported | yes | yes | yes | yes |
| Rust | yes | yes | Tree-sitter | yes | yes | block | yes | flow-sensitive | yes | yes | yes | yes | yes | `reqwest::get` | `Html::from_string_unchecked` only | indicator plus `bincode::deserialize` | unsupported | `Redirect::to` | yes | yes | yes |
| Java | yes | yes | Tree-sitter | yes | yes | block | yes | flow-sensitive | yes | yes | yes | yes | yes | yes | HTML context only | tainted `ObjectInputStream` argument | yes | redirect (not XSS) | yes | yes | yes |
| PHP | yes | yes | Tree-sitter | yes | yes | yes | yes | flow-sensitive | yes | yes | yes | yes | yes | yes | HTML context | yes | yes | yes | yes | yes | yes |
| Kotlin | yes | yes | Tree-sitter | yes | yes | block | yes | flow-sensitive | yes | yes | yes | yes | yes | yes | yes | yes | unsupported | yes | yes | yes | yes |
| Swift | yes | yes | Tree-sitter | yes | yes | block | yes | flow-sensitive | yes | yes | yes | yes | yes | yes | unsupported | yes | yes | unsupported | yes | yes | yes |
| C# | yes | yes | Tree-sitter | yes | yes | block | yes | flow-sensitive | yes | yes | yes | yes | yes | `GetAsync` / `WebRequest.Create` | `Html.Raw` | local `Deserialize` is a gap | unsupported | yes | yes | yes | yes |
| Shell | yes | yes | Tree-sitter (bash) | yes | yes | yes | yes | flow-sensitive | yes | yes | unsupported | eval/bash | files vs source | yes | unsupported | unsupported | eval | unsupported | unsupported | yes | yes |

`unsupported` means the vocabulary is empty and tests assert the category is
not implemented.

Path findings are `potential_path_traversal`. Static analysis does not emit
demonstrated directory escape.

Each sink records `dangerous_condition`, `safe_alternatives` when known, and
`required_context` when a generic API is only dangerous in a specific output
or HTML context. Unrelated sanitizer kinds cannot suppress a finding.

## Specialized formats

HTML: script and event-handler sinks. CSS/SCSS: `expression()` / `javascript:`
indicators. SQL: dangerous statements (`DROP`, `EXECUTE`) in SQL files. These
are not full application taint engines.

## Detection-only languages

YAML, JSON, TOML, Markdown, reStructuredText remain detection-only (config/docs).

R, Scala, Dart, Lua, Elixir: grammars exist in `tree-sitter-language-pack` but
BugForge does **not** claim FULL_AST or analysis parity. They stay
`DETECTION_ONLY` until quality rules, taint vocabularies, and fixtures exist.
Contract tests assert `parse_file` / `analyze_file` raise
`UnsupportedCapabilityError`.

## Solidity

Solidity is not in the generic taint table above. Its parser is Tree-sitter
when the bundled grammar loads (`FULL_AST`, backend `tree_sitter`). If that
parser cannot load, the file is `PROFILE_FALLBACK` and Solidity security rules
do not run. The capability matrix uses `YES`, `LIMITED`, `UNSUPPORTED`, and
`UNAVAILABLE_AT_RUNTIME`. Same-file call/state order is `LIMITED` data flow.
Compiler storage layout is not claimed. Selectors are emitted only when every
parameter type canonicalizes, including same-file structs whose fields are
known. A parse error does not receive a guessed selector. External Foundry,
Slither, Echidna, Medusa, Halmos, and Wake capabilities follow the installed
binary and stay `UNAVAILABLE_AT_RUNTIME` when it is absent. See
[phase28-solidity-deep-analysis.md](phase28-solidity-deep-analysis.md).
