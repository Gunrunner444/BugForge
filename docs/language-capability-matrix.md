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
`UNAVAILABLE_AT_RUNTIME`. Same-file call/state order, the intra-procedural CFG,
and intra-procedural def-use are `LIMITED`. The CFG is not a compiler CFG:
unknown braces stay unknown, and an unknown graph is not treated as proof that
a path is safe. A guard counts only when it dominates the operation.
Selectors are emitted only when every parameter type canonicalizes, including
same-file enums (`uint8`), user-defined value types, contract types
(`address`), and structs whose fields are known. A name defined in exactly one
other file can be resolved by `unique_abi_aliases`; a repeated name stays
unresolved. A parse error does not receive a guessed selector. ABI tuples are
dynamic only when a component is dynamic. `solc` and `forge` are optional. When
they are absent, compiler storage layout is `UNAVAILABLE` and is not invented.
External Foundry, Slither, Echidna, Medusa, Halmos, and Wake capabilities follow
the installed binary and stay `UNAVAILABLE_AT_RUNTIME` when it is absent.
A DeFi layer classifies token calls, share/asset conversions, ERC-4626-style
flows, rounding direction, slippage bounds, oracle valuations, lending and AMM
relationships, permit binding, and token-callback ordering. That layer is
`LIMITED`: it is not a model of every protocol, and it does not treat a method
name or a modifier name as proof.
Storage layout, inheritance order, delegatecall targets, and upgrade
authorization are also `LIMITED`. The parser assigns slots only when the types
and the base contracts are known. An ambiguous base or an unknown type leaves
the slot unknown. A compiler layout, when a real standard-JSON result is
supplied, is kept beside the parser layout; a disagreement is recorded and is
not silently resolved. Yul `sload` and `sstore` link to a slot only when the
argument is a literal or a constant with a literal value. This is not
compiler-equivalent layout, not EVM symbolic execution, and not a certificate
that a proxy implements UUPS, EIP-1967, or a diamond. Static Solidity findings
stay potential evidence. Cross-contract and cross-function summaries are also
`LIMITED`: ambiguous callees stay ambiguous, unresolved calls stay unresolved,
and a bound leaves the model incomplete rather than safe. Namespaced storage
is isolated from sequential slots only for the deterministic forms BugForge
recognizes. Exploratory generated tests are not a Solidity proof.

Vyper is detection-only. BugForge does not claim a native Vyper AST. Slither
may analyze Vyper when the `slither` executable is installed; that external
result is still potential evidence.

Go, Rust, and C/C++ can hand a target to `go test`, `cargo test`, or a local
clang/AFL harness. Those bridges report `LIMITED` or `UNAVAILABLE_AT_RUNTIME`.
They do not mark a finding verified. See
[phase28-solidity-deep-analysis.md](phase28-solidity-deep-analysis.md),
[phase29-cfg-runtime-and-ci.md](phase29-cfg-runtime-and-ci.md), and
[phase30-solidity-semantic-reinforcement.md](phase30-solidity-semantic-reinforcement.md)
and
[phase31-solidity-defi-semantic-analysis.md](phase31-solidity-defi-semantic-analysis.md)
and
[phase32-solidity-proxy-storage-upgradeability.md](phase32-solidity-proxy-storage-upgradeability.md).
