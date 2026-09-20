# Language capability and test matrix

This matrix records what BugForge **actually tests** after the polyglot
parity work. A checked cell means a dedicated assertion exists, not merely
that a source file is present.

Parser backend:

| Language | Graph builder | Quality static analysis |
|---|---|---|
| Python | CPython AST (`python_graph.py`) | Yes (`python_analyzer.py`) |
| JavaScript / TypeScript | Profile scanner (`extract.py`) | Yes (`javascript_analyzer.py`) |
| Ruby, C, C++, Go, Rust, Java, PHP, Kotlin, Swift | Profile scanner | No (security analysis only) |
| Detection-only set | None | No |

The profile scanner is string-aware and comment-aware. It is **not** a full
language AST. Remaining limitations: no preprocessor/macros, weak nested
generics, intra-procedural taint only, and regex literals after a division
operator can still be ambiguous.

## Analysis languages

| Language | detect | parse | imports | entities | bindings | calls | malformed | sources | SQL | cmd | path | SSRF | XSS | deser | eval | redirect | crypto | frameworks | negatives | parser edges |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Python | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | Django/Flask/FastAPI | yes | AST tests |
| JavaScript | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | Express/Next/React | yes | yes |
| TypeScript | yes | yes | yes | yes | yes | yes | yes | yes | yes | via JS | via JS | yes | via JS | via JS | yes | via JS | via JS | NestJS/TSX | yes | typed syntax |
| Ruby | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | profile | profile | profile | profile | profile | yes | profile | Rails/Sinatra sources | yes | comments |
| C | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | unsupported | unsupported | unsupported | unsupported | unsupported | profile | n/a | yes | brace-next-line |
| C++ | yes | yes | yes | yes | yes | yes | yes | yes | via C | via C | yes | unsupported | unsupported | unsupported | unsupported | unsupported | profile | n/a | yes | classes |
| Go | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | profile | yes | profile | profile | unsupported | profile | profile | net/http | yes | import block |
| Rust | yes | yes | yes | yes | yes | yes | yes | yes | profile | yes | yes | profile | profile | profile | unsupported | profile | profile | n/a | yes | impl/enum |
| Java | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | profile | profile | profile | profile | profile | yes | profile | servlet | yes | call chains |
| PHP | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | profile | profile | yes | profile | yes | profile | profile | superglobals | yes | `#` comments |
| Kotlin | yes | yes | yes | yes | yes | yes | yes | yes | profile | yes | profile | yes | profile | profile | unsupported | profile | profile | Ktor-style | yes | fun/object |
| Swift | yes | yes | yes | yes | yes | yes | yes | yes | yes | profile | profile | profile | unsupported | profile | profile | unsupported | profile | n/a | yes | class/struct/enum/actor |

`via JS` means TypeScript reuses the JavaScript profile sinks; dedicated TS
tests cover SQL, SSRF, eval, and NestJS sources. `profile` means the
vocabulary exists and is covered by the generic profile-support contract,
with additional language-suite tests where listed as `yes`.

`unsupported` is an explicit empty sink tuple. Tests assert the category is
not implemented rather than inventing detections.

## Detection-only languages

C#, Shell, YAML, JSON, TOML, Markdown, reStructuredText, HTML, CSS, SCSS,
SQL, R, Scala, Dart, Lua, Elixir: detection and (where applicable) `SOURCE`
only. Contract tests assert `parse_file` / `analyze_file` raise
`UnsupportedCapabilityError`.
