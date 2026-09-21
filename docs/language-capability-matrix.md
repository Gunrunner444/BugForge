# Language capability and test matrix

This matrix records what BugForge **actually implements and tests** after Phase
10. A checked cell means a dedicated assertion exists. Parser backend is taken
from runtime diagnostics, not README claims.

Parser backend:

| Language | Graph builder | Parser tier | Quality |
|---|---|---|---|
| Python | CPython AST (`python_graph.py`) | FULL AST | Yes (`python_analyzer.py`, CODE QUALITY) |
| JavaScript / TypeScript | Tree-sitter | FULL AST | Yes (`javascript_analyzer.py`, syntax events, CODE QUALITY) |
| Ruby, C, C++, Go, Rust, Java, PHP, Kotlin, Swift, C#, Shell | Tree-sitter | FULL AST | Security analysis; no extra quality catalog |
| HTML, CSS, SCSS, SQL | Tree-sitter | SPECIALIZED | Format-specific security only |
| Detection-only set | None | DETECTION ONLY | No |

The regex profile scanner is a labeled **PROFILE FALLBACK** only. It is not
equivalent to Tree-sitter or CPython AST analysis.

## Analysis languages

| Language | detect | parse | AST | imports | entities | scopes | calls | data flow | malformed | sources | SQL | cmd | path | SSRF | XSS | deser | eval | redirect | crypto | frameworks | negatives |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Python | yes | yes | CPython | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | Django/Flask/FastAPI | yes |
| JavaScript | yes | yes | Tree-sitter | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | indicator JSON.parse | yes | yes | yes | Express/Next/NestJS | yes |
| TypeScript | yes | yes | Tree-sitter | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | indicator | yes | yes | yes | NestJS | yes |
| Ruby | yes | yes | Tree-sitter | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | Rails/Sinatra | yes |
| C | yes | yes | Tree-sitter | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | unsupported | unsupported | unsupported | unsupported | unsupported | yes | n/a | yes |
| C++ | yes | yes | Tree-sitter | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | unsupported | unsupported | unsupported | unsupported | unsupported | yes | n/a | yes |
| Go | yes | yes | Tree-sitter | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | indicator json | unsupported | yes | yes | Gin/Echo/Fiber | yes |
| Rust | yes | yes | Tree-sitter | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | indicator | unsupported | yes | yes | Actix/Axum/Rocket | yes |
| Java | yes | yes | Tree-sitter | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | Spring/Servlet | yes |
| PHP | yes | yes | Tree-sitter | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | Laravel/Symfony | yes |
| Kotlin | yes | yes | Tree-sitter | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | unsupported | yes | yes | Ktor | yes |
| Swift | yes | yes | Tree-sitter | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | unsupported | yes | yes | unsupported | yes | Vapor | yes |
| C# | yes | yes | Tree-sitter | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | n/a (grammar only) | yes |
| Shell | yes | yes | Tree-sitter (bash) | yes | yes | yes | yes | yes | yes | yes | unsupported | yes | yes | yes | unsupported | unsupported | yes | unsupported | unsupported | n/a | yes |

`unsupported` means the vocabulary is empty and tests assert the category is
not implemented.

Path findings are `potential_path_traversal`. Static analysis does not emit
demonstrated directory escape.

## Specialized formats

HTML: script and event-handler sinks. CSS/SCSS: `expression()` / `javascript:`
indicators. SQL: dangerous statements (`DROP`, `EXECUTE`) in SQL files. These
are not full application taint engines.

## Detection-only languages

YAML, JSON, TOML, Markdown, reStructuredText, R, Scala, Dart, Lua, Elixir:
detection and (where applicable) `SOURCE` only. Contract tests assert
`parse_file` / `analyze_file` raise `UnsupportedCapabilityError`.
