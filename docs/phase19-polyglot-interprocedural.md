# Phase 19 — Polyglot interprocedural analysis

Phase 19 extends the existing repository semantic graph. It does not add a
second taint engine. A language is included only where Tree-sitter already
records an import path and a function or class identity that a test can
resolve to one local file.

## Supported

Go:

- `import "helpers"` binds `helpers.Func` when exactly one `helpers.go` is in the scan
- `import h "proj/helpers"` binds `h.Func` when the package identifier and the quoted path are separate syntax nodes and `proj/helpers.go` is unique
- Dot imports (`. "..."`) and blank imports (`_ "..."`) are not edges
- Import paths that contain a dot, such as a third-party host, are not mapped onto the repository

Java:

- `import pkg.Helper` binds the class or function `Helper` when exactly one `pkg/Helper.java` contains that name
- `import static ...` is not an edge

Kotlin:

- `import pkg.run` binds the function or class `run` when exactly one `pkg/run.kt` contains that name
- `import pkg.run as runCode` uses the alias as the local name

Argument and return flow, sanitizers, and partial-callee rejection are the same summary rules used for Python. An HTML escape does not clear a command sink. Profile fallback graphs are not eligible.

## Not supported

These stay unresolved. The parser may still see the text, but BugForge does not invent a file edge:

- Ruby `require` and `require_relative` (the receiver of the later call is not a stable qualified name)
- C# `using` (a namespace, not a source file)
- Swift `import` (a module, not a source file)
- Go module graphs, `go.mod`, and vendor lookup
- Java classpaths, Kotlin aliases through calls, and star imports
- Inheritance and dynamic dispatch

Static findings from these flows remain `POTENTIAL` or `CORROBORATED`. They are not `VERIFIED`.
