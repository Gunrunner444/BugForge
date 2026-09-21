# Phase 17 — Incremental analysis

Phase 17 adds an in-memory parse index so a second scan of the same files
does not parse them again. It does not add a second taint engine or a second
semantic graph.

`analyze_incremental` reuses a `SyntaxGraph` only when all of these match:

- repository-relative path
- SHA-256 of the file text
- parser identity (`language:backend:tier:phase17-v1`)
- analysis-limit identity

The limit identity covers file-size and taint limits, including field depth,
field bindings, alias edges, import depth, and the cross-file budget. It does
not include `secret_key` or `ai_api_key`. Changing a secret does not force a
reparse. Changing a taint limit does.

After graphs are loaded, BugForge always rebuilds the repository semantic
graph and runs the security rules. An incremental result for the same files
matches `SecurityAnalysisEngine.analyze_repository` on observations,
diagnostics, semantic edges, resolved callees, and finding status, title,
vulnerability class, and location. Finding ids and timestamps are not part of
that identity.

## Invalidation

Editing one file reparses that file. The other cached graphs stay. The next
rule pass sees the edited graph, so a sink removed from a helper disappears
from the caller, and an unrelated method sink remains.

A syntax error is cached with the graph that reports it. The parser-error
diagnostic is emitted again on a cache hit. A partial or truncated graph is
never treated as a complete summary; that rule is unchanged from Phase 13.

If the parser that actually ran does not match the adapter's claimed parser
id, the record is stored under the actual id and will not be reused as the
claimed parser.

## What is not cached

These names are parsed when a security adapter accepts them, and they are
never stored in the index:

- `.env` and names starting with `.env`
- `id_rsa`, `id_dsa`
- `credentials.json`, `secrets.json`
- `*.pem`, `*.key`, `*.p12`, `*.pfx`

The index is process-local. It is not written to disk. It does not store
authorization tokens or live HTTP responses. Cache keys do not contain
timestamps, process ids, or object addresses.

## Limits

The index does not skip semantic-graph construction or security rules. Those
passes stay bounded by the existing taint limits. A zero or negative limit is
still rejected or disables that propagation, as in earlier phases.

Static findings from this path remain `POTENTIAL` or `CORROBORATED`. They are
not `VERIFIED`.
