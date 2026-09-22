# Phase 22 — Production security lifecycle and evidence integrity

Phase 22 makes the evidence lifecycle the production path for security
findings. It does not add a taint engine, a new vulnerability family, or
AI verification.

```
Repository
  → static semantic analysis
  → potential / corroborated finding
  → FindingLifecycleService.persist_static_scan
  → evidence collection
  → server attribution from the loaded finding
  → FindingLifecycleService correlation
  → explicit domain transition
  → reproduced / verified
  → human review
```

`POST /api/v1/security/projects/{id}/analyze` and `AnalysisService` both
call `persist_static_scan`. That initial write may still be `potential` or
`corroborated`. Later evidence and every status change go through
`record_collected_evidence` or `attach_evidence`. Those methods load the
row, check project ownership, correlate, optionally call one domain method,
and merge the result. They do not assign `FindingStatus`.

Quality findings from the static analyzers stay on `FindingRepository`.
They are a different model and are not security findings.

## Attribution

Collectors do not trust a client-supplied finding key. When BugForge starts
collection for one persisted finding, `FindingLifecycleService` builds a
`ServerAttribution` from that row and stamps collector output. A forged
`attribution=server` stamp is stripped on `attach_evidence`.

Matching order:

1. trusted server finding key
2. server execution id already stored on that finding
3. exact normalized source location plus vulnerability identity
4. exact sink or source when enough context exists
5. otherwise reject

A file or line that disagrees with the finding is rejected even when a key
is present. HTTP responses, reproduction results, and test results may omit
a source path when the server stamp identifies one finding. Evidence that
does not identify exactly one finding stays unattached.

Competing findings are loaded with `competing_findings` for the same
project, vulnerability class, line, and normalized file. The paginated
project list is not the ambiguity set. A competitor past the first page
still blocks attachment.

If `project_id` is supplied, the loaded finding must belong to that
project. A mismatch raises `FindingProjectMismatchError` before correlation,
transition, or persistence. Omitting `project_id` is for internal callers
that already hold the finding id. The operator HTTP route always passes the
path project id and still requires operator authentication. The project id
is not authorization by itself.

## Reproduction and verification

`REPRODUCED` requires a positive reproduction record: kind `REPRODUCTION`,
reproduction provenance, and no failure or contradiction flag. A failed
test, log, screenshot, generated test, AI text, or contradictory result
does not reproduce. The reproduction collector emits `REPRODUCTION` only
for a successful result. Failures become `TEST_FAILURE`. Manual notes stay
logs. They are not reproduction evidence.

`VERIFIED` requires an independent observation whose kind is HTTP response,
browser, scanner, API test, replay, fuzzing, or proxy, and whose stable
evidence identity is not the reproduction record. The same reproduction
artifact cannot be reused as verification. One such observational event can
verify when it is not that reproduction record. The rule is explicit in
`independent_verification_items`.

`SecurityFinding.verify()` still requires verification-compatible
provenance for database round-trips and direct domain use. Production
verification goes through the lifecycle service, which applies the stricter
independence rule before calling `verify()`.

Contradictory evidence stays attached when it identifies the finding. It
does not verify, erase earlier evidence, or delete the row. A later
contradiction does not downgrade `VERIFIED` or `HUMAN_ACCEPTED`. Rejection
is an explicit `reject()` transition.

A refused transition still saves evidence that correlated. The status does
not change.

## Concurrency and rescans

Lifecycle saves lock the row on PostgreSQL (`SELECT FOR UPDATE`) and merge
evidence by stable evidence identity. Identity is kind, source, summary,
details digest, artifact, line, contradiction flag, execution id, and
outcome. It is not the generated UUID. The same observation is not stored
twice. Distinct details stay distinct. A stale writer cannot drop the other
writer's evidence or replace a stronger status with `potential`. `rejected`
stays terminal. SQLite tests prove the merge. They do not take a PostgreSQL
row lock.

A rescan reconciles on `(project_id, finding_key)`. It refreshes static
location and flow fields and replaces static evidence. It keeps runtime
evidence, human review, and protected status. `analysis_id` is the latest
scan that observed the finding, not a historical store.

## Operator API

`POST /api/v1/security/projects/{project_id}/findings/{finding_id}/transition`
accepts `{"operation": "corroborate"|"reproduce"|"verify"|"human_accept"|"reject"}`.
Extra fields, including `status`, are rejected. The server uses evidence it
already stored. Responses include `status`, `evidence_tier`, and
`human_review_state`. The findings panel shows those statuses and labels
potential, corroborated, and reproduced results as not verified.

## Research agent

Research findings stay in `research_findings`. Promotion uses the same
`positive_reproduction` predicate and `dataclasses.replace`. The agent
cannot call `verify`. It does not write `security_findings`, so it is not a
second persistence model for production security findings.

## Migration 022

`022_phase20_finding_key` canonicalizes legacy keys inside the migration
file. It does not import `finding_identity` or the repository. Runtime code
still uses `finding_identity` for column and JSON agreement.

## Identity guarantee

`sink_occurrence` is the count of earlier same-scope calls with the same
callee and whitespace-insensitive argument shape. The shape includes
literal-versus-expression, callees, accesses, and identifiers already on
the semantic graph. Line numbers and parser byte offsets are not part of
the key. Byte offsets are used only to order identical shapes inside one
scope.

What stays stable:

- formatting whitespace around the same tokens
- a harmless call with different argument text, such as `eval("constant")`
  before `eval(request.args.get("q"))`
- the same call text in different scopes

What is not stable:

- inserting another call with the same shape earlier in the scope
- renaming a callee or changing an argument token
- an alias the resolver has not already rewritten to the same callee
- spaces inside string literals, because the key compacts the snippet

## Known limits

- Direct `SecurityFinding.verify()` can still accept reproduction provenance.
  The production transition does not.
- Research sessions are not automatically copied into `security_findings`.
- SQLite does not provide the PostgreSQL row lock. The merge still applies.
- `analysis_id` records the latest observing scan only.
- Occurrence identity shifts when an identical call is inserted earlier.
