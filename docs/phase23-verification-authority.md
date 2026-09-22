# Phase 23 — Verification authority and evidence provenance

Phase 23 closes the remaining trust gaps in the security-finding lifecycle.
It does not add a taint engine, a vulnerability family, or AI verification.

## One transition path

Production security findings live in `security_findings`.

```
static analysis
  → SecurityFinding.potential / corroborate
  → FindingLifecycleService.persist_static_scan
  → server-stamped evidence
  → correlate
  → SecurityFinding.reproduce / verify / human_accept / reject
  → merged persistence
```

`FindingLifecycleService` is the only production writer for later evidence
and status changes. It calls the domain methods. It does not assign
`FindingStatus`.

Research findings stay in `research_findings`. The research agent can
corroborate from a non-AI research observation and can reproduce only with
`positive_reproduction`. It cannot call `verify`.

## Finding identity

`finding_key` is still the stable static identity. It does not include the
line number or a parser byte offset. Whitespace around the same tokens keeps
the key. An identical call inserted earlier in the same scope still shifts
`sink_occurrence`. Spaces inside string literals are compacted out of the key.

## Server attribution

Only the lifecycle service stamps lifecycle identity, after it has loaded
the persisted finding. `strip_client_attribution` always removes:

```
finding_key
finding_id
execution_id
attribution
```

A client value of `attribution=server` is removed with the rest. Untrusted
metadata cannot select a finding. Pathless evidence without a server stamp
stays unattached. An unambiguous file, line, and vulnerability class can
still attach an observation, and the stored record does not keep the client
key.

Trusted matching order:

1. server finding key stamped from the loaded finding
2. server execution id already stored on that finding
3. normalized file, line, and vulnerability identity, with no competing peer
4. otherwise reject

## Evidence identity

`observation_identity` is kind, source, summary, details digest, artifact,
line, contradiction flag, execution id, and outcome. It does not include the
`Evidence` UUID. The same observation submitted twice is one record. A
different execution id or different details is a different observation.
Database reload preserves that identity, including `collected_at`. Provenance
is derived from kind, so a stored record cannot deserialize into a stronger
provenance than its kind allows.

## Corroboration

`corroborate()` requires evidence. One static observation stays `potential`.
Two copies of that observation stay `potential`. Static plus AI text stays
`potential`. Two distinct static or source observations become
`corroborated`. One non-AI research observation (HTTP, browser, scanner,
API, replay, fuzzing, proxy, or HTTP request) can corroborate. The operator
endpoint cannot invent that observation.

## Reproduction

`positive_reproduction` requires kind `REPRODUCTION` and an explicit result:

```
outcome = reproduced | consistently_reproduced | success | exploited
```

or `reproduced=true` with an empty or positive outcome.

These are not success:

```
not_reproduced
inconclusive
intermittent
blocked
timeout
environment_error
missing outcome
unknown outcome
reproduced=false
```

The reproduction collector maps `consistently_reproduced` to
`EvidenceKind.REPRODUCTION` and maps the failure classifications above to
`TEST_FAILURE`. A bare `Evidence(kind=REPRODUCTION)` does not reproduce.

## Independent verification

Two evidence events are independent when all of the following hold:

* the verification event's kind is HTTP response, browser, scanner, API
  test, replay, fuzzing, or proxy
* its `observation_identity` is not the identity of a positive reproduction
  record
* its `execution_id`, when set, is not a reproduction execution id

A new object id is not independence. The same bytes wrapped again are the
same observation. Reproduction execution A plus verification execution B
can verify. The same execution id cannot.

`SecurityFinding.verify()` and `SecurityFinding.verified()` use this rule.
Reproduction evidence alone cannot verify. A duplicate of that evidence
cannot verify.

`REPRODUCED` can be human-accepted. `VERIFIED` requires the independent
observation. Reloading a human-accepted row uses `verified()` when an
independent observation is stored, and `reproduce()` when the only success
record is the reproduction. A stored `verified` row still has to satisfy
`verified()`. A later contradiction stays attached and does not downgrade
`potential`, `reproduced`, `verified`, or `human_accepted`. The explanation
says the static result is kept and the stored lifecycle state stays.

## Concurrency and field ownership

Lifecycle saves start from the current row. Static location, flow, report
text, and existing AI analysis stay with that row. Empty fields may be
filled. Runtime evidence is the union by observation identity. Status keeps
the stronger value, and `rejected` stays terminal. `created_at` stays
original. Human review stays with the current row unless the incoming review
is set or the status becomes `human_accepted`.

PostgreSQL `SELECT FOR UPDATE` is covered by
`test_postgres_concurrent_evidence_updates`: two transactions merge
reproduction and verification evidence, and a second transaction blocks
while the first holds the row lock. SQLite still covers the merge function.

A refused transition flushes retained evidence in the service. The request
session commits that evidence and then returns 409. A caller that rolls the
session back does not keep the change. A project mismatch returns before
any write.

## Operator API

`POST /api/v1/security/projects/{project_id}/findings/{finding_id}/transition`
accepts only `operation`. `extra="forbid"` rejects `status`, `evidence`,
`finding_key`, `finding_id`, `execution_id`, `verified`, and `reproduced`.
The server loads the finding for the path project and evaluates evidence it
already stored.

## Phase 24 coverage input

This is an audit of the current static analyzer. Phase 23 does not implement
these gaps.

Supported taint classes, each as a potential or corroborated finding:

* SQL injection
* command injection
* potential path traversal
* SSRF
* XSS
* unsafe deserialization, with `JSON.parse` and similar APIs kept as
  `potential_unsafe_deserialization`
* dangerous dynamic execution
* unsafe redirect

Indicator classes, not source-to-sink findings:

* hard-coded secrets
* weak cryptography
* insecure configuration
* authentication comparisons and JWT `verify=False`
* CSRF explicitly disabled
* IDOR-style lookup without an adjacent ownership check

Languages with a security vocabulary: Python, JavaScript, TypeScript, Ruby,
Go, Java, PHP, C#, Kotlin, C, C++, Rust, Swift, shell, and markup/SQL
profiles. Python uses CPython AST. The others use Tree-sitter when the
grammar is installed and a profile fallback otherwise. Profile fallback is
not full semantic analysis. Go, Java, and Kotlin have local interprocedural
import following. Other languages are weaker across files.

Sanitizer coverage is narrow: HTML escaping and a few language-specific
encode/quote helpers. C, C++, Rust, Kotlin, Swift, shell, HTML, CSS, and SQL
vocabularies have empty or token-level sanitizer lists.

Strong framework routes require a proven constructor import for Flask,
FastAPI, and Express. Django, Rails, and Nest source patterns exist in
profiles. Local names that shadow those constructors are not routes.

Known false positives: test helpers, checksum hashes, example secrets,
trusted cache payloads, relative redirects, and debug settings in tests.

Known false negatives: path-insensitive flow, unresolved aliases, dynamic
dispatch, middleware authorization, runtime-built strings, open-redirect
allow-lists, and gadget chains behind `JSON.parse`.

`sink_occurrence` still shifts when an identical call is inserted earlier.
That is an identity limit, not a detection family.
