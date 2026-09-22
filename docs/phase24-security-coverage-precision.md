# Phase 24 — Security coverage, precision, and verification trust

Phase 24 finishes the remaining evidence-trust gaps from the Phase 23 audit
and tightens the existing security detectors. It does not replace the parser,
the taint engine, or the lifecycle service. Static analysis still creates
only `potential` or `corroborated` findings. AI analysis still cannot verify.

## Remaining Phase 23 trust fixes

Phase 23 stripped client `finding_key`, `finding_id`, `execution_id`, and
`attribution` before correlation. `SecurityFinding.verify()` still accepted
an observational kind when the identity and execution id differed from a
reproduction record. An unstamped `Evidence` object could therefore verify a
production finding.

Phase 24 moves that check into the domain rule. The lifecycle service is the
production issuer. `attach_evidence` correlates and cannot mint trust.

## Trusted evidence model

`Evidence` is never trusted. `ServerObservation` is a subtype that
`issue_server_observation` returns. Construction checks an HMAC-SHA256 over:

* kind, source, normalized summary
* details digest and artifact path
* server execution id, finding id, and finding key
* `observed_target`
* outcome
* server observation id

The signature uses `settings.secret_key`. The observation id is
`uuid4().hex` generated inside the issuer. Client metadata is dropped before
signing, including `attribution`, `execution_id`, `finding_id`,
`finding_key`, `observation_signature`, `observed_target`, and
`server_observation_id`.

An observation verifies a finding only when all of the following hold:

1. `is_trusted_observation` is true (`ServerObservation` and a matching HMAC).
2. The kind is HTTP response, browser, scanner, API test, replay, fuzzing, or proxy.
3. `observed_target` equals `semantic_target_identity` of the current finding.
4. The canonical observation identity is not a positive reproduction record.
5. The execution id is not a reproduction execution id.

A new `Evidence` UUID is not independence. Two issuances of the same payload
still collapse to one observation. The same trusted execution is not a second
observation. A different execution id is independent. A client-chosen
observation id is not part of the identity and does not become trusted.

`record_collected_evidence` stamps server attribution and then calls the
issuer. Tests and internal callers use `issue_for_finding`, which binds the
finding's current target, id, and key. Passing a boolean does not opt in.

Reproduction success does not require `ServerObservation`. Verification does.
Anyone who can import the issuer and knows the server secret can issue an
observation. The HTTP operator endpoint cannot: it accepts only `operation`.

Reload promotes a stored record to `ServerObservation` only when the
signature validates. A failed restore drops `attribution`,
`observation_signature`, `observed_target`, and `server_observation_id`. It
keeps `execution_id` so deduplication stays stable.

## Verified-target identity

`finding_key` remains the stable static identity and still excludes the line
number. Lifecycle verification uses a separate semantic target:

* normalized file path
* vulnerability class
* flow sink
* flow source
* field path
* static-evidence scope id
* static-evidence argument index

Line number and `flow_summary` are excluded. Whitespace is compacted.

On rescan, historical evidence is merged and kept. When the semantic target
changes and the stored status is `corroborated`, `reproduced`, `verified`, or
`human_accepted`, the row returns to the incoming scan's potential or
corroborated status and human review resets to `unreviewed`. A line-only or
formatting move keeps the previous status. `rejected` stays terminal.

Old evidence is not treated as proof of the new target. `observed_target` on
a trusted observation must match the current identity.

`sink_occurrence` can still shift when an identical call is inserted earlier
in the same scope. That remains a finding-key limit.

## Evidence identity

`observation_identity` is a canonical payload. It does not include the
`Evidence` UUID or a client `server_observation_id`.

Shared fields: kind, source, normalized summary, details digest, artifact,
line, contradiction flag, execution id, and outcome.

Type-specific fields:

| Kind | Extra fields |
|---|---|
| HTTP request, HTTP response, proxy, API test | method, URL or route, status |
| Scanner | check or rule id, target, result id |
| Browser | route or URL, event, session id |
| Fuzzing | target, result id |
| Reproduction | result id, reproduced flag |
| Static analysis, source code | rule or sink, field path |

Whitespace in the summary does not create a second observation. Different
URLs, statuses, executions, and sinks do.

## Static-ingress restrictions

`FindingLifecycleService.persist_static_scan` accepts `potential` and
`corroborated` only. It refuses `reproduced`, `verified`, `human_accepted`,
and `rejected`. There is no import path that reuses scan ingress for a
pre-verified finding.

A stored `corroborated` status reloads through `corroborate()`. One static
record stays `potential`. A stored `verified` or `human_accepted` status
reloads through `verified()` or the accepted-finding helper. If the evidence
does not satisfy the domain rule, the domain object is `potential`.
`to_security_response` reports that domain status, not a stronger column
value.

## Research persistence

`research_findings` stores kind, source, summary, details, artifact path,
provenance, redacted metadata, `collected_at`, execution identity, outcome,
and reproduced state. Lifecycle keys, including the HMAC and observation id,
are not passed through secret redaction. Secret-like strings in other
metadata are redacted.

Reload uses the domain transitions. It does not `replace()` a finding into
`corroborated`, `reproduced`, `verified`, or `human_accepted`. A failed,
inconclusive, or intermittent reproduction stays non-reproduced. Duplicate
evidence stays one identity. A corrupt claimed status stays `potential`.

Research findings still cannot call production `verify` except by satisfying
the same `ServerObservation` rule when a signed observation was stored.
Promotion does not verify.

## Security rule inventory

Taint families, each emitted as `potential` or `corroborated`:

* SQL injection
* command injection
* `potential_path_traversal`
* SSRF
* XSS
* unsafe deserialization
* dangerous dynamic execution
* unsafe redirect

Indicator families:

* hard-coded secrets
* weak cryptography
* insecure configuration
* authentication, including explicit JWT signature checks disabled
* CSRF explicitly disabled
* IDOR-style lookup without an intra-procedural ownership check

JSON parsers such as `json.loads` stay out of unsafe deserialization.
`JSON.parse` remains a potential-indicator class, not an execution sink.

## Detection changes in this phase

These are precision edits on the existing engine.

* Command list form such as `subprocess.run(["git", user])` is not shell
  injection. `shell=True`, `os.system`, and wrappers `sh -c`, `bash -c`,
  `cmd /c`, and `powershell -c` stay dangerous.
* Sanitizer suffix matching applies only to a dotted or qualified API name.
  `html.escape` can sanitize HTML. `my_module.escape` does not.
* Bare `Query`, `Path`, and `Body` are sources only when the file imports
  FastAPI or, where listed, NestJS. A local `def Query` is not a source.
* Weak cryptography matches the callee name `md5`, `sha1`, `des`, `rc4`, or
  `ecb`, or a crypto constructor argument that names those algorithms.
  `hashlib.sha256` is not reported.
* Secret assignment skips placeholders and checksum-like binding names.
  Evidence text stays redacted. Insecure-config rules skip `test_*.py` and
  paths under `tests/`.
* JWT detection includes `verify=False` and `verify_signature` false on the
  same line. Ordinary `jwt.decode` with algorithms is not flagged. Password
  comparison skips empty and `None` comparisons.
* CSRF includes `@csrf_exempt`, `WTF_CSRF_ENABLED = False`, and
  `csrf_protect = False`.
* IDOR uses the enclosing function and skips functions whose names contain
  `admin`. Ownership patterns include `current_user`, `owner ==`,
  `user_id ==`, `g.user`, and `principal`.
* Profile-fallback and detection-only parser tiers set
  `analysis_incomplete=parser_fallback` on taint observations. Python
  `full_ast` does not.

Runtime explanations treat HTTP response, HTTP request, browser, scanner,
API test, replay, fuzzing, proxy, reproduction, test failure, and log as
runtime support. A verified browser, scanner, fuzzing, or proxy observation
is not described as having no runtime support.

## Supported languages

Python uses the CPython AST. JavaScript, TypeScript, Ruby, Go, Java, PHP,
Kotlin, C, C++, Rust, Swift, C#, and shell use Tree-sitter when the grammar
is installed, otherwise a labeled profile fallback. HTML, CSS/SCSS, and SQL
have specialized profiles. Fallback is not full semantic analysis.

Go, Java, and Kotlin keep the Phase 19 local interprocedural import
following. Other languages are weaker across files. This phase's new corpus
asserts Python. Other cells below are not claimed as equivalent.

## Detection coverage matrix

Labels live in `backend/app/security/coverage.py`.

* `tested` — this phase or an existing fixture asserts the behavior.
* `existing-suite` — an older test covers part of the family.
* `limited` — a vocabulary or profile exists and is not full semantic support.
* `unsupported` — this phase does not claim a detector for that cell.

| Language | SQL | Command | Path | SSRF | XSS | Deserialization | Dynamic exec | Redirect | Secrets/controls |
|---|---|---|---|---|---|---|---|---|---|
| Python | tested | tested | tested | tested | tested | tested | tested | tested | tested |
| JavaScript | existing-suite | existing-suite | limited | limited | limited | limited | limited | limited | limited |
| TypeScript | existing-suite | limited | limited | existing-suite | limited | limited | existing-suite | limited | limited |
| Go | limited | existing-suite | limited | limited | limited | limited | unsupported | limited | limited |
| Java | limited | existing-suite | limited | limited | limited | limited | limited | limited | limited |
| Ruby | existing-suite | limited | limited | limited | limited | limited | limited | limited | limited |
| PHP | limited | limited | limited | limited | limited | limited | limited | limited | limited |
| Kotlin | limited | existing-suite | limited | limited | limited | limited | unsupported | limited | limited |
| C/C++ | limited | existing-suite | existing-suite | unsupported | unsupported | unsupported | unsupported | unsupported | limited |
| Rust | limited | limited | limited | limited | unsupported | limited | unsupported | limited | limited |
| Swift | limited | limited | limited | limited | unsupported | limited | limited | unsupported | limited |
| C# | limited | limited | limited | limited | limited | limited | unsupported | limited | limited |
| shell | unsupported | limited | limited | unsupported | unsupported | unsupported | limited | unsupported | limited |

Markup and SQL profiles stay profile-specific. They are not in this matrix
as equivalent taint languages.

## Known limitations

* Unknown calls do not propagate taint. A sink wrapped in an unrecognized
  helper is a false negative, and that helper is also not a sanitizer.
* IDOR is intra-procedural. Middleware and authorization in another file are
  not modeled. A lookup with no enclosing function falls back to a short
  adjacent window.
* Framework bare names require an import string containing `fastapi` or
  `nestjs`. `Query as Q` is not matched.
* Allow-listed redirects and fixed-host URLs with a tainted path are not
  fully modeled. A variable used as a redirect target can still be reported.
* Path traversal stays `potential_path_traversal`. Static analysis does not
  claim a demonstrated directory escape. A function named like normalization
  is not treated as a sanitizer unless its semantics are defined.
* `text()` and query-construction helpers are not vulnerabilities by
  themselves. A finding requires tainted input at a dangerous query
  operation.
* Parameterized SQL is recognized for common placeholder call shapes. Unusual
  APIs can still be flagged or missed.
* Sanitizer recognition is qualified-name matching, not a full import graph.
* Secret detection is assignment and PEM/cloud-key shaped. It misses secrets
  built at runtime and can still miss novel formats.
* Weak cryptography does not rank every checksum as a password flaw, and it
  does not understand every library constructor.
* Parser fallback sets `analysis_incomplete` and must not be read as
  corroboration or verification.
* Cross-file analysis does not speculate when several callees match, and it
  stays inside the existing depth budget.
* PostgreSQL row locks serialize lifecycle writers. SQLite does not.

## Known false positives

The negative corpus and older suites cover checksum-like names, example
placeholders, test-file debug settings, list-form shell commands, constant
SQL and URLs, parameterized queries, HTML escaping, local `Query` shadows,
constant `open` and `eval`, fixed redirects, and lookups with an obvious
ownership check.

Remaining false-positive pressure: short source names such as `get` and
`input` when the syntax does not distinguish them, relative redirects stored
in variables, and IDOR when the ownership check is outside the function.

## Known false negatives

Unrecognized wrappers, unresolved aliases, dynamic dispatch, middleware
authorization, runtime-built strings, open-redirect allow-lists, and gadget
chains behind JSON parsers. Aliased framework imports. Sanitizers applied
under a local name. Languages marked `limited` or `unsupported` above.

An unsupported case is not a passed negative test. Absence of a finding is
not evidence that the pattern is safe.

## Parser and fallback limitations

Python `full_ast` observations do not set `analysis_incomplete`.
Profile fallback and detection-only tiers set
`analysis_incomplete=parser_fallback`. Incomplete cross-file analysis stays
labeled. Partial analysis cannot by itself create corroboration or
verification. Findings still carry rule id, language, parser backend, parser
tier, file, line, sink, and source when the analyzer produced them.

## What Phase 24 does not claim

* Equal analysis quality across languages.
* Demonstrated exploitability from static analysis.
* Automatic exploit execution or AI verification.
* That a client can select a trusted observation id.
* That line movement alone invalidates verification.
* That a semantic target change keeps the old observation as proof.
* That `alembic check` is clean. Index-name drift in older migrations is
  pre-existing and is not part of this phase.
