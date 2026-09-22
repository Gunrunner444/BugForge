# Phase 25 — Verification binding and adversarial detection

Phase 25 hardens the Phase 24 trust boundary and replaces a few broad
security-rule heuristics with checks the existing parser and taint model can
actually support. It does not replace the parser, the taint engine, or the
lifecycle service.

AI remains a hypothesis and explanation source. It cannot corroborate,
reproduce, or verify a finding.

Phase 26 corrects two gaps in this phase's enforcement. Corroboration used
the observation's own `observed_target` as the expected target, so a bound
observation matched itself. Python `CallArgument` records omitted keyword
arguments, so `shell=True` never reached the command rule. Both are enforced
in Phase 26. The trust order below is unchanged.

```text
static analysis
    ↓
POTENTIAL / CORROBORATED
    ↓
trusted reproduction
    ↓
REPRODUCED
    ↓
trusted independent observation
    ↓
VERIFIED
    ↓
HUMAN_ACCEPTED
```

## 1. Trusted-observation binding

`issue_server_observation` is the only issuer. It requires a non-empty
execution id, semantic target, and finding id. It writes the finding key and
project id into the signed metadata, including when those values are empty,
so a later change is visible to the signature.

`issue_for_finding` copies the finding id, finding key, `project_id`, and
`semantic_target_identity` from the finding. `record_collected_evidence`
sets `project_id` from the stored row before issuing.

`SecurityFinding.verify()` and reload through `verified()` accept an
observation only when `independent_verification_items` says it is:

* a `ServerObservation` whose HMAC matches `settings.secret_key`
* an observational kind: HTTP response, browser, scanner, API test, replay,
  fuzzing, or proxy
* bound to this finding's id, finding key, project id, and current semantic
  target
* not the same canonical event or execution as a positive reproduction

An empty target id or finding id never matches. A signature that is valid
for Finding A does not verify Finding B, even when the file, vulnerability
class, sink, source, field, scope, and argument are the same.

## 2. Signed payload

The HMAC is SHA-256 over a canonical JSON object. The object contains:

* kind
* stripped source
* whitespace-normalized summary
* SHA-256 of details
* canonical artifact path
* server observation id

and these metadata fields, each whitespace-normalized:

`argument_index`, `check_id`, `contradicts`, `event`, `execution_id`,
`field_path`, `finding_id`, `finding_key`, `line`, `method`,
`observed_target`, `outcome`, `project_id`, `reached`, `reproduced`,
`result_id`, `route`, `rule`, `rule_id`, `scope_id`, `session_id`, `sink`,
`sink_occurrence`, `status`, `status_code`, `target`, `url`.

Keyword order in the JSON does not matter because the keys are sorted.
Unsigned keys, such as `note`, are not part of the HMAC. The issuer does not
sign arbitrary secret values or raw payloads beyond the details digest.

Client-supplied copies of `attribution`, `execution_id`, `finding_id`,
`finding_key`, `observation_signature`, `observed_target`, `project_id`, and
`server_observation_id` are dropped before signing. The issuer then sets
them.

## 3. Immutable identity

`ServerObservation` is frozen, and `__post_init__` replaces `metadata` with
`MappingProxyType`. Assigning into that mapping raises `TypeError`.
Rebuilding the observation with a changed signed field and the old signature
raises `ValueError`. Rebuilding it with only an unsigned `note` still
validates.

Ordinary `Evidence` stays a normal mapping so collectors can attach notes.
Trust starts only after issuance.

`restore_server_observation` promotes a stored record only when the signature
validates. A bad signature drops `attribution`, `observation_signature`,
`observed_target`, and `server_observation_id`. It keeps `execution_id`,
`finding_id`, `finding_key`, and `project_id` so deduplication stays stable.

## 4. Finding and project binding

Project identity is in two places:

* `semantic_target_identity` hashes the project id, so two projects with the
  same code do not share a target
* the signed envelope stores `project_id`, so a signature from one project
  fails on another even if a caller forced the same target string

Rescans compare targets with the row's project id. A scan finding that has
not copied `project_id` yet is not treated as a project change.

## 5. Semantic target identity

The target hash is the first 32 hex characters of SHA-256 over:

* project id
* normalized file path
* vulnerability class
* flow sink and flow source
* field path
* from the first static evidence item: `scope_id`, `argument_index`,
  `sink_occurrence`, `sink_id`, and `call_identity`

Line number, `flow_summary`, parser `node_id`, and byte offsets are not
included. Formatting-only edits and line-only movement keep the hash.

## 6. Sink occurrence identity

`call_identity` is the whitespace-insensitive callee and argument shape from
`_call_structure`. `sink_occurrence` counts equivalent sink calls. Together
they separate:

```python
eval(request.args["a"])
eval(request.args["b"])
```

An observation for the first call does not verify the second. Occurrence
still shifts if an identical call is inserted earlier in the function. That
remains a known limit. Line numbers are not used as the stable key.

A material change of sink, source, field path, argument index, scope, file,
project, or sink occurrence keeps stored evidence and requires a new trusted
observation. The row returns to the incoming scan's potential or corroborated
status. Rejected stays terminal.

## 7. Corroboration trust classes

`can_corroborate` accepts either of these:

* two static or source observations with different canonical identities
* one trusted runtime observation bound to this finding's id, key, project,
  and its own `observed_target`

Runtime kinds that can corroborate are the verification kinds plus
`HTTP_REQUEST`. They still cannot verify.

These do not corroborate:

* one static observation, or two copies of the same static identity
* AI analysis
* a contradictory observation
* plain client HTTP, browser, scanner, or other runtime evidence
* forged `attribution=server`

Cluster construction calls `can_corroborate` without a finding id, so only
the static path can corroborate a cluster. Research promotion stamps runtime
graph evidence with `issue_for_finding` before corroborating, so a research
HTTP observation is trusted and bound to that finding.

## 8. Research persistence

Research evidence reload restores kind, provenance, source, summary, details,
artifact path, metadata, `collected_at`, and the execution fields that were
stored. `collected_at` is read from ISO format. A failed trusted-observation
restore drops the stamp and keeps the record. Secret values are redacted in
static observations; the research store does not add a second copy of a raw
credential in order to preserve identity.

## 9. Detection precision

Command injection no longer treats every list argv as safe.
`subprocess.run(["git", user])` is suppressed. `subprocess.run([user])`,
`shell=True`, and `["/bin/sh", "-c", user]` or `["/bin/bash", "-c", user]`
stay findings. The decision reads argument nodes. A quoted literal program
whose basename is `sh`, `bash`, `dash`, `zsh`, `ksh`, `cmd`, `powershell`,
`pwsh`, or `cmd.exe` is a shell wrapper.

FastAPI and NestJS bare names (`Query`, `Path`, `Body`, `Param`, `Headers`)
count only when this file binds them. `from fastapi import Query` and
`from fastapi import Query as Q` bind `Query` and `Q`. `import fastapi`
binds `fastapi.Query`. A module-level function of the same name shadows the
import. A requirements file is not required for that binding, and a
requirements file does not make an unbound `Query()` a source. Rust `Query`
is a different catalog entry and is not gated. Re-exports through an unknown
local module are not inferred.

IDOR uses the lookup line and earlier `if` guards in the same function whose
body returns or raises. An ownership check that only calls `audit()` does
not suppress the lookup. A function named `admin_load` is not skipped.
`@admin_required`, `staff_member_required`, and `permission_required` are
treated as authorization decorators. Middleware in another file is not
modeled. When no function span exists, the finding is reported.

Password comparison requires a word-bounded password name compared with `==`
to an identifier. `password_hash == candidate_hash`, `password is None`, and
`password == ""` are not findings.

Weak crypto reads literal call arguments. `hashlib.md5`, `hashlib.sha1`,
`hashlib.new("md5")`, and `Cipher.getInstance("AES/ECB/PKCS5Padding")` match.
`hashlib.sha256` and a string that merely mentions `md5` do not. A variable
holding the algorithm name is not resolved.

Secrets match whole literals, quoted dict keys on the same line, connection
strings, bearer tokens, PEM headers, and AWS-style key ids. `example`,
`changeme`, `password123`, and the other full-value placeholders are skipped.
The substring `example` inside a longer token is not a placeholder. Checksum,
etag, digest, sha256, crc32, and md5sum names are skipped. Paths named
`test_*.py` or under `/tests/` are skipped. Evidence text redacts the value.
Comments are skipped. A documentation comment is not a finding.

JWT findings require a `decode` call on `jwt` or `jose`, including
`import jwt as tokens`, with `verify=False` or `verify_signature: False`.
The parser drops keywords from the argument list, so the call's source line
is checked. `algorithms=["HS256"]` is not a finding.

CSRF findings are `@csrf_exempt` decorators and assignments whose name is
exactly `WTF_CSRF_ENABLED`, `csrf_protect`, `csrf_protection`, or
`CSRF_ENABLED` with a `False` value. A local `csrf = False` is not a finding.

## 10. Adversarial tests

`backend/tests/test_phase25/test_adversarial_security.py` covers finding and
project reuse, forged binding fields, tampered signed metadata, unsigned
notes, canonical identity, sink occurrence, material target drift, client
corroboration, static ingress, fail-closed reload, research timestamps, and
overlapping PostgreSQL writers.

`backend/tests/test_phase25/test_semantic_edges.py` covers the taint families
SQL, command, path, SSRF, XSS, deserialization, dynamic execution, and
redirect. Each case is `finding`, `clean`, or `gap`. A `gap` asserts that no
finding was emitted and that the case is listed as a known limitation.

## 11. Serialization

PostgreSQL `save_lifecycle` loads the row with `SELECT FOR UPDATE`. The
transaction that holds the lock merges the incoming finding onto the current
row: runtime evidence is the union by canonical identity, status keeps the
stronger value, and rejected is terminal. Static flow and location stay with
the locked row, so a stale `flow_summary` does not overwrite them. Duplicate
observations collapse. SQLite has no row lock; the same merge function runs,
without blocking the other writer.

The overlapping-writer test holds the row in one transaction, starts the
second save, and checks that the second waits. After both commit, reproduction
and the independent observation are both present and the status is verified.
A later rejection is not overwritten by a duplicate verification save.

## 12. Known limitations

* Any in-process code that can read `settings.secret_key` can call
  `issue_server_observation`. The HTTP operator endpoint does not accept an
  evidence body.
* Reproduction success does not require a `ServerObservation`. Verification
  does. `human_accept` of an already reproduced finding does not require a
  second observation.
* Unknown wrappers do not propagate taint. Ambiguous callees are not
  resolved. A syntax error produces no partial finding.
* `os.path.realpath` does not clear a path finding. Conditional
  `url_has_allowed_host_and_scheme` around a URL or redirect is not modeled.
* Bare sinks such as `execute`, `open`, `Markup`, and `redirect` still match
  a local function of that name. Qualified calls such as `os.system` do not
  match a local `system`.
* IDOR is intra-procedural. Authorization in middleware or another file is
  not visible.
* Framework names are bound from imports in this file. A re-export through
  an unknown local module is not inferred.
* `sink_occurrence` changes when an identical call is inserted earlier.
* Language coverage is unequal. The coverage matrix in the security package
  is the source of truth for what each language claims.
* `verify=False` on a JWT line can also match the insecure-configuration
  indicator. That indicator is not the JWT rule.

## 13. Known false positives

* A local function named `execute`, `open`, `Markup`, or `redirect` can still
  be reported as the corresponding sink.
* `open(path, user_value)` can be reported even when the tainted value is
  not the path argument.
* `pickle.loads(constant, user_value)` and `eval("1", {"x": user_value})`
  can be reported from a non-primary argument.
* A single-line dict or docstring that contains a production-looking
  assignment is reported. Comments are not.
* IDOR reports a lookup when the authorizing check is outside the function.

## 14. Known false negatives

* The `gap` cases in `test_semantic_edges.py`: wrappers, ambiguous callees,
  syntax-error files, and unmodeled conditional allowlists.
* Algorithm names stored in variables, for example `hashlib.new(name)`.
* Secrets assembled at runtime.
* CSRF and authorization enforced only in middleware or another module.
* Shell invocation that builds the argument list without a literal list in
  the first argument node.

## Intentionally unsupported

* Automatic exploit execution.
* AI verification or AI corroboration.
* New vulnerability classes beyond the existing catalogs.
* Speculative import resolution when the graph does not show the binding.
* Using parser byte offsets or line numbers as the primary target identity.
