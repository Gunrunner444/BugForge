# Phase 21 — Evidence correlation and finding lifecycle

Phase 21 connects existing analysis, persistence, evidence, and domain
transitions into one lifecycle. It does not add a taint engine, a new
vulnerability family, or AI verification.

```
Repository
  → static semantic analysis
  → potential / corroborated finding
  → stable finding_key + persistence
  → trusted runtime / observational evidence
  → evidence correlation
  → reproduce / verify domain transition
  → human review
```

`FindingLifecycleService` is the production path. The security analyze API
and `AnalysisService` persist the initial static finding through
`persist_static_scan`. Later evidence uses `record_collected_evidence` or
`attach_evidence`, which correlate, optionally call a domain method, and
merge the complete finding. Phase 22 is the integration of that service;
this document's correlation order is tightened there.

## Correlation is not verification

`correlate_finding` answers: does this evidence belong to this finding?

Phase 22 prefers, in order:

1. trusted server finding identity stamped from the loaded finding
2. a server execution id already stored on that finding
3. exact normalized file, line, and vulnerability identity
4. exact sink or source when those facts are present
5. otherwise reject as ambiguous

An untrusted client `finding_key` does not match by itself. Runtime evidence
without a source path matches only through the server stamp.

It does not attach evidence merely because the file, class, sink name, or
project matches. Competing findings on the same line leave the evidence
unattached. Duplicate items are not stored twice.

Correlation never changes status. Verification is only
`SecurityFinding.verify()` with independent observational or executable
evidence. AI text, static analysis, generated tests that were never run, and
source excerpts cannot verify.

## Lifecycle states

| Status | Meaning |
|---|---|
| `potential` | Static or AI hypothesis. Not verified. |
| `corroborated` | Independent static or research observations agree. Still not verified. |
| `reproduced` | Independent reproduction evidence is attached. Stronger than corroboration, not verified. |
| `verified` | Domain `verify()` succeeded with independent evidence. |
| `human_accepted` | An operator accepted a reproduced or verified finding. |
| `rejected` | Terminal rejection. Cannot be verified. |

Orchestration calls `corroborate()`, `reproduce()`, `verify()`,
`human_accept()`, or `reject()`. It does not assign `FindingStatus` directly.

Contradictory runtime evidence is attached and explained. It does not delete
the static finding, does not mark it verified, and does not automatically
unverify an already verified finding.

## Persistence

The dedicated `finding_key` column is authoritative. A NULL column cannot be
reconstructed from `intelligence_json`. Duplicate legacy rows keep history
but lose the key so a later scan cannot create a second logical identity.

A static rescan reuses the row for `(project_id, finding_key)`. It may
refresh location and flow facts. It must not erase status, human review
state, or independent evidence. Concurrent scans rely on the unique
constraint plus savepoint recovery rather than lookup-then-insert alone.

`analysis_id` is the latest scan that observed the finding. The schema is not
a historical finding store; an older analysis listing can go empty after a
newer scan reconciles the same key.

## Identity

`finding_key` stays line-independent. `sink_occurrence` counts earlier calls
in the same scope with the same callee and argument structure. A harmless
`eval("constant")` does not change the key of `eval(request.args.get("q"))`.
Inserting another identical finding before existing ones does shift later
ordinals; removing it restores them. Whitespace-only line shifts keep the
key.

Framework routes require a constructor whose import or require origin is
proven (`flask.Flask`, `fastapi.FastAPI`, `express`). Local functions named
`FastAPI` or `express` are not routes.

Research-agent promotion uses `dataclasses.replace` so identity and
lifecycle fields survive evidence merge. The agent still cannot verify.
