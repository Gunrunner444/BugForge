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

`FindingLifecycleService` is the orchestration path. It loads a persisted
finding, correlates trusted `Evidence` onto that exact finding, optionally
calls a domain method, and saves the complete object.

## Correlation is not verification

`correlate_finding` answers: does this evidence belong to this finding?

It prefers, in order:

1. exact `finding_key`
2. exact file plus vulnerability class plus line
3. exact sink/source when those are present
4. otherwise reject as ambiguous

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
