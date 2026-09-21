# Evidence workflow

Evidence is a graph, not a count of IDs.

## Completeness states

| State | Meaning |
|---|---|
| `OBSERVATION_COMPLETE` | Observations exist; no supported hypothesis yet |
| `HYPOTHESIS_SUPPORTED` | Live (non-AI, non-replay) evidence supports a hypothesis |
| `REPRODUCTION_REQUIRED` | Reproduction has not run or did not produce live evidence |
| `REPRODUCED` | Deterministic reproduction succeeded; **not** verified |
| `VERIFIED` | Independent live verification evidence exists |
| `INCONCLUSIVE` | Contradictions, missing chain, or exhausted research |

A hypothesis with supporting evidence IDs is **never** `COMPLETED_SUCCESS`.
Unverified work ends as `INCONCLUSIVE` or `COMPLETED_NO_FINDINGS`.

## Provenance

Replay observations are stored with `provenance=replay`. Replay evidence
cannot qualify as live verification. AI hypothesis provenance cannot verify.

`identify_missing_evidence()` checks that referenced IDs exist, are linked
to the hypothesis, have valid provenance, are not AI-only, considers
contradictions, and applies vulnerability-class requirements (authorization
oracles for IDOR/access-control).

## Export

- Whole-session export: `GET /sessions/{id}/export`
- Specific finding: `GET /sessions/{id}/export?finding_id=...` (404 if unknown
  or not in the session)

`hashes.sha256` is SHA-256 of canonical JSON (sorted keys, sorted graph
nodes/edges, redacted secrets) **excluding** the hashes object. Recorded
timestamps that are part of the artifact are included.

Packages include finding, hypothesis, evidence, tool execution, request,
response, reproduction, source, scope snapshot, and timeline. Secrets are
redacted. The package does not claim a complete chain if payloads were
redacted for safety.

## HackerOne handoff

Handoff uses `HackerOneScopeEvaluator`. Substring containment is never used
to infer scope. The payload includes target, matched structured scope id,
asset type, eligibility, program, scope snapshot, and evaluation reason.
Human approval is still required before submission.
