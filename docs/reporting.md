# Reporting

BugForge findings and HackerOne reports are different objects.

## Evidence packages

Research export packages are canonical (sorted keys/nodes/edges, redacted
secrets). `hashes.sha256` hashes that JSON excluding the hashes object.
Export a whole session or `?finding_id=` for one finding (404 if unknown).

## Local reports

`LocalReportProvider` renders markdown. It never uploads.

## HackerOne drafts

`HackerOneReportDraft` is created from a **persisted verified** BugForge
finding (`finding_id` + `project_id` + `program_handle`). Clients cannot
POST `status=verified` or homemade evidence to mint a submission-ready
draft.

Required locally before a real `POST /hackers/reports` — and re-checked
at READY_FOR_REVIEW, HUMAN_APPROVED, and immediately before POST:

- title, vulnerability information, impact
- target in the **current** structured scope snapshot
- target eligible for submission
- valid numeric `structured_scope_id`
- numeric program `weakness_id` (human chooses when the mapping is missing or ambiguous)
- severity when the program requires it (`critical|high|medium|low|informational`)
- verifying evidence + reproduction in `vulnerability_information`
- no detected credentials/secrets
- `HUMAN_APPROVED` whose hashes still match the current payload/scope/evidence

Severity is never invented. Informational maps to HackerOne `none` on
the wire.

## Weakness mapping

BugForge vulnerability classes are not HackerOne weakness ids. The
mapping layer returns CWE candidates, then looks up the program's
synchronized weaknesses. Only a numeric HackerOne id is sent.

## Duplicate protection

A BugForge finding id can have at most one HackerOne report id per
program. The constraint is persisted. A second submit is refused locally.
Unknown network outcomes require reconciliation, not a retry POST.

## UI

On `/security-testing`:

- Program: connection, last sync, scope count, snapshot version, exclusions, weaknesses, instructions
- Finding: persisted id, verification, evidence, reproduction, scope match, eligibility
- Report: DRAFT → READY FOR REVIEW → HUMAN APPROVAL → DRY RUN → SUBMISSION → REMOTE STATE
- Payload hash, scope snapshot, evidence summary, weakness, severity, target, program

After any edit, approval is invalidated.

## Report intents and attachments

A local BugForge intent is not a HackerOne report intent. Intents persist
(`HackerOneReportIntent` + `HackerOneReportIntentAttachment`) bound to
project, finding, and draft. Attachments start as `RECEIVED`; client
`reviewed=true` is ignored. Humans then `REVIEWED` → `UPLOAD_AUTHORIZED`
before the official HackerOne attachment API is used.

## Concurrent submission

The database claims a submission (`HUMAN_APPROVED` → `SUBMISSION_ATTEMPTED`)
before the remote POST. A second concurrent request receives
`SUBMISSION_IN_PROGRESS`. Timeouts become `SUBMISSION_OUTCOME_UNKNOWN`.
