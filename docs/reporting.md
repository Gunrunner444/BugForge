# Reporting

BugForge findings and HackerOne reports are different objects.

## Local reports

`LocalReportProvider` renders markdown. It never uploads.

## HackerOne drafts

`HackerOneReportDraft` is created from a **verified** BugForge finding.

Required locally before a real `POST /hackers/reports`:

- title, vulnerability information, impact
- target in current structured scope
- target eligible for submission
- valid `structured_scope_id`
- weakness selected (human chooses when the BugForge class is ambiguous)
- severity when the program requires it (`critical|high|medium|low|informational`)
- verifying evidence + reproduction
- no detected credentials/secrets
- `HUMAN_APPROVED`

Severity is never invented. Informational maps to HackerOne `none` on
the wire. Beginning 21 September 2026, programs that require severity
will 422 without it; BugForge surfaces that as `severity_required`.

## Weakness mapping

BugForge vulnerability classes are not HackerOne weakness ids. The
mapping layer returns **candidates**. If more than one candidate exists
(or none), a human must select.

## Duplicate protection

A BugForge finding id can have at most one HackerOne report id. A second
submit is refused locally.

## UI

On `/security-testing`:

- Generate Report
- Review Report
- Dry Run
- Approve Submission
- Submit (disabled until validation passes and `HUMAN_APPROVED` exists)
