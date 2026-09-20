# HackerOne Integration

BugForge talks to the official **HackerOne Hacker API** only:

`https://api.hackerone.com/v1`

Authentication is HTTP Basic with:

- `HACKERONE_API_USERNAME`
- `HACKERONE_API_TOKEN`

Local human approval uses a separate operator session:

- `BUGFORGE_OPERATOR_TOKEN`
- `BUGFORGE_OPERATOR_IDENTITY`
- header `X-BugForge-Operator-Token`

The HackerOne token never appears in the frontend, audit log, findings,
report evidence, or the database. Ordinary project records store program
handles, scope snapshots, and report ids — not credentials.

## What BugForge will and will not do

| Action | Behavior |
|---|---|
| Lookup program by handle | Yes (`GET /hackers/programs/{handle}`) |
| Sync structured scopes | Yes, all pages, then `filter[id__gt]` if needed |
| Sync scope exclusions | Yes — **report-category / reward** exclusions, not target denials |
| Sync program weaknesses | Yes — numeric HackerOne weakness ids |
| Evaluate a target | Deterministic `HackerOneScopeEvaluator` (never AI) |
| Build a report draft from a **persisted verified** finding | Yes (`finding_id`) |
| Dry-run payload preview | Yes — **never** `POST /hackers/reports` |
| Human approve | Required (`HUMAN_APPROVED`) via operator token + payload hashes |
| Real submission | Only after current validation + matching approval hashes |
| Auto-submit during setup | **Never** |
| Fabricated `status=verified` from an API client | **Rejected** |

## Persistent state

Programs, structured scopes, exclusions, weaknesses, sync records, drafts,
approvals, submissions, and lifecycle audit events persist in PostgreSQL
(Alembic revision `015`). Restarting BugForge does not forget a HackerOne
report id or a `SUBMISSION_OUTCOME_UNKNOWN` lock.

## Scope vs scope exclusions

**Structured scope** answers *where* an asset may be tested
(`TargetScopeDecision`: in-scope, structured_scope_id, submission/bounty flags).

**Scope exclusions** answer *which finding/report categories* are not
reward-eligible (`ReportEligibilityDecision`). BugForge does **not** treat
`scope_exclusions.details` as a hostname deny-list. A target can be
`IN_SCOPE` and `ELIGIBLE_FOR_SUBMISSION` but `NOT_ELIGIBLE_FOR_BOUNTY`.

## Weaknesses

BugForge class → candidate CWE → synchronized **program** weakness →
numeric HackerOne `weakness_id` (for example `sql_injection` → `cwe-89` →
id `1338`). CWE strings are never sent as `weakness_id`. Missing, multiple,
or program-absent matches require human selection.

## Report payload

`POST /hackers/reports` uses JSON:API **attributes** (not relationships):

- `team_handle`, `title`, `vulnerability_information`, `impact`
- `severity_rating` when present
- `weakness_id` (integer)
- `structured_scope_id` (integer)

`vulnerability_information` always includes summary, affected asset, steps
to reproduce, observed/expected results, and evidence references. `impact`
stays a separate field.

## Approval versioning

Approval is bound to:

- `report_content_hash`
- `evidence_hash`
- `scope_snapshot_hash`
- `payload_hash`
- operator identity and timestamp (TTL 24h)

If title, vulnerability information, impact, severity, weakness, structured
scope, target, or evidence references change, `HUMAN_APPROVED` is invalidated
and the draft returns to `READY_FOR_REVIEW`.

A free-form `operator=researcher` string is **not** authorization.

## Duplicate handling and unknown outcomes

A `(finding_id, program_handle)` pair may have at most one submission row.
If the HackerOne POST times out or the network fails after the request may
have been accepted, state is `SUBMISSION_OUTCOME_UNKNOWN`. BugForge will
not POST again until an operator reconciles remote state.

## Report intents

`/api/v1/hackerone/report-intents` is a **local** workflow bound to the same
persisted finding. Raw client payloads cannot bypass evidence. Attachments
are secret-scanned, reviewed, and not uploaded without human authorization.
Report Assistant output is never verification evidence.

## Dry-run

Dry-run uses current program/scope/weakness data, re-runs validators and
secret scans, and shows the exact redacted JSON request. Automated tests
prove `POST /hackers/reports` does not occur.

## Manual live test (never in CI)

1. Export `HACKERONE_API_USERNAME`, `HACKERONE_API_TOKEN`,
   `BUGFORGE_OPERATOR_TOKEN`, and `BUGFORGE_OPERATOR_IDENTITY`.
2. `GET /api/v1/hackerone/status` — confirm `configured: true` and that
   no token is in the JSON.
3. Sync a program you are authorized to test.
4. Review structured scopes (target authorization).
5. Review scope exclusions separately (reward categories).
6. Review synchronized weaknesses (numeric ids).
7. Create a **deliberately verified local test finding** only
   (do not invent a production vulnerability against a real program).
8. Generate a draft from that `finding_id`.
9. Dry-run and inspect the exact payload.
10. Approve as the authenticated local operator.
11. Submit manually.
12. Confirm the HackerOne report id.
13. Reconcile remote state (`new` is not `triaged` or `resolved`).

Never automatically submit during setup.
