# HackerOne Integration

Phase 4 talks to the official **HackerOne Hacker API** only:

`https://api.hackerone.com/v1`

Authentication is HTTP Basic with:

- `HACKERONE_API_USERNAME`
- `HACKERONE_API_TOKEN`

The token never appears in the frontend, audit log, findings, or report
evidence. Ordinary project records store program handles and report ids,
not credentials.

## What BugForge will and will not do

| Action | Behavior |
|---|---|
| Lookup program by handle | Yes (`GET /hackers/programs/{handle}`) |
| Sync structured scopes | Yes, all pages |
| Sync scope exclusions | Yes, all pages |
| Evaluate a target | Deterministic `HackerOneScopeEvaluator` (never AI) |
| Build a report draft from a **verified** finding | Yes |
| Dry-run payload preview | Yes — **never** `POST /hackers/reports` |
| Human approve | Required (`HUMAN_APPROVED`) |
| Real submission | Only after validation + `HUMAN_APPROVED` |
| Auto-submit during setup | **Never** |

## Scope sync

Structured scopes preserve:

- structured scope id
- asset type (Domain, URL, Wildcard, IP, CIDR, Source Code, Executable,
  Android/iOS app, Hardware/IoT, Other, AI Model)
- asset identifier
- instruction
- eligible_for_bounty
- eligible_for_submission
- reference

These are **not** collapsed into `allowed_hosts`. In-scope, eligible for
submission, and eligible for bounty stay separate. "Not bounty eligible"
is not the same as "out of scope".

Non-network assets are not forced through the hostname evaluator.

## Open vs closed scope

Closed-scope (default): unknown asset → deny.

Open-scope: unknown asset is **still not automatically authorized**. A
human must acknowledge an explicit active-testing policy describing what
BugForge may test. AI cannot grant that acknowledgement.

## Report workflow

```
LOCAL_DRAFT → READY_FOR_REVIEW → HUMAN_APPROVED → SUBMISSION_ATTEMPTED → SUBMITTED
```

Failures: `SUBMISSION_FAILED`, `IDENTITY_VERIFICATION_REQUIRED`.

Kept separate:

- BugForge finding verification (`potential` … `verified`)
- HackerOne report submission state
- HackerOne remote state

The AI cannot advance a draft to `HUMAN_APPROVED`.

A finding can become a draft only if it is verified, has verifying
evidence, has reproduction notes where required, maps to a current
structured scope that is eligible for submission, and does not contain
detected secrets.

## Dry-run

Dry-run may authenticate, fetch program/scope, validate, and display the
redacted JSON:API payload. Automated tests prove `POST /hackers/reports`
does not occur.

## Identity verification

If the API reports that identity verification is required, BugForge
records `IDENTITY_VERIFICATION_REQUIRED` and keeps the local draft.
There is no bypass.

## Manual live test

1. Export `HACKERONE_API_USERNAME` and `HACKERONE_API_TOKEN`.
2. `GET /api/v1/hackerone/status` — confirm `configured: true` and that
   no token is in the JSON.
3. Import a program you are authorized to test (`POST /hackerone/programs/sync`).
4. Review structured scopes, exclusions, and instructions in the UI.
5. Create a **deliberately verified local test finding** (do not invent
   a production vuln).
6. Generate a report draft and run **Dry Run**.
7. Review the exact payload.
8. Perform the **HUMAN_APPROVED** transition as a human operator.
9. Only then click **Submit**.

Never automatically submit during setup.

## Report intents

`POST/GET/PATCH /hackers/report_intents` and submit-intent are a
**separate** workflow. HackerOne Report Assistant output is not BugForge
verified evidence. Human review remains mandatory.
