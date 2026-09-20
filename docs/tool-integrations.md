# Tool Integrations

All tools are untrusted data sources. Output is wrapped as
`[UNTRUSTED_TOOL_OUTPUT]` before it can reach a model. Secrets in headers,
cookies, and bodies are redacted.

## Browser (Playwright)

`PlaywrightBrowserAdapter` collects evidence: URL, title, DOM (optional),
screenshots, console, cookie *names*, local/session storage *keys*,
network exchanges, navigation history.

Every navigation goes through `ScopeGuard`. Clicks default off.
Destructive labels (`delete`, `purchase`, …) are blocked unless an
explicit destructive policy is enabled (still off by default).

Playwright is optional. Without the package, the adapter still records
authorized navigations for tests and refuses out-of-scope URLs.

## Proxy / HAR / Burp

- **HAR** — ingest recorded HTTP archives as evidence.
- **Burp** — ingest HTTP history XML or JSON. Deduplicates requests.
  Imported traffic is evidence; **replay** requires ScopeGuard,
  SafetyController, and PoC approval.

BugForge does not control the Burp GUI.

## OWASP ZAP

Uses Automation Framework YAML plans. Passive wait / spider / activeScan
jobs are emitted **only** for targets that already passed BugForge scope.
ZAP's own target configuration cannot override BugForge restrictions.
Active scanning requires active-testing permission, high-risk approval,
rate limits, and a maximum duration. Alert JSON can be ingested without a
local ZAP binary.

## Nuclei

External tool integration: health/version when installed, JSON/JSONL
ingest, template id, severity, endpoint, matcher metadata.

A `NucleiTemplatePolicy` restricts tags and severity. Denied tags include
`dos` by default. Arbitrary templates are not run automatically. Target
lists are validated with ScopeGuard before Nuclei would receive them.

## API testing

Imports OpenAPI/Swagger JSON, Postman collections, Insomnia exports, HAR,
and raw HTTP into `APISpec` / `Endpoint` / `Parameter` models. Candidate
tests (auth omitted, method tampering, object-id swap, invalid input) are
proposals. Execution uses `GatedHttpClient`. A model prediction is never
a successful finding by itself.

## Fuzzing

`FuzzingEngine` mutates query, path, JSON, form, and selected headers
from a `SeedRequest`. Conservative defaults (small request cap, 1 r/s,
tiny payloads). Stop conditions are enforced. Differences are evidence,
not verified vulnerabilities.

## Manual evidence

Researchers can record observations, request/response, reproduction
notes, screenshots, expected vs actual results, and comments. These join
the same `EvidenceBundle` as automated evidence.
