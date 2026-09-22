# Tool Integrations

All tools are untrusted data sources. Output is wrapped as
`[UNTRUSTED_TOOL_OUTPUT]` before it can reach a model. Secrets in headers,
cookies, and bodies are redacted.

## Browser (Playwright)

`PlaywrightBrowserAdapter` collects evidence: URL, title, DOM (optional),
screenshots, console, cookie *names*, local/session storage *keys*,
network exchanges, navigation history.

Every navigation goes through `ScopeGuard`. Independently, a
`BrowserNetworkPolicy` is installed on the Playwright `BrowserContext`
(`route("**/*")`) so document/fetch/XHR/script/image/stylesheet/iframe/
redirect/WebSocket requests are authorized before they hit the network.
Popup pages inherit the context policy. Service workers are blocked
(`service_workers="block"`). `page.goto` authorization does not cover the
redirect chain.

Screenshots are written only under a project evidence directory with
name sanitization, size limits, and cleanup. DOM, console, URLs, storage
metadata, and network metadata are secret-redacted before storage/AI.

Clicks default off. Destructive labels are blocked unless an explicit
destructive policy is enabled (still off by default).

Playwright is optional. Without the package, the adapter still records
authorized navigations for tests and refuses out-of-scope URLs.

## Proxy / HAR / Burp

- **HAR** — ingest recorded HTTP archives as evidence.
- **Burp** — ingest HTTP history XML or JSON. Deduplicates requests.
  Imported traffic is evidence; **replay** requires ScopeGuard,
  SafetyController, and PoC approval.

BugForge does not control the Burp GUI.

## OWASP ZAP

Uses Automation Framework YAML plans **and executes them** when `zap.sh` /
`zap-cli` (or a test runner) is available:

target validation → SafetyController → authorization → approved plan →
process → timeout → ingest alerts.

A generated plan is `SCANNER_PLAN` (planning metadata). Authorization
alone is not scanner evidence. States include `PLANNED`, `RUNNING`,
`COMPLETED` / `RESULTS_INGESTED`, `FAILED`, `TIMEOUT`, `TOOL_UNAVAILABLE`.
The plan's URL list is only the BugForge-authorized target.

## Nuclei

Target validation → template policy → SafetyController → subprocess →
timeout → JSON/JSONL ingest.

Untagged, unknown-tag, unknown-severity, and denied-tag templates are
denied by default. Only Nuclei output becomes `SCANNER` / `SCANNER_RESULT`
evidence. "Scan authorized" is `TOOL_STATUS` / `AUTHORIZED`, not a finding.

## API testing

Imports OpenAPI/Swagger JSON, Postman collections, Insomnia exports, HAR,
and raw HTTP into `APISpec` / `Endpoint` / `Parameter` models. Candidate
tests (auth omitted, method tampering, object-id swap, invalid input) are
proposals. Execution uses `GatedHttpClient`. A model prediction is never
a successful finding by itself.

## Fuzzing

`FuzzingEngine` mutates query, path, JSON, form, and selected headers
from a `SeedRequest`. JSON mutations parse the seed and use `json.dumps`
(never Python `repr()`). `MALFORMED_JSON` is an explicit broken-JSON mode.
Fuzzer limits are the stricter of `FuzzLimits` and `SafetyController`
(RPS, concurrency, timeout, payload count, request count, body size).

## Discovery engines

Discovery engines are registered on the plugin catalog and selected by
`DiscoveryScheduler`. A missing binary returns `UNAVAILABLE` and `executed=false`.
Slither and Echidna/Medusa are AGPL executables and are not vendored. Foundry
is MIT/Apache. Wake is ISC and optional. Halmos is used only after a target is
marked difficult to reach. `forge test` never adds `--fork-url`. Tool text is
redacted and is not a verification decision.

## Manual evidence

Researchers can record observations, request/response, reproduction
notes, screenshots, expected vs actual results, and comments. These join
the same `EvidenceBundle` as automated evidence.
