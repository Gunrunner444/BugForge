# Agent tools

The AI never invokes subprocesses or the network. It requests a structured
tool call. BugForge validates the JSON schema, capability, mode, session,
`ScopeGuard`, `SafetyController`, tool-specific approval, and budget, then
executes.

```json
{
  "tool": "browser_navigate",
  "arguments": {"url": "https://authorized.example/"},
  "reason": "Investigate authentication flow"
}
```

The model is given `ToolSpec.for_llm()`: name, description, JSON schema,
`risk_level`, `allowed_modes`, `network_access`, `requires_active_testing`,
`approval_kind`, and `capability`.

Capability states: `UNAVAILABLE`, `PLANNING_ONLY`, `EXECUTABLE`,
`RESULTS_INGESTIBLE`. Planning or authorization is never labeled as a scan
result. Separately, a tool may be `AVAILABLE` or `UNAVAILABLE` (installed),
`ENABLED` or `DISABLED` (operator), `APPROVED` or not (human gate), and
`AUTHORIZED` or `BLOCKED` (current target). Execution success is a fifth
question.

| Tool | Capability | Risk | Approval | Notes |
|---|---|---|---|---|
| `source_inspect` | **executable** | PASSIVE | none | Repo-relative reads, traversal rejected, secrets redacted, untrusted |
| `evidence_inspect` | **executable** | PASSIVE | none | Loads graph nodes for this session only |
| `proxy_evidence` | **executable** | PASSIVE | none | Loads captured exchanges for this session |
| `http_request` | **executable** | LOW_RISK_ACTIVE | `send_poc_request` (live) | `GatedHttpClient` |
| `browser_navigate` | **executable** if Playwright installed, else **unavailable** | ACTIVE | active testing (live) | Real `PlaywrightBrowserAdapter`; no fake navigation |
| `api_test` | **executable** | LOW_RISK_ACTIVE | `send_poc_request` (live) | Requires `spec_path` (OpenAPI/Postman/Insomnia/HAR) |
| `fuzz` | **executable** | ACTIVE | `ENABLE_FUZZING` | `FuzzingEngine`; interesting diffs only, not all vulns |
| `reproduce` | **executable** | ACTIVE | `SEND_POC_REQUEST` (live) | Oracle: status-only is `INCONCLUSIVE` |
| `zap_scan` | **executable** with `zap.sh`, else **results-ingestible** / **unavailable** | HIGH_RISK | `START_LIVE_SCAN` + `HIGH_RISK_SCANNER` (live) | Real `ZapAdapter`; ingest alerts |
| `nuclei_scan` | **executable** with `nuclei`, else **results-ingestible** / **unavailable** | ACTIVE | `START_LIVE_SCAN` (live) | Real `NucleiAdapter`; arbitrary templates denied |

Unknown tools, invalid arguments, out-of-scope targets, exhausted budgets,
disabled tools, and missing approvals are rejected with a structured
authorization decision. Result quality is one of `SUCCESS`, `NO_RESULT`,
`BLOCKED`, `FAILED`, `TIMEOUT`, `UNAVAILABLE`, `PARTIAL`,
`RESULTS_AVAILABLE`.

The AI cannot declare a target in scope, enable tools, grant approvals,
mark findings verified, approve reports, or submit to HackerOne.
