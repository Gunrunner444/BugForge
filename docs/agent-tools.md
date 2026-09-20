# Agent tools

The AI never invokes subprocesses or the network. It requests a structured
tool call. BugForge validates arguments, authorizes the target, then executes.

```json
{
  "tool": "browser_navigate",
  "arguments": {"url": "https://authorized.example/"},
  "reason": "Investigate authentication flow"
}
```

Registered tools:

| Tool | Purpose |
|---|---|
| `source_inspect` | Read project source excerpts |
| `browser_navigate` | Browser navigation through the gated browser stack |
| `http_request` | HTTP via `GatedHttpClient` |
| `proxy_evidence` | Inspect captured HTTP evidence |
| `api_test` | OpenAPI/API checks through the gated client |
| `zap_scan` | ZAP inside the scanner execution envelope |
| `nuclei_scan` | Nuclei inside the scanner execution envelope |
| `fuzz` | Bounded fuzz requests |
| `reproduce` | `ReproductionPlan` through ScopeGuard + SafetyController |
| `evidence_inspect` | Inspect existing evidence nodes |

Unknown tools, invalid arguments, out-of-scope targets, exhausted budgets, and
disabled tools are rejected with a structured authorization decision.
The AI cannot declare a target in scope.
