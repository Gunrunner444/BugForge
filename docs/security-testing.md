# Authorized Security Testing

Phase 3 adds **controlled, scope-aware security testing**. It is not
unrestricted autonomous hacking. The human operator remains responsible for
authorization and for any later disclosure.

HackerOne report submission is **not implemented**.

## Local lab vs live

| Mode | Allowed targets | Active testing |
|---|---|---|
| **Lab** | Loopback / `.lab` / configured lab hosts only | Must still be explicitly enabled |
| **Live** | Structured program scope only | Human approval + explicit enable |

The two modes cannot be mixed in one session. A lab session cannot reach
`example.com`. A live session cannot use lab isolation as a bypass.

## Authorization chain

Every active network operation must pass:

1. `TargetNormalizer` — canonical host, port, path, IP/CIDR
2. `ScopeGuard` — structured include/exclude rules (default **deny**)
3. `SafetyController` — conservative request, method, size, duration limits
4. `RateLimiter`
5. `SecurityToolRunner` / `GatedHttpClient`
6. Evidence collection (redacted)
7. Finding correlation (AI-only never verifies)

A denied request never reaches a network-capable tool.

Dry-run mode explains what would be executed without sending traffic.

## Human approval gates

Required before:

- enabling active testing on a live project
- starting a live external scan
- enabling fuzzing
- running a higher-risk scanner (ZAP active scan, Nuclei)
- sending a generated proof-of-concept request
- submitting a HackerOne report (gate exists; submission is not implemented)

The AI may propose actions. `SafetyController` decides whether they are
technically allowed. A human decides whether active research should begin.

## Evidence lifecycle

Findings move only through frozen transitions:

`potential` → `corroborated` → `reproduced` → `verified` → `human_accepted`

or `rejected`.

Verification requires independent observational or executable provenance.
AI hypotheses, static hints, and source excerpts cannot verify a finding.
Scanner timeouts and tool crashes are infrastructure states, not
vulnerabilities.

Manual researcher notes join the same `EvidenceBundle`.

## Limitations

- Playwright, ZAP, and Nuclei binaries are optional. Without them, adapters
  still enforce scope and can ingest recorded output.
- Burp is ingest-only (HTTP history export). BugForge does not drive the GUI.
- Default HTTP methods are `GET`, `HEAD`, `OPTIONS`. Destructive methods are
  off.
- DoS, social engineering, notification spam, and physical testing are
  forbidden in code.
- Do **not** use this against live external targets unless a human has
  loaded structured scope, granted approvals, and accepted the rate limits.

## UI

`/security-testing` shows project, program/lab, targets, scope status,
active testing, rate limit, tools, and finding states. Each attempted
operation displays target, scope decision, tool, request limit, reason,
and human approval state. There is no "Hack Everything" button.
