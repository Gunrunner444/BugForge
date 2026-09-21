# Authorized Security Testing

Phase 3 adds **controlled, scope-aware security testing**. It is not
unrestricted autonomous hacking. The human operator remains responsible for
authorization and for any later disclosure. Phase 12 deepens static dataflow
only. It does not authorize live activity, change ScopeGuard or
SafetyController, or let static analysis or AI mark a finding verified.

HackerOne report submission is implemented behind human review, dry-run,
persisted duplicate protection, and an authenticated local operator
session. See [hackerone.md](hackerone.md) and [reporting.md](reporting.md).

## Local lab vs live

| Mode | Allowed targets | Active testing |
|---|---|---|
| **Lab** | Loopback / `.lab` / configured lab hosts only | Must still be explicitly enabled |
| **Live** | Structured program scope only | Human approval + explicit enable |

The two modes cannot be mixed in one session. A lab session cannot reach
`example.com`. A live session cannot use lab isolation as a bypass.
Lab permissions never apply to live HackerOne projects. Phase 9 live safety
tests cover missing scope, unknown assets, disabled active testing, missing
approval, disabled tools, exhausted budget, and offline replay.

The Phase 6–8 research agent uses the same tool APIs in both modes. There is
no fully autonomous HackerOne mode. Live agent sessions are blocked unless
the program's structured scope has been synchronized. Live sessions start in
dry-run with active testing, fuzzing, and scanners disabled.

`RateLimiter` is in-memory and **per OS process**. Two API workers can each
send a full request budget. Production live deployments must run a single
worker or terminate requests at a shared proxy.

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
- submitting a HackerOne report (human operator; AI cannot approve)

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

## Scanner vs per-request rate limit

`RateLimiter` applies to `GatedHttpClient` traffic (API tests, fuzzing, PoCs).
ZAP and Nuclei generate their own packets. BugForge still decides whether
they may run, which targets they may use, and the maximum envelope
(`ScannerExecutionPolicy`: max targets, runtime, scanner rate, concurrency,
allowed/denied templates, methods, destructive flag). The tool is configured
with limits no looser than that envelope.

## Limitations

- Playwright, ZAP, and Nuclei binaries are optional. Without them, adapters
  still enforce scope, emit a **plan** (`SCANNER_PLAN` / `TOOL_UNAVAILABLE`),
  and can ingest recorded output. They do **not** invent scanner-result
  evidence from authorization alone.
- When binaries (or a test runner) are present, adapters execute and ingest
  real output only.
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
