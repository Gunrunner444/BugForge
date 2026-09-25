# Phase 42 — verification bridge and counterexamples

Phase 42 consumes Phase 41 candidates. It does not replace them and it does
not call another model.

## Queue

`bridge` builds one verification request per candidate path. The request
records the path, invariant, contract, function, compiler version from the
transition model (or `unspecified`), assumptions, and path conditions. Every
queued result is `not_requested`. Building the queue does not verify anything.

## Tools

`solc`, `forge`, and `semgrep` are detected at runtime with `shutil.which`.
A missing binary is `unavailable`. No result is fabricated. BugForge does not
embed an API key and does not call an LLM from this layer.

The default SMT and Foundry harnesses are new strings marked
`BUGFORGE GENERATED VERIFICATION HARNESS — not production source`. They are
not written back into the target contract. The default SMT stub is
`assert(true)` and is forced to `encoded=false`, so a compiler success on
that stub cannot become `proved_safe`.

## Status

| Status | Meaning |
| --- | --- |
| `not_requested` | The request was only queued |
| `unavailable` | The tool binary is absent |
| `unknown` | The tool ran, or a passing Forge suite was seen, without an authoritative result |
| `timeout` | The tool reported a timeout |
| `unsupported` | The tool reported an unsupported feature |
| `failed` | The tool or harness failed |
| `counterexample` | An encoded SMT run reported an assertion violation |
| `proved_safe` | An encoded SMT run explicitly reported a proof |
| `reproduced` | An encoded Forge run failed and the output was kept |

Exit code 0 is not a proof. A passing Forge run is testing evidence and stays
`unknown`. A tool status of `proved_safe`, `counterexample`, or `reproduced`
is downgraded to `unknown` unless the request is marked `encoded` and, for
SMT, the harness was supplied as that encoding.

## Evidence

`evidence_for` maps `proved_safe` and `counterexample` to static analysis,
other non-reproduction statuses to tool status, and `reproduced` to a
reproduction record only when the raw Forge artifact is present.
`lifecycle_effect` is always `none`. Static evidence and an unsigned
reproduction record do not satisfy independent verification. They do not
mark a finding verified.

## Not claimed

This bridge does not encode every candidate into an SMT assertion or a
Foundry sequence. Unencoded properties stay non-authoritative. A
counterexample is the tool's text, normalized into actors, calls, and source
lines that were actually present. Fields the tool did not supply stay empty.
