# Phase 42 — verification bridge

Phase 42 queues Phase 41 candidate paths. It does not verify them and it
does not call another model.

## Queue

`bridge` keeps paths whose status is `candidate`. `unknown` chains and
`explore:` truncations are not queued. For each selected path, up to
`MAX_ATTEMPTS` (8), it builds a `VerificationSpecification` with `specify`
and a `VerificationRequest`. Every queued result is `not_requested`.
`request.encoded` is always false. That flag is not read by `run_smt` or
`run_forge`.

The request records the path, invariant, contract, function, compiler
version from the transition model (or `unspecified`), assumptions, path
conditions, the specification hash, and the specification's SMT capability
(`semantically_supported` or `unsupported`). Building the queue does not run a tool.
If more candidate paths exist than the attempt cap, `BridgeResult.truncated`
is `verification attempt limit reached`.

## Tools

`solc`, `forge`, and `semgrep` are detected at runtime with `shutil.which`.
A missing binary is `unavailable` when a run is attempted without a
specification, or when an encoded specification cannot be executed. No
result is fabricated. Semgrep is only reported in `tool_availability`. This
layer does not invent Semgrep findings. BugForge does not embed an API key
and does not call an LLM from this layer.

## Status without a specification

`run_smt` and `run_forge` require a `VerificationSpecification` produced by
`specify`. A caller-supplied harness and `encoded=True` do not authorize a
result. With no specification and no binary, the status is `unavailable`.
With no specification and a runner or a binary, the status is `unsupported`.

`parse_smt_output` and `parse_forge_output` classify unbound text. The words
`proved`, `counterexample`, and `Suite result: FAILED` stay `unknown`.
Timeout and compiler-failure wording are still distinguished. Authoritative
parsing is `parse_smt_bound` and `parse_forge_bound` in the Phase 43 layer.

## Evidence

`lifecycle_effect` is always `none`. An unbound result is tool-status
evidence. It does not satisfy independent verification and it does not mark
a finding verified.

## Not claimed

The bridge does not encode every candidate. Encoding, harness binding, and
tool authority are Phase 43. A candidate path is not a finding.
