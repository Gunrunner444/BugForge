# Phase 43 — verification authority and harness binding

Phase 43 sits on the Phase 42 queue. The only authoritative results are tool
outputs bound to a harness BugForge generated for one specification.

```text
CandidatePath
    -> VerificationSpecification
    -> GeneratedVerificationArtifact
    -> tool execution
    -> VerificationResult
```

A banner, a comment, `assert(true)`, `assertTrue(true)`, `encoded=True`, and
a tool exit code are not predicates and are not authority.

## Specification

`specify(path, model, program)` builds a `VerificationSpecification`. The
deterministic `specification_hash` is the SHA-256 of a canonical JSON object
containing the path id, invariant id, predicate, declaration ids, operation
ids, function ids (truncated to 8), assumptions, compiler version, source
digest, and the SMT and Foundry capabilities. The source digest is the
SHA-256 of the on-disk source when `program.file` exists, otherwise the
joined function sources.

The predicate is copied from the Phase 41 invariant. Partial and unknown
predicates are not rewritten into a formula the analyzer does not have.

## Capability

`capability_matrix()` is the encoder's catalog, not a claim about a
particular target:

| Property | SMT | Foundry |
| --- | --- | --- |
| scalar equality | supported | supported |
| mapping-sum equality | unsupported | unsupported |
| monotonic increment | supported | supported |
| asset/share | unsupported | unsupported |
| authorization | unsupported | unsupported |
| reentrancy | unsupported | unsupported |
| external-call preservation | unsupported | unsupported |
| allowance, debt, reserve, pause | unsupported | unsupported |
| ERC-4626 conservation | unsupported | unsupported |

A per-specification capability is narrower than the catalog. Scalar equality
is `supported` for SMT only when every function in the path is a
parameterless function of the invariant's contract, the contract source has
no `import`, and both sides are state names in that contract. Foundry also
requires those names to be `public`, because the replay contract calls the
generated getters. Monotonic increment adds the requirement that the source
contains `subject += 1` or `subject = subject + 1`. Anything else is
`unsupported`. `partially_supported` is not used as an encoding status.

## Harness

`generate_smt_artifact` and `generate_forge_artifact` return a
`GeneratedArtifact`. `encoding_status` is `encoded` only when the harness
contains a real check and is within 16_000 characters.

The SMT harness copies the target contract and injects
`function bugforge_<hash8>() external`. For equality the body calls each
path function and then `assert(lhs == rhs)`. For monotonicity it records
the subject, calls the path functions, and then `assert(next > previous)`.
The copy is the proof scope `contract-copy-harness`. It is not a proof of
the protocol, of other functions, or of external calls.

The Foundry harness appends `contract BugforgeReplay` to the same source.
It deploys the target with `new Contract()`, calls the path functions, and
reverts with `bugforge-fail:<specification hash>` when the equality or the
monotonic comparison fails. It does not import `forge-std` and it does not
call `assertTrue(true)`.

An unsupported harness contains the specification hash and no `assert`.

The manifest is canonical JSON. It records the schema `phase43.1`,
specification hash, source digest, harness digest, compiler config, contract,
path id, invariant id, function ids, operation ids, encoding status, proof
scope, token, fail token, assert line, and command. `binds` requires all of
those to match the specification and the harness bytes. A modified harness,
source, contract, path, operations, property, or compiler config fails the
bind. A matching banner is not enough.

## SMT execution

When the artifact is encoded and `binds` succeeds, `run_smt` invokes the
`solc` on `PATH`:

```text
solc --model-checker-engine chc --model-checker-show-proved-safe Harness.sol
```

The timeout is 30 seconds. BMC is not selected. The recorded compiler config
is the transition model's version string. The invoked binary is whatever
`solc` is on `PATH`; a version mismatch is written into the diagnostics and
is not treated as the project's compiler. If `solc` is absent, an encoded
run is `unavailable`. Static candidate generation still runs.

`parse_smt_bound` splits the compiler text into blank-line stanzas. A stanza
counts only when it contains the injected function token or `:<assert line>:`.
Inside those stanzas, assertion-violation or counterexample wording is
`counterexample`, and `proved` is `proved_safe`. The same words in another
stanza stay `unknown`. Timeout, unsupported, and `Error:` are classified
separately. Exit code 0 is not a proof.

`proved_safe` means the encoded assertion in the contract copy was reported
proved. It does not mean the protocol is secure. External calls are not
modeled by this harness. The counterexample records the token or the assert
line, the raw output, and source lines that contain that marker. Actors,
calldata, initial state, and state deltas stay empty unless a later parser
is given those fields by the tool. This parser does not invent them.

## Foundry execution

`foundry_root` walks parents of the source path for `foundry.toml` and
records that directory. Execution does not write into it and does not copy
`lib/`. An encoded harness is self-contained, so `run_forge` creates a
temporary project with its own `foundry.toml`, empty `src/`, and
`test/BugforgeReplay.t.sol`, then runs:

```text
forge test --match-contract BugforgeReplay --root <temp>
```

The timeout is 60 seconds. The result diagnostics say that the analyzed
project was not modified. A target whose source contains `import`, or whose
state is not `public`, is `unsupported` rather than run against a partial
copy of the project. If `forge` is absent, an encoded run is `unavailable`.
SMT can still run when `solc` is present. Semgrep output is not fabricated.

`reproduced` requires `parse_forge_bound` to see both a Forge failure
(`[FAIL`, `Suite result: FAILED`, or `Test result: FAILED`) and
`bugforge-fail:<specification hash>`. A failing stub, a stale harness, or a
failure for another test stays `unknown`. A passing suite stays `unknown`.
A passing run is not a proof.

The Phase 43 unit tests that feed runner output are simulated. They do not
show that `solc` or `forge` executed. Live tests are skipped when the binary
is missing.

## Evidence

A bound `proved_safe` or `counterexample` from SMT is static-analysis
evidence. A bound Forge `reproduced` with the raw output is reproduction
evidence. Every other status, including an authoritative-looking status that
failed `_downgrade`, is tool-status evidence. Evidence metadata carries the
specification hash, source digest, harness digest, manifest digest, proof
scope, tool, and tool version. The result's `artifacts` keep the manifest
and the harness text.

`lifecycle_effect` is `none`. Independent verification still requires a
signed server observation. This layer cannot move a finding to verified or
reported. `unknown` is not rewritten to `safe`. Static analysis is not
accepted as `reproduced`. A non-SMT tool cannot produce `proved_safe`.

## Bounds

Harness size 16_000 characters, sequence length 8, actors 4, verification
attempts 8, SMT timeout 30 seconds, Foundry timeout 60 seconds. Phase 41
caps still limit transitions, paths, depth, and invariants. The attempt cap
is reported on `BridgeResult.truncated` when it binds. There is no unbounded
symbolic execution, fuzz campaign, or all-path enumeration.

## Not claimed

BugForge does not encode reentrancy, authorization, allowance, debt,
ERC-4626 conservation, mapping sums, or cross-contract call sequences.
Foundry does not run inside the analyzed project when that project has
dependencies. The installed `solc` is not automatically the compiler pinned
by the project. A contract-copy proof is not a whole-program proof. No LLM
API is called from this layer.
