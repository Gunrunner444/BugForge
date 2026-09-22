# Phase 27 — multi-engine discovery and Solidity

Phase 28 hardens this loop and the Solidity rules. See
[phase28-solidity-deep-analysis.md](phase28-solidity-deep-analysis.md).
The status words below are unchanged.

BugForge can turn a static location into a bounded research target, choose
engines that are actually available, and store their output on the existing
evidence graph. An engine result is not a verified finding.

## Status words

| Word | Meaning |
|---|---|
| planned | The scheduler named an engine and did not run it |
| available | The engine factory is registered and its binary or in-process implementation is present |
| installed | `availability()` is `available` |
| executed | The adapter ran and set `executed=true` |
| results_ingested | Output was normalized into `DynamicResult.findings` |
| candidate finding | Static or tool observation with status `potential` |
| corroborated | Independent non-AI evidence, through the existing finding lifecycle |
| reproduced | A reproduction record, still not verified |
| verified | Only `SecurityFinding.verify` with independent evidence |

AI text, a scanner row, and a fuzzer input do not call `verify`.

## Discovery loop

`DiscoveryScheduler` picks complementary engines from language, framework,
harness presence, availability, difficulty, and a campaign budget. It does not
send every repository through every engine.

Registered engines:

| Engine | Role | When it runs |
|---|---|---|
| bugforge-static | In-process `SecurityAnalysisEngine` | Selected for Solidity and several other languages |
| slither | Optional static JSON | Installed `slither` binary |
| foundry | `forge test`, including a `--match-test` filter | `foundry.toml` or an explicit harness, and `forge` is installed |
| echidna | Property campaign | Installed `echidna` binary and a target file |
| medusa | Coverage-guided fuzz | Installed `medusa` binary |
| halmos | Symbolic tests | Installed, and the target is marked difficult or a prior round stagnated |
| wake | Optional extra detectors | Installed `wake` binary; not required |

C, C++, Java, and Python have scheduler names for coverage fuzzing, sanitizers,
Jazzer, and property tests. Those names are not registered adapters. The
scheduler records them as not registered. It does not pretend they ran.

A static finding can become the next `AnalysisRequest` (`file`, `function`,
`contract`, rule id). A dynamic result can add a crash or symbolic seed to
`DiscoveryCorpus` and mark the next target difficult when coverage does not
move. Seeds store a hash and a redacted preview, not a raw secret.

## Oracles

`app.discovery.oracle` explains whether an execution is meaningful. A nonzero
exit code is not enough. A sanitizer diagnostic, an assertion or property
failure, or a real crash is. This is separate from the reproduction oracles in
`app.security_agent.oracles`.

## Evidence

`record_discovery_chain` writes hypothesis, fuzz target, campaign,
counterexample, and oracle nodes on the existing `EvidenceGraph`. Relations
include `motivates` and `produces`. `correlate_results` groups the same
contract, function, and detector family. Two rows from one engine and detector
are one observation. The group is never marked verified.

## Solidity

Tree-sitter builds the syntax graph: contracts, interfaces, libraries, structs,
enums, events, errors, modifiers, constructors, fallback, receive, functions,
visibility, state variables, imports, inheritance, using-for, overrides, calls,
and selectors when every parameter type is a primitive. Selectors are
Keccak-256, not SHA3.

Rules cover reentrancy (including a checks-effects-interactions negative),
`tx.origin`, unchecked low-level calls, arbitrary versus immutable
`delegatecall`, missing authorization, downcasts, explicit `unchecked`
arithmetic, pre-0.8 arithmetic, division before multiplication, `ecrecover`
without a nonce, initializers, a mutable implementation slot used with
`delegatecall`, unbounded external loops, ignored ERC-20 `transfer` returns,
token-hook reentrancy, and upgrade functions without an auth modifier.

Solidity 0.8 checked arithmetic is not reported as overflow. Rules do not run
on a profile-fallback graph. Quality rules (empty fallback/receive, shadowing,
unbounded pragma, assembly, `throw`/`suicide`) stay in the code-quality catalog.

Same-file order of calls and state writes is limited data flow. Cross-contract
type checking, storage layout, and Yul control flow are not claimed. `solc` is
not required. If `solc` or `forge` is installed, the capability matrix says
compiler AST support is limited because the graph itself remains Tree-sitter.

Candidate Foundry tests can be validated with the Solidity parser. They are
refused if the destination is inside the analyzed repository.

## Local execution

Optional tools run as argument lists through a local subprocess with BugForge
secrets removed and output redacted. Nothing is downloaded. Fork URLs are
rejected by the Foundry adapter. Live network testing still has to pass
ScopeGuard, SafetyController, and the existing approval path. There is no
bypass.
