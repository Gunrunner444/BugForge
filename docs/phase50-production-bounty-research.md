# Phase 50: production bounty-research workflow

Phase 50 adds program-aware bounty research on top of the Phase 49
orchestrator. It adds a campaign manifest, semantic Solidity research
analyzers, impact-first triage, call-sequence generation, a compiler advisory
corpus, known-issue handling, and a deterministic report pack.

Nothing here verifies a finding, submits a report, calls a model, or widens a
scope or budget. Static evidence, corroboration, a differential divergence, a
fuzzer finding, a crash, an unexpected revert, and an economic divergence are
each not verification.

## Step 0: baseline audit of Phases 27-49

What Phase 49 already handles correctly:

- one engine per round, chosen deterministically from evidence
- a budget ledger that resume cannot raise
- evidence quality levels with no "verified" level
- contradictions that stay visible and negative evidence that never proves safety
- an authorization gate (`DefaultGate`) and a persisted, resumable state

What Phase 50 reuses unchanged: `Orchestrator`, `plan()`, `assess()`,
`BudgetLedger`, `ResearchState`, `check_gate`, `CampaignIdentity`, the
scheduler engine abstraction, `sequences.py` caps, the Phase 45-48 runtime
and fork machinery, and the Solidity compiler runner.

What was missing for real bounty research:

- no notion of a bounty program, its scope, rules, or known issues
- no caller-context, oracle, message-binding, or accounting analysis that works
  across contracts without relying on function names
- no impact-first ordering driven by program policy
- no compiler advisory knowledge tied to the compiler version in use
- no known-issue or duplicate handling
- no report a human can review

Regressions or architecture problems found: none. Two additive changes touch
shared code. `CampaignIdentity` gets an optional `program_context` that is left
out of `target_digest()` when empty, so existing digests do not change.
`detector_family` recognizes the new `sol.research.*` rule prefixes.

## Campaign manifest

`app/discovery/bounty/campaign.py` defines `BountyManifest`. It records the
platform, program id and name, program reference, rules version, in-scope and
out-of-scope assets, operator-supplied known issues, required PoC status,
allowed testing mode, repository and commit, deployments (chain, address,
contract), fork source, fork block and state snapshot, compiler version and
config, optimizer, viaIR, bytecode identity, severity categories, and notes.

- Unknown stays unknown. A missing field is never filled in.
- A contract is not in scope because it exists in the repository. Scope comes
  only from the operator's asset list.
- The manifest digest (`pc_...`) is the `program_context` of the campaign
  identity. It flows into every request, result, and finding.
- `request_extra()` carries the digest only. It never carries scope or approvals.

`BountyGate` (`gate.py`) wraps `DefaultGate`:

- the request digest must equal the manifest digest
- OUT_OF_SCOPE gives SCOPE_BLOCKED
- unknown scope allows local analysis only
- a fork run needs IN_SCOPE, `testing_mode=fork_allowed`, a pinned fork equal to
  the manifest's (chain id, block, state snapshot), and an approval
- a scope claim inside a request grants nothing

## Semantic analyzers

`app/parsing/solidity_research.py` is a bounded structural reader
(comments stripped, braces balanced). The analyzers share it and return
`SemanticCandidate` values that carry facts, observed items, missing items and
impact tags. They are static candidates.

| Family | Module | Looks for |
|---|---|---|
| caller_context | `solidity_caller_context.py` | `msg.sender` reaching an authorization decision through delegatecall, multicall, router dispatch or nested calls, path-sensitive, including interface receivers |
| oracle_quality | `solidity_oracle_quality.py` | price reads without freshness, round, deviation, or quorum checks |
| message_binding | `solidity_message_binding.py` | proofs and messages not bound to destination, chain, nonce or domain; signature replay; approval composition |
| account_abstraction | `solidity_account_abstraction.py` | ERC-4337 validation mismatches. Skipped when no such code exists |
| balance_delta | `solidity_accounting.py` | accounting from requested amounts instead of balance deltas; donation and fee-on-transfer mismatches |
| arithmetic | `solidity_arithmetic.py` | batch accumulation and asymmetric rounding |

Authorization is detected from guards and call structure, not names. An actor
name is not proof of authorization. Safe nested calls that change `msg.sender`
are modeled and do not fire. Missing evidence stays unknown.

`solidity_research_suite.py` runs the families and reports which ran and which
were skipped. The matching rules are `sol.research.<family>`.

## Prioritization and findings

`priority.py` produces a triage score. It is not exploitability. It uses
evidence-backed properties (value transfer, custody, vault accounting,
mint/burn, privileged operations, upgrade, arbitrary calls, router dispatch,
oracle value, bridge verification, signature authorization, AA validation,
liquidation, collateral, reserves, governance, roles, approvals). Impact
categories come from the program's policy, with no hard-coded rewards. When the
program requires a PoC, PoC-feasible candidates rank higher.

`findings.py` builds `ResearchFinding` records. The severity candidate is
separate from the confirmed severity, which is always "unconfirmed". If the
program lists no severity categories the candidate is "unknown". Qualification
statuses: `report_candidate`, `needs_poc`, `needs_scope`, `known_issue`,
`out_of_scope`. KNOWN ISSUE, OUT OF SCOPE and DUPLICATE do not mean SAFE.

## Call sequences, feedback, minimization

`vfcs.py` builds Vulnerable Function Call Sequences from real functions only,
with identity kept. It uses short templates such as authorize then execute and
deposit then donate then withdraw. It does not generate blind permutations.
Feedback-directed mutation is deterministic and bounded. Delta-debugging
minimization reports the original and minimized sequence, a completion flag and
a reason. A minimized sequence is not verification.

## Compiler intelligence

`advisories.py` matches against `data/solidity_advisories.json`, a local copy
of the official Solidity `bugs.json` (66 entries, source sha256
`cfca0ca0a571db9717c0244c602d4e59513f17d65e4fc724f6730ab7a13f3855`,
retrieved 2026-10-07; descriptions dropped). The analyzer never fetches it.
Refresh it by replacing the file from the official source and recording the new
hash. Statuses: `applicable_candidate`, `version_match_no_trigger`,
`version_match_unassessed`, `unknown`, `no_match`. A match needs the actual
compiler version and pipeline evidence. Unknown config stays unknown. Source
triggers exist for SOL-2026-1 to 6 and SOL-2025-1, and the official
`regex-source` checks are honored.

`compiler_diff.py` compiles under a bounded set of pipelines when a compiler
exists. `HostSolcBackend` needs the `solidity_host_compiler` setting and an
installed `solc`. Otherwise the result is UNAVAILABLE. BugForge never
downloads a compiler. A divergence is a candidate only, and only when an
advisory trigger, behavioral evidence and identity binding all agree.

## Report pack

`report_pack.py` builds a deterministic Markdown pack with 16 sections: Summary,
Program and rules, Scope status, Asset and source identity, Affected code, Root
cause, Impact claim, Severity candidate, Preconditions, Call sequence, Proof of
concept status, Evidence, Contradictions and negative evidence, Known-issue and
duplicate status, Compiler and tooling context, Uncertainty and limitations.
The pack has `verified=False` and `submitted=False`. There is no submission
code and no platform client.

## Orchestration integration

Nine new capabilities: `bounty_context_analysis`, `caller_context_analysis`,
`oracle_quality_analysis`, `proof_binding_analysis`,
`account_abstraction_analysis`, `accounting_analysis`,
`compiler_advisory_analysis`, `vfcs_generation`,
`compiler_differential_validation`.

- `bugforge-research` serves the first eight. `bugforge-compiler-diff` serves
  the differential and is available only when the compiler backend is.
- Results are INGESTED with `metadata["verified"] = "false"`. An engine refuses
  a request whose program context does not match its manifest.
- `bounty_context_analysis` runs only when a program context is present.
  `vfcs_generation` runs only when a research candidate exists.
- The planner is deterministic. Cursor suggestions stay bounded and validated.
- Report generation and minimization are library functions, not scheduled
  capabilities.

## Caps

| Cap | Value |
|---|---|
| Research files / file bytes / contracts / functions | 64 / 400,000 / 256 / 2,000 |
| Candidates per family / total | 64 / 256 |
| Caller-context edges / path depth / interface targets | 256 / 4 / 4 |
| VFCS length / candidates / mutations | 4 / 16 / 4 |
| Minimization attempts / feedback signals | 24 / 16 |
| Advisory matches / sources | 16 / 64 |
| Compiler pipelines / comparisons | 4 / 6 |
| Findings / report findings / pack chars | 128 / 32 / 120,000 |

Resume cannot raise a budget. Failed engines are not rerun automatically.

## Cursor control

Settings stay `controller = cursor`, `ai_controller = cursor`,
`provider = cursor_external`. BugForge calls no model and holds no API key.
Cursor cannot bypass authorization, change scope, raise a budget, approve live
testing, mark a finding verified, or submit a report. Real-chain testing needs
an explicitly authorized and pinned fork identity.

## Limitations

- The analyzers are heuristic and structural. They do not run a full compiler
  front end. They produce candidates, and false positives and negatives exist.
- `solc`, `forge`, `semgrep` and `docker` were not installed where this phase
  was built. The compiler differential is tested with a fake backend, and
  runtime and fork paths are tested through the existing fakes.
- The advisory source triggers cover seven entries. The others are
  `version_match_unassessed`.
- Report generation and minimization are not orchestrated capabilities.
- Duplicate detection depends on operator-supplied known issues. BugForge does
  not search platform history.
