# Phase 36 — Agentic-Bug-Hunter gap review

Inspected commit: `93aa1fe6642e8e2aca3e26a0d49ad2d2dcaa1e0a` (MIT).
BugForge base: Phase 35 `df410ba` plus the local compiler, calldata, and cross-contract bound work.

No second AI controller was added. Cursor remains the planner. Scanner output and proposed chains stay unverified until BugForge's existing evidence rules say otherwise.

## Gap matrix

| Capability | Agentic-Bug-Hunter | BugForge before | Status | Action |
| --- | --- | --- | --- | --- |
| Feature and vulnerability hunting methodology | Skill markdown | Cursor docs, no Web3 sibling method | PARTIAL | Reimplemented as graph checks and this doc |
| Persistent leads | `lead_board.py` JSONL | `research_memory` only | MISSING | `research_leads` table, `LeadStore`, and `save_lead` |
| A→B→C chains | Prompt guidance | Evidence edges, no chain gate | PARTIAL | `ExploitChain` cannot verify without per-step evidence |
| Accounting desync | Grep playbook | DeFi rules, no sibling write diff | MISSING | `sol.accounting_desync` |
| Sibling authorization | Documented rule | Per-function auth only | MISSING | `sol.sibling_auth` |
| Boundary / off-by-one | Grep playbook | No sibling operator diff | MISSING | `sol.boundary` |
| ERC-4626 inflation | Playbook | Preview mismatch and zero-share notes | PARTIAL | `sol.erc4626_inflation` |
| Flash-loan paths | Playbook | No spot-price gate | MISSING | `sol.flash_spot` (name alone is not a hit) |
| Storage collision across implementations | Not a detector | Proxy-vs-impl only | PARTIAL | Implementation-upgrade comparison |
| Semgrep | Arsenal docs | Nuclei and ZAP only | MISSING | Optional adapter; static evidence; UNAVAILABLE without a binary |
| OOB / interactsh | Arsenal docs | None | MISSING | Session-bound ledger, no network client |
| Attack-surface priority | Lead routing table | Agent budget | PARTIAL | Deterministic `prioritize` |
| Foundry in exploratory image | Host forge assumed | Image has no forge | PARTIAL | Left as a toolchain gap |
| Yul completeness | Not modeled | Hard cap | PARTIAL | Caps are now settings, still bounded |
| Second LLM provider | Groq integration | Cursor / mock | DUPLICATE/NO NEED | Rejected |

## Adopted

Independently reimplemented. See `THIRD_PARTY_NOTICES.md`.

## Intentionally excluded

- Copying skill markdown, wordlists, or the Groq client
- TVL and payout scoring
- ffuf, interactsh network registration, or a new AI router
- Treating Semgrep or an OOB callback as a verified bounty
- Replacing ScopeGuard, evidence, replay, or Foundry exploratory

## What is actually wired

- Research leads are rows in `research_leads`. Saving a research session writes them. Restoring that session loads them by project key and puts unresolved and stale leads in the planner context. Killed and reported leads stay closed.
- A new hypothesis opens or updates a lead. It does not verify the lead.
- Wide versus deep is a planner route on the session. It does not change safety limits.
- Chains are stored in the existing research-memory table as `exploit_chain` entries and restored with the session. A proposal is not verified.
- Semgrep can ingest JSON and, when a process runner and binary are both present, scan one local path. A missing binary is unavailable. Output is static evidence and cannot verify a finding. There is no live-target scan.
- OOB is a correlation ledger plus an empty provider. There is no interactsh client. A callback is not verification.
- Storage collisions can be different names at the same slot and offset when a delegatecall proxy is in the same graph. Uncertain layouts are incomplete, not collisions. Append-only upgrades are not slot collisions. Cross-repository proxy identity is still not inferred.

## Limitations

- Sibling families still start from a name set. An empty public function is not a missing-authorization finding.
- Accounting still needs a shared coupled name, or a write that the sibling also uses, plus an early return.
- A boundary finding requires the comparison to guard a value write or transfer.
- ERC-4626 inflation requires at least two vault entry points, not a stray `totalSupply`.
- Flash-spot ignores view functions, oracle reads, and a function that merely is named `flashLoan`.
- Yul remains incomplete past the configured node cap.
- Exploratory Docker still does not contain `forge`.
- Deployment and source identity mapping is unchanged.
