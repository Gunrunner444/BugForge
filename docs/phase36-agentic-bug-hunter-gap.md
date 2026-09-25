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

## Limitations

- Sibling families are a fixed name set, not a full semantic embedding.
- Accounting comparison needs the coupled names in both function bodies.
- Implementation storage collisions require a delegatecall in the same graph and a shared variable name.
- Yul remains incomplete when a block exceeds the configured node cap.
- Exploratory Docker still does not contain `forge`.
