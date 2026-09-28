# Third-party notices

## Awarexone/Agentic-Bug-Hunter

- Source repository: https://github.com/Awarexone/Agentic-Bug-Hunter
- Source commit inspected: `93aa1fe6642e8e2aca3e26a0d49ad2d2dcaa1e0a`
- License: MIT (Copyright (c) 2026 Claude Bug Bounty Hunter Contributors)
- Source paths reviewed: `skills/web3-audit/SKILL.md`, `skills/bb-methodology/`, `skills/bug-bounty/`, `skills/triage-validation/`, `skills/security-arsenal/`, `bughunter/tools/lead_board.py`, `web3/`
- BugForge destination: none copied
- Reuse type: independently reimplemented

No source file from that repository was copied into BugForge. Methodology ideas (accounting desynchronization, sibling-function comparison, boundary checks, ERC-4626 inflation, flash-loan-aware spot pricing, lead status, and chain planning) were reimplemented against BugForge's syntax graph, evidence model, and research tables. The MIT copyright notice is recorded here because the methodology was consulted. BugForge's own license continues to cover the new code.

Referenced third-party tools and wordlists in Agentic-Bug-Hunter were not copied.

## fuzzland/ityfuzz

- Source repository: https://github.com/fuzzland/ityfuzz
- BugForge destination: none copied
- Reuse type: optional external executable
- Interface inspected: 2026-09-28, off-chain stdout (`ityfuzz evm -t <glob>`, `Found vulnerabilities`, Description, Trace, Stats, Coverage Summary). Documentation reference: https://docs.ityfuzz.rs/quickstart
- Integration: `app/adapters/discovery/ityfuzz.py` runs that command inside Docker when `security_agent_ityfuzz_image` names an image the operator already has. Public RPC and fork campaigns are rejected. A missing image produces no findings. Host `ityfuzz` is not a fallback.

BugForge does not vendor ItyFuzz source, does not copy its tests, and does not relicense it. The upstream project states its own license. The adapter records that the executable is third-party. No benchmark repository is copied into BugForge.
