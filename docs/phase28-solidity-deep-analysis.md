# Phase 28 — discovery hardening and Solidity deep analysis

Phase 27 added the discovery loop and the first Solidity catalog. Phase 28
audits that loop and makes the Solidity path more precise. Static output is
still a hypothesis.

## What the audit changed

`motivates` was already on the evidence-graph allowlist. `record_discovery_chain`
still uses it for hypothesis → fuzz target, and now also records execution,
seed, counterexample, oracle, and reproduction nodes. Invalid relations are
still rejected. Snapshot and restore keep the relation string.

The in-process static engine takes its languages from adapters that implement
security analysis. A request that names Python does not scan `.sol` files.

The scheduler still does not run every installed tool. Wake stays off unless
the request asks for it. Echidna and Medusa wait for a contract, function, or
harness. Halmos waits until a dynamic result reports coverage that is not new.
A later round can turn a Halmos counterexample into a corpus seed and a Foundry
fuzz mode. Those transitions are stored as reasons. None of them call
`SecurityFinding.verify`.

Corpus identity is the SHA-256 of the original seed. The stored preview is
redacted. The same hash, source, and target are one seed. Snapshots keep
provenance and do not keep the raw secret.

Oracles separate an expected revert, an unexpected revert, a panic, an
out-of-gas observation, a fuzzer crash, and a compiler or tool failure. A
nonzero exit, including an HTTP 500, is not a vulnerability by itself.

## Solidity analysis

Tree-sitter remains the graph builder. Profile fallback is labeled and the
security rules do not run on it. `solc` is not required and is not pretended
to be the graph.

Selectors use Keccak-256 of the canonical argument list. `foo()` has a
selector. `uint` is `uint256`. Dynamic arrays, fixed arrays, and `address
payable` canonicalize. A struct in the same file becomes its field tuple when
every field canonicalizes. If Tree-sitter reports an error, or a type cannot
be canonicalized, the selector is empty and `selector_status=unresolved`.

Reentrancy looks at order. A later write of a variable that was read before a
value-bearing call is reported. A write that already happened before the call,
with no earlier read, is not. `staticcall` is not treated as that call.
Authorization is a `require`/`if` comparing `msg.sender`, `hasRole`, or a
modifier named `onlyOwner`, `onlyRole`, `onlyAdmin`, `authorized`, `auth`,
`requiresAuth`, or `requiresRole`. `owner = msg.sender` is not a guard.

A low-level call is checked only when `require` wraps it or a later
`require`/`if`/`assert` names the success flag. `emit Something(ok)` does not
count. `transfer` is not the unchecked-call rule; `send` is, because it
returns a boolean.

`abi.encodePacked` is reported only when the packed values used by
`keccak256` include more than one dynamic argument, or a dynamic argument
plus an unknown one. Fixed-width arguments are not reported. `block.timestamp`
in a deadline comparison is not reported as randomness. The same value inside
`keccak256`, or in a function whose name is a lottery or random draw, is a
potential observation.

Other potential observations added in this phase: signature use that has a
nonce but no domain, chain, or `address(this)` binding; `selfdestruct` with
the compiler floor recorded and no claim that every EVM version behaves the
same; signed-to-unsigned casts; oracle reads that never mention `updatedAt`
or `answeredInRound`; share math based on `balanceOf(address(this))` and
`totalSupply`; and a fee-on-transfer indicator when `transfer` is paired with
a single `balanceOf`. These are indicators. They are not verified findings.

Invariant suggestions require a relationship. `totalSupply` alone does not
produce a supply-conservation candidate. A balance mapping plus a mint,
burn, or transfer that mentions supply does. Every candidate has
`valid=false`.

A candidate Foundry harness copies the parsed parameter list. `withdraw(uint256 amount)`
does not become `withdraw()`. The harness is still not written into the
repository under analysis.

## External tools

| Tool | License | What BugForge runs |
|---|---|---|
| Slither | AGPL | `slither . --json -` when installed. JSON is normalized. No JSON means no finding. |
| Foundry | MIT/Apache | `forge build`, `forge test`, `forge test --fuzz-runs`, an invariant `--match-test`, or `forge coverage`. `foundry.toml` is read. `--fork-url` is rejected. |
| Echidna | AGPL | `echidna <file> --format text`, plus `--contract` and `--config` when those exist. Falsified properties and call sequences are parsed. |
| Medusa | AGPL | `medusa fuzz`, plus `--config medusa.json` when present. Coverage is recorded only when the output contains it. |
| Halmos | AGPL | `halmos --contract --function` only after the target is difficult. Otherwise the status is `planned` and nothing is executed. |
| Wake | ISC | `wake detect` for static ingestion and `wake fuzz` for a fuzz campaign. Lines that do not look like `file:line` are not findings. |

Source for the AGPL tools is not copied into this repository. Nothing is
downloaded. Commands are bare executable names resolved from `PATH`. A
path-qualified command is refused. Secrets used by BugForge are removed from
the child environment. Timeouts are `timeout`, compiler failures are
`tool_failure`, and neither is a contract vulnerability.

## Limits

Same-file statement order is not a control-flow graph. Assembly, Yul, and
cross-contract callbacks are not fully modeled. Storage layout is not
computed, so an EIP-1967 constant is recognized as a marker rather than a
proof of a slot collision. A variable named `implementation` is not, by
itself, a proxy bug. DeFi names such as `price` or `collateral` do not create
a finding unless the rule also sees the operation it describes.
