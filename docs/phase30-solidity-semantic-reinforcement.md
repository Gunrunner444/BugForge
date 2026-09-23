# Phase 30 — Solidity semantic reinforcement

Phase 30 stays on Solidity. It audits the Phase 29 CFG and rules, then replaces
several text-presence checks with control-flow and def-use checks. It does not
add another language and it does not claim compiler-equivalent analysis.

Static findings remain potential evidence. Nothing in this phase sets
`verified`, `confirmed`, `exploited`, or `proven`.

## What Phase 29 got wrong

- Loop bodies were one CFG node plus a self-edge. A call and a later write
  inside the loop could look like the same node, so path checks returned false.
- `break`, `continue`, `while`, `do while`, `unchecked`, and `try/catch` were
  not real edges.
- Modifier names such as `onlyOwner` and `nonReentrant` suppressed findings
  even when the body was only `_;`.
- `sol.signature_replay` treated any `nonce` in the function as protection,
  including `nonce += 1` next to `ecrecover` of an unrelated hash.
- `sol.stale_oracle` went silent if the word `updatedAt` appeared anywhere.
- `sol.storage_collision` returned no finding whenever an EIP-1967-looking
  constant existed, even if `delegatecall` still used a mutable storage variable.
- Loop bounds treated any `[N]` in the function, and the absence of `[]`, as a
  fixed array. The bound was not the loop header's collection.
- `while` and `do while` were not `sol_loop` events.
- Enums, user-defined value types, and contract/interface types did not
  canonicalize, so selectors stayed unresolved or were impossible.
- Inline Yul was only `sol_assembly` text. Security-relevant opcodes were not
  identified.

Phase 27 and Phase 28 tests that encoded the nonce-anywhere and empty-initializer
behavior were updated so the fixture matches the check they claim to make. The
tests were not deleted.

## CFG

`build_function_cfg` now splits:

- straight-line statements
- `if` / `else` / `else if`, including braceless branches
- nested `if`
- `for`, `while`, and `do while`, with the body in its own nodes
- `require` / `assert` failure edges
- `return` and `revert` edges to the function exit
- `break` to the loop exit and `continue` to the loop header
- `unchecked` blocks as their inner statements
- `try` / `catch` bodies joined after the try

A back edge stays inside the loop. A write before the loop is not reachable
from a call inside it. The next iteration of the loop is reachable from
`continue`. Unknown or unbalanced braces set `known` false. Rules must not
treat that as safe.

An authorization check protects an operation only when it dominates that
operation. `require(msg.sender == owner)` and `if (msg.sender != owner) revert()`
can protect later operations. A check on one branch does not protect the other.
A check after the operation does not protect it. `owner = msg.sender` is an
assignment, not a check.

## Dataflow

`analyze_flow` is intra-procedural reaching definitions on that CFG. It records
assignments, parameters, `keccak256` uses, index expressions, and source spans
on `FlowEdge`. It is not a compiler SSA.

`signature_replay_gap` reports a gap unless a `nonce` or `nonces` value reaches
the `ecrecover` digest and that variable is consumed in the function.
`signature_domain_gap` reports a gap unless the digest actually includes a
domain separator, chain id, `address(this)`, or type hash. Computing those
values and not hashing them does not count.

`oracle_freshness_protects` is true only when `updatedAt` or `answeredInRound`
from `latestRoundData` dominates every use of that call's answer. A local
`updatedAt` does not. `latestAnswer` has no freshness component and stays a
potential finding. Unknown flow does not suppress the finding.

## Authorization and reentrancy

`onlyOwner`, `onlyRole`, and `nonReentrant` count only when the modifier body
in the same file shows the check or the lock before `_;`. An unresolved
imported modifier is not assumed to be a guard.

Sensitive operations are owner/admin/implementation/role/supply writes,
native value transfer, and delegatecall. A function named `withdraw` or `mint`
with an empty body is not a finding. A resolved internal helper that is itself
a guard counts when the call dominates the operation.

Reentrancy requires a control-transfer (`call`, `delegatecall`, `staticcall`,
`send`, `transfer`, `safeTransferFrom`) and a later state write on the same
path that is read before the call, used by the call, shared with the call's
arguments, an accounting variable (`balance`, `share`, `supply`, ...), or a
`delegatecall`. `counter = 2` after an unrelated call is not a finding.
Cross-function reentrancy requires the callee to write state the caller also
reads or writes. An internal helper that only touches a local does not.

## Loops, tokens, proxies, assembly

The loop header is the bound. `i < 10`, `min(length, MAX)`, and `T[N]` for the
collection in that header are bounded. A `[4]` somewhere else in the function
does not bound `users.length`. `while` and `do while` are loops. State growth
includes index assignment and `.push`.

`sol.fee_on_transfer` requires an ERC-20-shaped `transfer` / `transferFrom`
(a comma in `transfer`, or `transferFrom`) and fewer than two `balanceOf`
reads. `payable(to).transfer(amount)` is native ether. Donation findings
require `balanceOf(address(this))`, `totalSupply`, and division in the same
statement.

Storage collision fires when `delegatecall` targets a mutable `implementation`
or `impl` variable. An EIP-1967 constant in the same file does not remove that
finding. A proxy that only `sload`s the standard slot and `delegatecall`s in
Yul does not take this finding. The Yul `delegatecall` is still
`sol.assembly_sensitive` potential evidence. `mload` / `mstore` / `sload` alone
are recorded as Yul but are not that finding. Unknown Yul is not treated as safe.

## Types and the compiler

Same-file enums canonicalize to `uint8`, `type X is T` to the underlying ABI
type, and contract or interface names to `address`, when the definition is in
the file. Structs, arrays, and tuples still compose. Selectors stay empty when
any component is unknown. Fixed-point and function types that this parser
cannot represent stay unresolved.

`unique_abi_aliases` accepts a name only when exactly one `sol_type_def` in the
supplied graphs provides it. `selector_for_function` uses that map.
Single-file parsing does not guess a type that is not defined in the file.

`solidity_compiler_status` is `UNAVAILABLE` when neither `solc` nor `forge` is
on `PATH`. `compiler_semantics` then returns no storage layout. A standard-JSON
payload is parsed only after a compiler is reported available. Garbage JSON is
`FAILED`, not a made-up slot. Tree-sitter remains the syntax graph either way.

## Tests

`backend/tests/test_phase30/` covers CFG paths, digest and oracle flow, auth
modifiers and helpers, reentrancy and cross-function cases, loop bounds,
signatures, oracles, fee-on-transfer, donation accounting, proxies, Yul,
type canonicalization, imported selectors, and the compiler overlay.

Phase 27–29 suites still run. External Foundry, Slither, Echidna, Medusa,
Halmos, and Wake binaries were not installed here, so their adapters stay
`UNAVAILABLE` or `NOT_IMPLEMENTED`. Those results were not simulated.

## Limitations

- The CFG and dataflow are intra-procedural and brace-based. They miss
  assembly control flow, modifier order beyond "a resolved guard runs first",
  and most aliasing.
- Inherited OpenZeppelin modifiers are not guards until their bodies are in the
  analyzed files.
- Reentrancy does not model gas stipends or token-specific callback standards
  beyond the hook names and call kinds above.
- Oracle support is `latestRoundData` / `latestAnswer` destructuring, not every
  wrapper or sequencer uptime feed.
- Storage layout from `solc` is not applied back onto the syntax graph.
- Cross-file selectors require the explicit alias helper. Ambiguous names stay
  unresolved.
- Yul is opcode-level. Raw selector dispatch is not reconstructed.
- A passing or failing fuzz campaign is still not a formal proof. Verification
  stays on BugForge's existing evidence lifecycle.
