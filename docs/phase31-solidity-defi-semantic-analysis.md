# Phase 31 — Solidity DeFi semantic analysis

Phase 30 built an intra-procedural CFG and def-use layer. Phase 31 corrects
the semantic checks that layer was already feeding, then adds an economic
model for tokens, vaults, and a small set of DeFi state transitions.

This is not a full DeFi protocol interpreter. Findings stay potential evidence.
Nothing in this phase marks a finding verified, confirmed, or exploited.

## Phase 30 corrections

### Initializers

A modifier named `initializer` is not protection. The body must check a prior
initialization or version state and then write that state before `_;`.

Protected shapes include `require(!initialized); initialized = true; _;`,
`if (initialized) revert();` before the write, and a monotonic version check
such as `require(version == 0)` or `require(_initialized < version)` before
the assignment. `initialized = true; _;` and `version = 1; _;` are not
protection. A check that runs only after `_;` does not protect the body.
A unique internal helper called before `_;` can carry the check. Two
definitions of that helper are not guessed.

### Reentrancy guards

`_reentrancy_locked` now requires a sequence that can be read from the
modifier body:

1. a check of the lock (`require(!locked)`, `require(_status != _ENTERED)`, or an equivalent revert),
2. an assignment of that same variable to an entered literal (`true`, `2`, `_ENTERED`),
3. the `_;` placeholder,
4. a clear to an open literal (`false`, `1`, `_NOT_ENTERED`).

`locked = true; _;`, `require(msg.sender == owner); _;`, and
`locked = computeLock(); _;` are not locks. The modifier name
`nonReentrant` is ignored. An OpenZeppelin-style `_status` pair is accepted
only when those three steps are visible. `Pausable` and `PullPayment` are
not treated as reentrancy guards.

### Modifier lookup

`ModifierIndex` resolves a modifier on the current contract, then through
bases in the same file and in other files. A base name that maps to more
than one contract is ambiguous. Two base contracts that both define the
modifier are ambiguous. Ambiguous, unresolved, and malformed bodies (no
`_;`) do not suppress authorization, initializer, or reentrancy findings.
The security engine installs the index for the graphs in the scan so
imported bases are visible without guessing.

### Signature nonce order

A nonce assignment is consumption only when it increments or decrements the
same nonce that reaches the `ecrecover` digest, on a path shared with that
call. `nonce = 1` does not consume a nonce. An increment after `return` is
not reachable and does not consume it. `nonces[owner]` in the digest is not
consumed by `nonces[attacker] += 1`.

`signature_nonce_order` distinguishes:

- `digest-verify-consume` — the signed nonce is incremented after verification,
- `consume-digest-verify` — the increment happens first and the updated value is what is signed,
- `consume-unrelated-verify` — a nonce changes, but a different message is recovered.

Both of the first two are still "nonce is in the digest and is consumed" for
the existing replay rule. That preserves the Phase 27 and Phase 28 bound
fixtures, which increment before hashing the new nonce. The analysis does
not claim the signature scheme is secure.

### Oracle observations

Each `latestRoundData()` or `latestAnswer()` call is one observation
(`oracle1`, `oracle2`, ...) with its own `roundId`, `answer`, `startedAt`,
`updatedAt`, and `answeredInRound` when those names are destructured.
Freshness from call 1 does not protect the answer from call 2. A lone
`latestAnswer` has no freshness component. An unrelated `updatedAt = block.timestamp`
is not part of the observation.

### Compiler tests

`compiler_semantics` is unchanged: a missing compiler returns `UNAVAILABLE`
and does not invent storage. The Phase 30 test no longer asserts that this
machine's `solc` or `forge` is absent. It monkeypatches the status and covers
absence, a present compiler with no runner, an invocation error, malformed
JSON, compiler errors, a storage layout, and a version-only payload.

## Token model

`analyze_defi` classifies calls by declared type, inherited interface name,
and method set.

- `IERC20`, `ERC20`, and `IERC20Metadata`, or a type that declares
  `transfer` and `balanceOf` plus another ERC-20 method, are strong ERC-20
  evidence.
- `IERC721`, `IERC1155`, and `IERC4626` are recognized the same way.
- An `address` used with `balanceOf`, `totalSupply`, `transferFrom`,
  `approve`, or `allowance` is ERC-20 by usage.
- `foo.transfer(a, b)` on an unresolved address, and `transfer` on a local
  contract that only happens to have that method, stay
  `unknown external transfer`.
- A one-argument `.transfer` is native Ether, not ERC-20.

The legacy `sol.erc20_unchecked_return` rule still keys off a transfer call
that ignores its return value. That is a call-shape check, not a claim that
the callee implements ERC-20.

Tracked roles, when the call shape provides them, are token, sender,
receiver, and amount.

## Fee-on-transfer

The rule no longer treats "a comma inside `.transfer`" plus a single
`balanceOf` string as the whole model. It flags an ERC-20 transfer or
`transferFrom` when accounting credits the requested amount
(`shares[user] += amount`) instead of a measured balance delta, and it still
flags a token movement that reads `balanceOf` once and never compares a
before/after pair. A before/after subtraction or comparison is not a finding.
A native `.transfer` of Ether is not a finding.

## Donation and inflation

A finding requires one conversion in which the vault's
`balanceOf(address(this))` (or `totalAssets` defined from that balance)
and `totalSupply` / `totalShares` are on the two sides of a division.
The words appearing in different expressions, a parameter named
`totalSupply`, or the string `"totalSupply"` do not qualify.

An offset on both sides of that division (`+ 1`, `+ 1e3`, `virtual`) is
treated as the virtual-asset/virtual-share mitigation described for
ERC-4626 inflation attacks. A variable named `virtualAssets` that is not in
the conversion does not suppress the finding.

## ERC-4626 style flows

Contracts do not need to inherit OpenZeppelin's ERC-4626. Functions named
`deposit`, `mint`, `withdraw`, `redeem`, and the matching `preview*` methods
are compared as:

- deposit: assets in, shares out
- mint: shares requested, assets required
- withdraw: assets requested, shares burned
- redeem: shares burned, assets returned

The rule flags a preview formula that does not match the executing function,
and a division that can round to zero shares or assets when the function
neither requires a non-zero result nor checks a caller-supplied minimum.
It does not claim the formulas match the standard's rounding modes.

## Rounding and slippage

`sol.rounding` is unchanged: division before multiplication. `sol.rounding_direction`
adds three economic cases:

- a withdraw, redeem, or swap that adds 1 after division (output rounded toward the caller),
- division before multiplication in an expression that is about shares, price, assets, collateral, or debt,
- a value that is divided again on every iteration of a loop.

`amount * 30 / 10000` and `totalSupply / 2` are not those cases.

Slippage is context-dependent. A swap or vault function with no minimum
argument is not a finding. A `minAmountOut`, `minShares`, `maxShares`, or
`deadline` parameter is a finding when it is never used, when it is compared
only with zero, or when the check happens after the accounting write it was
meant to constrain.

## Oracle, lending, and AMM

`sol.oracle_accounting` fires only when an oracle answer is multiplied or
divided into collateral, debt, shares, health, or liquidation. It explains
whether freshness belongs to that observation, whether a non-positive price
is accepted, or whether the expression mixes scales such as `1e8` and `1e18`.
It is not a second copy of "every oracle call needs a check."

Lending support is initial. It records debt and collateral transitions and
flags debt that is reduced with no token or value transfer, a health factor
that is checked from a snapshot taken before the debt or collateral write,
and liquidation math that mixes decimal scales.

AMM support recognizes `reserve0` / `reserve1` / `amountOut`. A quote that
only reads reserves is not a finding. A swap that transfers tokens without
updating reserves, that writes reserves before it computes the output, that
prices from `balanceOf(address(this))` while leaving stored reserves
untouched, or that applies `fee` to `amount0` but not `amount1`, is a
potential indicator. This is not a constant-product proof.

## Callbacks, approvals, and the state model

`sol.defi_reentrancy` treats an ERC-20 `transfer` or `transferFrom` as a
control transfer when an accounting variable (`shares`, `debt`, `collateral`,
`reserve`, and the same family) is written afterward. Checks-effects-interactions
and a guard that passes the reentrancy sequence above suppress it. Ether
`call` reentrancy remains `sol.reentrancy`. ERC-721 and ERC-1155 receiver
hooks remain `sol.callback_reentrancy`.

`sol.approval` looks at permit-style functions. It flags a spender or token
that is written into an allowance but does not reach the digest, a nonce that
is not consumed, a domain separator that is in scope but not in the digest,
and `increaseAllowance` implemented as a replacement instead of an addition.
A normal `approve` that sets an allowance is not reported by itself.

`EconomicTransition` records an action (`deposit`, `withdraw`, `mint`,
`redeem`, `borrow`, `repay`, `liquidate`, `swap`, `addLiquidity`,
`removeLiquidity`, `permit`) plus user effects (shares, debt, collateral,
allowance), protocol effects (total shares, total assets, reserves), and
token flows. Later Solidity phases should extend this model instead of
adding unrelated detectors.

## Tests

`backend/tests/test_phase31/` covers the Phase 30 corrections and the DeFi
matrix: standard and non-standard transfers, fee-on-transfer versus a
measured delta, empty-vault donation versus a virtual offset, ERC-4626
preview mismatch and zero-share deposits, oracle observations, lending,
AMM reserves, callback ordering, and permit binding. Adversarial fixtures
use the suspicious words without the corresponding relationships.

Phase 27 through Phase 30 suites are still required. The compiler test was
rewritten because asserting `UNAVAILABLE` on the host made the suite depend
on which binaries happen to be installed. The compiler behavior under test
is the same.

## Known limitations

- Modifier resolution does not evaluate `using for`, storage aliases, or
  modifiers reached only through assembly.
- Token classification is structural. It does not execute a token or prove
  fee-on-transfer behavior.
- Share math is recognized per function, not across an entire inheritance
  hierarchy of vault implementations.
- ERC-4626, lending, and AMM coverage is a set of relationships, not a model
  of Uniswap, Aave, or Compound.
- Oracle wrappers that hide `latestRoundData` behind an unresolved helper
  stay unresolved.
- Signature order is not a proof of EIP-712 or EIP-2612 compliance.
- Cross-contract reentrancy beyond a token call in the same function is still
  limited to the Phase 30 call/write rules.
