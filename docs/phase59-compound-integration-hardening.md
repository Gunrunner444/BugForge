# Phase 59: Compound integration hardening

Phase 58 deployed the pinned `CometWithExtendedAssetList` and held an unauthorized `pause`. Two limits remained. Any revert plus an unchanged getter could hold the authorization property, and one constructor sequence stayed inconclusive because its argument was not ABI-expressible. The Compound tests also skipped in CI when the external tree was absent. Phase 59 closes those gaps on the same campaign pipeline. It does not add an execution engine, and it does not claim a vulnerability.

The pinned source stays outside BugForge, at commit `f766f51583c23acc33b2a7824654ef2029a96804`. Its license is BUSL-1.1. BugForge does not vendor it.

## Authorization oracle

`pause` in the pinned source is:

```solidity
if (msg.sender != governor && msg.sender != pauseGuardian) revert Unauthorized();
```

`error Unauthorized();` is declared in `CometMainInterface.sol`. The selector is the first four bytes of `keccak256("Unauthorized()")`, computed with BugForge's Keccak implementation, not NIST SHA3.

When that declaration is present, `call_must_fail` for this property requires all of the following:

- The configured governor calls the same `pause(true, false, false, false, false)` and the call succeeds.
- `isSupplyPaused()` changes across that authorized call.
- The attacker call reverts.
- The revert data is at least four bytes and the selector equals the declared error.
- `isSupplyPaused()` is unchanged across the attacker call.

A different selector, missing or truncated revert data, an unreadable getter, a failed control, or a control that does not change state is `not_evaluated`. A successful attacker call, or a getter change across that call, is `property_violated`. `property_held` is not a strong candidate and is not verified.

Other `call_must_fail` and `second_call_must_fail` oracles that do not name a selector keep the previous rule: a revert can hold the property. An arbitrary revert elsewhere in BugForge is not turned into an authorization verdict.

The positive control is harness setup. It is not a second finding.

## Profile types and source binding

`prepare_profile` reads struct declarations from the hashed files. It checks, recursively:

- constructor parameter name and struct type
- field names in source order, including missing, extra, duplicate, and reordered fields
- integer width (`uint8` rejects 256; `uint64` and `uint128` use their real bounds)
- booleans, address roles, and address fixtures
- array element types and length, up to 24 elements
- nested structs, including a struct declared in another bound file
- enums and user-defined value types, which are rejected as `profile_type_unsupported` because this parser does not resolve them

A value is not accepted merely because a different type would compile. Imports and the struct file must be in `bound_files` and match their hashes. A profile `source_commit`, when set, must equal the campaign manifest's `source_commit`. A target-file hash is not treated as the whole snapshot. Mismatches use reason codes such as `profile_source_mismatch`, `profile_dependency_unbound`, `profile_type_mismatch`, `profile_integer_bounds`, and `profile_source_revision_mismatch`.

There is still no Solidity expression, shell command, guessed constructor argument, ambiguous implementation, RPC, or weaker execution bound. Without an accepted profile, an unknown struct still fails closed.

## The Phase 58 constructor sequence

The inconclusive sequence is `arithmetic.unsafe_downcast_after_arithmetic@CometWithExtendedAssetList.constructor()`, template `boundary-batch`. The parser records the signature as `constructor()` and drops the `Configuration` parameter from that signature. The sequence was treating the constructor as an ordinary external call.

Phase 59 does not encode that call and does not delete the sequence. Harness build returns `constructor_not_a_call` before deployment arguments are guessed. The sequence stays submitted, with outcome `inconclusive`, and it does not increment the Foundry count. A normal external call such as `poke(uint256)` is unchanged.

## Non-empty asset list

`AssetConfig` in the pinned `CometConfiguration` is `address asset`, `address priceFeed`, `uint8 decimals`, three `uint64` factors, and `uint128 supplyCap`. `AssetList` requires price-feed decimals 8, token decimals equal to the config, `borrowCollateralFactor < liquidateCollateralFactor`, and `liquidateCollateralFactor <= 1e18`. Factors are then descaled by `1e14`.

The asset profile configures one collateral:

| Field | Value |
|---|---|
| asset | local token fixture, 18 decimals |
| priceFeed | local feed fixture, 8 decimals |
| borrowCollateralFactor | `5e17` (descales to 5000) |
| liquidateCollateralFactor | `8e17` (descales to 8000) |
| liquidationFactor | `9e17` (descales to 9000) |
| supplyCap | `1e18` (one whole token after the 18-decimal descale) |

The factory fixture is the pinned `AssetListFactory`, which deploys the pinned `AssetList`. The holder fixture only returns that factory. The target file is not edited. The pause profile still uses an empty `assetConfigs` array and the stub factory, so the authorization campaign does not depend on collateral.

`getAssetInfo(uint8)` returns `CometCore.AssetInfo`. Under Solidity 0.8.15 that static struct is eight words with no leading offset. Word 0 is `offset`. Word 1 is `asset`. The oracle reads word 1 and compares it to the deployed collateral fixture. A match is `property_held`. A different word is `property_violated`. A failed call or a short return is `not_evaluated`. This is not the pause property under another name, and it does not call `getPrice` or a live oracle.

## Compiler and EVM

The campaign still requests Solidity 0.8.15, optimizer on, 1 run, `via_ir` on, and EVM `cancun`. Solidity 0.8.15 cannot apply Cancun, so the run records requested `cancun`, applied EVM empty, and `evm_exact` false. That is not an exact upstream build and not a deployed-bytecode reproduction. The compiler resolved for the campaign is the pinned 0.8.15 binary under `~/.bugforge/solc/0.8.15/solc`. `PATH` may still provide another `solc`; the campaign does not substitute it.

## Measured campaigns

Both runs used the local checkout of `f766f51583c23acc33b2a7824654ef2029a96804`, Foundry offline, and no RPC.

Pause authorization:

- 3 sequences generated
- 1 excluded before submission (`getPrice`, oracle testing prohibited)
- 0 generation skips
- 2 submitted
- 1 Foundry invocation, 1 compiled harness, 1 executed sequence
- 1 `property_held` for `pause`, with the `Unauthorized()` selector and `positive_control` `changed`
- 1 `inconclusive` sequence, reason `constructor_not_a_call`
- `verified` false, and no strong candidate

Asset list:

- 5 sequences generated
- 3 excluded before submission: 1 oracle-testing prohibition and 2 outside the named contract scope
- 1 generation skip: a duplicate sequence
- 2 submitted
- 1 Foundry invocation, 1 compiled harness, 1 executed sequence
- 1 `property_held` for `getAssetInfo(uint8)`, word 1 equal to the local collateral address
- 1 `inconclusive` sequence, reason `constructor_not_a_call`
- `positive_controls` 0 on this campaign, because this property is not the pause control
- `verified` false, and the held finding strength is `property_held`, not strong

Reloading each campaign reproduces the forge count, outcomes, and reason codes. One held property does not hide the inconclusive constructor sequence.

## CI

`.github/workflows/backend.yml` keeps the existing pytest job, which does not fetch Compound and does not set `BUGFORGE_REQUIRE_COMET`. A new `compound-integration` job checks out `compound-finance/comet` at the pinned commit, verifies the commit and the required sources, installs Foundry 1.8.5 and the checksummed `solc` 0.8.15, sets `BUGFORGE_COMET_ROOT` and `BUGFORGE_REQUIRE_COMET=1`, and runs the Phase 58 and Phase 59 Compound tests with `FOUNDRY_OFFLINE=true` and `FOUNDRY_FFI=false`. A missing tree fails those tests instead of skipping them. The Foundry process is still offline.

## What this does not establish

The local evaluation shows that this pinned source, compiled with Solidity 0.8.15 and the settings above, deploys under the stated local configuration, that an unauthorized `pause` reverts `Unauthorized()` without changing the pause flag after a governor pause succeeds, and that `getAssetInfo(0)` returns the one configured collateral address. It does not show deployed bytecode, a mainnet market, a live price, liquidation safety, or a novel vulnerability. Public issues 1103 and 1104 are not findings.

## Reproduce

```bash
cd backend
FOUNDRY_OFFLINE=true BUGFORGE_COMET_ROOT=/tmp/comet BUGFORGE_REQUIRE_COMET=1 \
  pytest tests/test_phase58/test_comet_pause_campaign.py \
         tests/test_phase59/ -vv
```

`solc` 0.8.15 must be installed at `~/.bugforge/solc/0.8.15/solc`. Foundry must be on `PATH`. Without `BUGFORGE_REQUIRE_COMET=1`, a missing tree skips the Compound tests. `BUGFORGE_REQUIRE_FOUNDRY=1` requires the compiler for the Foundry job and does not by itself require the Compound tree.
