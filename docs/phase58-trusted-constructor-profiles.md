# Phase 58: trusted constructor profiles

Phase 57 could select `CometWithExtendedAssetList` and bind Solidity 0.8.15, but the campaign never reached Foundry. The constructor takes `Configuration memory config`, and the harness refuses to invent a struct. That refusal stays in place. Phase 58 adds an explicit profile for the cases where every value is typed, local, and bound to a source hash.

## Profile

`constructor_profile.py` parses one campaign document into a `ConstructorProfile`. A profile names the contract, the parameter, the Solidity type, and a tree of values:

- integers and booleans
- role addresses chosen from a fixed local set (`governor`, `pause_guardian`, `attacker`, `victim`)
- addresses of named local fixtures
- structs whose fields are those values
- one empty array

The governor and the pause guardian cannot be the attacker or the victim. A profile cannot carry a Solidity expression, a shell command, or an extra field. `prepare_profile` checks the bound file hashes and the struct fields, including nested structs, against the source text. A mismatch raises a `ProfileError` with a reason code. If the campaign has no profile, or the profile names a different contract, the old constructor builder still returns `unknown_constructor_argument`.

The profile is a field on `CampaignSpec`. Analysis attaches one seed sequence for the profile's property. Execution parses the accepted profile again and passes it only to that campaign's harness. The coverage summary records the profile id, validation, hashes, fixtures, and assumptions, and marks the configuration as a local environment. It does not record a deployment.

## Compound configuration

The target is `contracts/CometWithExtendedAssetList.sol` from Compound Comet commit `f766f51583c23acc33b2a7824654ef2029a96804`. BugForge does not vendor that tree. The license is BUSL-1.1. Set `BUGFORGE_COMET_ROOT` to a local checkout of that commit (the default path is `/tmp/comet`).

`comet_pause_profile` reads the constructor and `Configuration` and refuses if they are not the expected source. The local values are:

| Field | Value | Why |
|---|---|---|
| governor | `address(0xC0FE)` | local role, not the attacker |
| pauseGuardian | `address(0x6A2D)` | local role, not the attacker |
| baseToken | decimals fixture `6` | `baseScale` must be at least `BASE_ACCRUAL_SCALE` (`1e6`) and at most 18 decimals |
| baseTokenPriceFeed | decimals fixture `8` | `PRICE_FEED_DECIMALS` |
| extensionDelegate | factory holder | the constructor calls `assetListFactory()` |
| baseMinForRewards | `1` | the constructor rejects `0` |
| storeFrontPriceFactor | `0` | allowed by the constructor; not the `FACTOR_SCALE` case of public issue 1104 |
| interest-rate fields | `0` | divided by `SECONDS_PER_YEAR` in the constructor |
| trackingIndexScale | `1` | explicit scalar |
| assetConfigs | empty | length `0` is within `MAX_ASSETS_FOR_ASSET_LIST`; `pause` does not read collateral |

The factory fixture implements `IAssetListFactory.createAssetList` and returns its own address. The holder fixture points at that factory. These contracts are generated into the harness. They are a local construction environment, not Compound's deployed token, feed, or factory.

The campaign compiles the target's import closure, eleven files, not the price-feed sources that import third-party vendor code. The target file itself is the pinned Comet contract.

## Property

`pause` reverts unless `msg.sender` is `governor` or `pauseGuardian`, then writes `pauseFlags`. The getter is `isSupplyPaused()`.

The seed calls `pause(true, false, false, false, false)` as `address(0xA11CE)`. The oracle is `call_must_fail` plus a before/after read of `isSupplyPaused()`. The property is held only when the call reverts and the getter is unchanged. A constructor revert, a compile failure, or a skipped sequence is not that result. A held property is not a vulnerability and is not marked verified.

`getPrice` stays excluded by the existing oracle-testing prohibition. Public issues 1103 and 1104 are not executed and are not discoveries.

## Reproduce

The checkout at `BUGFORGE_COMET_ROOT` must be commit `f766f51583c23acc33b2a7824654ef2029a96804`. Solidity `0.8.15` must be installed under the BugForge compiler root (`~/.bugforge/solc/0.8.15/solc`), not by replacing `solc` on `PATH`. Foundry must be on `PATH`.

```bash
cd backend
FOUNDRY_OFFLINE=true BUGFORGE_COMET_ROOT=/tmp/comet \
  pytest tests/test_phase58/test_comet_pause_campaign.py -vv
```

`BUGFORGE_REQUIRE_COMET=1` fails the test when the tree is missing. Without it, the Compound test skips. `BUGFORGE_REQUIRE_FOUNDRY=1` requires `solc` 0.8.15 for the Foundry job and does not, by itself, require the Comet tree.

The run is offline: `FOUNDRY_OFFLINE`, no RPC, no fork, no FFI, no live oracle, and no third-party contract beyond the pinned closure and the harness fixtures.

## Measured campaign

On this tree the closure campaign produced:

- 3 sequences
- 1 excluded before the executor (`getPrice`, oracle testing prohibited)
- 0 profile skips
- 2 submitted
- 1 Foundry invocation
- 1 completed property evaluation, verdict `property_held`
- 1 inconclusive result: the constructor sequence's call argument is still not ABI-expressible, so that sequence did not invoke Foundry

Compiler `0.8.15+commit.e14f2714.Linux.g++` at `~/.bugforge/solc/0.8.15/solc`. Optimizer on, 1 run, `via_ir` on. Requested EVM `cancun`. Applied EVM none. `evm_exact` is false. This is not an exact upstream build and not a deployed-bytecode reproduction.

`verified` is false. No finding was marked strong. Reloading the campaign summary repeats the same forge count, the same held outcome, and the same profile hash.

A separate `PauseVault` fixture campaign exercises the same pipeline without the Compound source. Its result is not the Compound result.

## What this does not prove

- The deployed cUSDCv3 bytecode matches this build.
- The live governor or pause guardian behaves as these local addresses do.
- Issues 1103 or 1104 are present or absent at runtime.
- An empty asset list is a production configuration.
- A held authorization check is a vulnerability.

## Follow-up

Non-empty `assetConfigs` are rejected. A profile fills the deployment constructor, not a later call whose argument is the same struct. Cancun remains unsupported on Solidity 0.8.15. Comparing this local deployment with deployed bytecode needs a separate, authorized process.
