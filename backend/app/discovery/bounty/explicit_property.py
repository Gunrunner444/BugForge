"""Researcher-supplied properties that execute without a detector candidate.

A property registered here is a test hypothesis. It is not a finding, and a
passing run is not a vulnerability. The harness is generated from declarations
checked against the target source. A mock used by that harness does not
implement the behavior under test.
"""

from __future__ import annotations

import json
import re
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from app.discovery.bounty.import_closure import resolve_import_closure
from app.discovery.bounty.stateful import (
    ProjectSettings,
    foundry_config,
    run_local_forge,
    scaffold,
    sha256_text,
    untrusted_cheatcode_use,
)
from app.discovery.process import tool_path
from app.parsing.solidity_project import _read_remappings, _solc_remapping
from app.parsing.solidity_research import strip_comments

_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,79}")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_RELATIVE = re.compile(r"[A-Za-z0-9_./-]+\.sol")
_ALLOWED_FIELD = frozenset({"address", "uint256", "bool"})
_TEST_FILE = "InitializeOnce.t.sol"
_REQUIRE = re.compile(
    r"require\s*\(\s*address\s*\(\s*_sharedStorage\s*\.\s*siloConfig\s*\)\s*==\s*"
    r"address\s*\(\s*0\s*\)\s*,\s*ISilo\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\)\s*;"
)
_ASSIGN = re.compile(
    r"_sharedStorage\s*\.\s*siloConfig\s*=\s*(?:address\s*\(\s*)?_siloConfig\s*\)?\s*;"
)
# ABI order of the pinned ISiloConfig structs. The withdraw fixture writes
# DepositConfig and then two zero ConfigData records, matching a borrower with no debt.
_DEPOSIT_CONFIG_FIELDS = (
    ("address", "silo"),
    ("address", "token"),
    ("address", "collateralShareToken"),
    ("address", "protectedShareToken"),
    ("uint256", "daoFee"),
    ("uint256", "deployerFee"),
    ("address", "interestRateModel"),
)
_CONFIG_DATA_FIELDS = (
    ("uint256", "daoFee"),
    ("uint256", "deployerFee"),
    ("address", "silo"),
    ("address", "token"),
    ("address", "protectedShareToken"),
    ("address", "collateralShareToken"),
    ("address", "debtShareToken"),
    ("address", "solvencyOracle"),
    ("address", "maxLtvOracle"),
    ("address", "interestRateModel"),
    ("uint256", "maxLtv"),
    ("uint256", "lt"),
    ("uint256", "liquidationTargetLtv"),
    ("uint256", "liquidationFee"),
    ("uint256", "flashloanFee"),
    ("address", "hookReceiver"),
    ("bool", "callBeforeQuote"),
)


class PropertyConfigError(ValueError):
    """The supplied property is incomplete or disagrees with the source."""

    def __init__(self, code: str, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(f"{code}: {reason}")


def normalize_explicit_properties(
    repo_root: Path, raw: Sequence[Mapping[str, Any]] | None
) -> tuple[dict[str, Any], ...]:
    """Validate every researcher-supplied property. An empty list stays empty."""
    if raw is None:
        return ()
    if isinstance(raw, Mapping) or not isinstance(raw, Sequence):
        raise PropertyConfigError("property_malformed", "explicit properties must be a list")
    return tuple(_normalize_one(repo_root, item) for item in raw)


def execute_explicit_properties(
    properties: Sequence[Mapping[str, Any]],
    repo_root: Path,
    sources: Mapping[str, str],
    *,
    compiler_path: str,
    project: ProjectSettings | None,
    timeout: int,
) -> tuple[dict[str, dict[str, Any]], int]:
    """Compile and run each property. Detector candidate counts are not touched."""
    executions: dict[str, dict[str, Any]] = {}
    forge_runs = 0
    for item in properties:
        record, runs = _execute_one(
            item,
            repo_root,
            sources,
            compiler_path=compiler_path,
            project=project,
            timeout=timeout,
        )
        executions[str(record["sequence_id"])] = record
        forge_runs += runs
    return executions, forge_runs


def classify_explicit_result(
    *,
    process_status: str,
    compiler_status: str,
    return_code: int | None,
    stdout: str,
    stderr: str,
    expected_test: str,
) -> dict[str, str]:
    """Map one Forge result to an outcome.

    A zero exit code is not a pass. ``property_held`` requires the named test
    to appear in Foundry's JSON with status ``Success``. A violation requires
    that same test to have failed with ``BugForgeProperty`` in its decoded
    reason. Text elsewhere in the logs is ignored.
    """
    if process_status == "timeout":
        return _status(
            "timeout",
            "not_run",
            "not_run",
            "not_run",
            "a Forge process timed out before the property finished",
            "timeout",
        )
    if process_status == "spawn_failed":
        return _status(
            "execution_failed",
            compiler_status or "not_run",
            "not_run",
            "not_run",
            "Forge did not start",
            "spawn_failed",
        )
    if compiler_status == "failed":
        return _status(
            "compile_failed",
            "failed",
            "not_run",
            "not_run",
            "the harness did not compile against the pinned source",
            "compile_failed",
        )
    parsed, suites = _forge_suites(stdout)
    if parsed == "malformed" or (parsed == "empty" and stdout.strip()):
        return _status(
            "inconclusive",
            "ok",
            "not_run",
            "not_run",
            "Forge output was malformed or incomplete",
            "malformed_output",
        )
    matched, total = _tests_named(suites, expected_test)
    want = expected_test if expected_test.endswith("()") else f"{expected_test}()"
    if not matched:
        if total == 0 or "no tests match" in stderr.lower():
            reason = "Forge exited without running any test"
            code = "no_tests_matched"
        else:
            reason = f"{want} did not run"
            code = "expected_test_missing"
        return _status("not_tested", "ok", "not_run", "not_run", reason, code)
    statuses = {str(item.get("status") or "") for item in matched}
    if len(statuses) != 1:
        return _status(
            "inconclusive",
            "ok",
            "not_run",
            "not_run",
            f"{want} has conflicting Foundry results",
            "ambiguous_result",
            matched_test=want,
        )
    status = next(iter(statuses))
    failure = "\n".join(str(item.get("reason") or "") for item in matched)
    if status == "Skipped":
        return _status(
            "not_tested",
            "ok",
            "skipped",
            "not_run",
            f"{want} was skipped",
            "test_skipped",
            matched_test=want,
        )
    if status == "Success":
        if return_code != 0:
            return _status(
                "inconclusive",
                "ok",
                "passed",
                "not_evaluated",
                f"{want} passed but Forge did not exit successfully",
                "ambiguous_result",
                matched_test=want,
            )
        return _status(
            "property_held",
            "ok",
            "passed",
            "held",
            f"{want} executed and passed",
            "property_held",
            matched_test=want,
        )
    if status != "Failure":
        return _status(
            "inconclusive",
            "ok",
            "not_run",
            "not_run",
            f"{want} finished with unrecognized status {status}",
            "ambiguous_result",
            matched_test=want,
        )
    if return_code == 0:
        return _status(
            "inconclusive",
            "ok",
            "failed",
            "not_evaluated",
            f"{want} failed but Forge exited successfully",
            "ambiguous_result",
            matched_test=want,
        )
    if "BugForgeFixture" in failure:
        return _status(
            "inconclusive",
            "ok",
            "failed",
            "not_evaluated",
            "the local fixture failed before the property could be judged",
            "fixture_failed",
            matched_test=want,
        )
    if "BugForgeProperty" in failure:
        return _status(
            "property_violated",
            "ok",
            "failed",
            "violated",
            f"{want} failed the property assertion: {failure[:180]}",
            "property_assertion_failed",
            matched_test=want,
        )
    return _status(
        "inconclusive",
        "ok",
        "failed",
        "not_evaluated",
        f"{want} failed without a property assertion",
        "forge_failed",
        matched_test=want,
    )


def _status(
    outcome: str,
    compiler: str,
    test: str,
    prop: str,
    reason: str,
    code: str,
    *,
    matched_test: str = "",
) -> dict[str, str]:
    sequence = "completed" if prop in {"held", "violated"} else "not_run"
    if outcome == "inconclusive" and test == "failed":
        sequence = "reverted"
    return {
        "outcome": outcome,
        "compiler_status": compiler,
        "test_status": test,
        "sequence_status": sequence,
        "property_status": prop,
        "reason": reason,
        "reason_code": code,
        "matched_test": matched_test,
    }


def _forge_suites(stdout: str) -> tuple[str, list[dict[str, Any]]]:
    """Decode Foundry `--json` objects. Empty output is not a passing suite."""
    if "{" not in stdout:
        return ("empty", [])
    decoder = json.JSONDecoder()
    suites: list[dict[str, Any]] = []
    index = stdout.find("{")
    parsed = False
    while index >= 0:
        try:
            payload, end = decoder.raw_decode(stdout[index:])
        except json.JSONDecodeError:
            return ("malformed", []) if not parsed else ("ok", suites)
        parsed = True
        if isinstance(payload, dict):
            suites.append(payload)
        index = stdout.find("{", index + end)
    return ("ok", suites) if parsed else ("malformed", [])


def _tests_named(
    suites: Sequence[Mapping[str, Any]], expected: str
) -> tuple[list[dict[str, Any]], int]:
    want = expected if expected.endswith("()") else f"{expected}()"
    matched: list[dict[str, Any]] = []
    total = 0

    def walk(node: Any) -> None:
        nonlocal total
        if isinstance(node, dict):
            results = node.get("test_results")
            if isinstance(results, dict):
                for name, result in results.items():
                    if not isinstance(result, dict) or "status" not in result:
                        continue
                    total += 1
                    if name == want:
                        matched.append(result)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for suite in suites:
        walk(suite)
    return matched, total


def _normalize_one(repo_root: Path, raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise PropertyConfigError("property_malformed", "a property must be an object")
    if raw.get("verified") is True:
        raise PropertyConfigError(
            "property_malformed", "a researcher-supplied property cannot be pre-verified"
        )
    if "detector" in raw or "candidate" in raw:
        raise PropertyConfigError(
            "property_malformed", "a researcher-supplied property is not a detector candidate"
        )
    source = str(raw.get("source", ""))
    if source != "researcher_supplied":
        raise PropertyConfigError("property_incomplete", "source must be researcher_supplied")
    kind = str(raw.get("kind", ""))
    if kind not in {
        "initialization_once",
        "erc4626_deposit_accounting",
        "deposit_twice_accounting",
        "partial_withdrawal_accounting",
    }:
        raise PropertyConfigError("property_unsupported", f"unsupported property kind {kind!r}")
    property_id = str(raw.get("property_id", ""))
    if not _ID.fullmatch(property_id):
        raise PropertyConfigError("property_incomplete", "property_id is missing or malformed")
    contract = _identifier(raw.get("contract"), "contract")
    entry = _identifier(raw.get("entry_point"), "entry_point")
    getter = _identifier(raw.get("state_getter"), "state_getter")
    error = (
        _identifier(raw.get("expected_error"), "expected_error")
        if kind == "initialization_once"
        else ""
    )
    deployment = str(raw.get("deployment", ""))
    rationale = str(raw.get("rationale", "")).strip()
    if len(rationale) < 20 or len(rationale) > 2000:
        raise PropertyConfigError("property_incomplete", "rationale must explain the property")
    source_file = _relative(raw.get("source_file"))
    locations = _locations(raw.get("locations"))
    imports = _imports(raw.get("imports"))
    extra_fixtures = (
        {"local_asset", "zero_interest_model", "second_depositor", "partial_withdraw"}
        if kind == "partial_withdrawal_accounting"
        else {"local_asset", "zero_interest_model", "second_depositor"}
        if kind == "deposit_twice_accounting"
        else {"local_asset", "zero_interest_model"}
        if kind == "erc4626_deposit_accounting"
        else set()
    )
    fixtures = _fixtures(raw.get("fixture_dependencies"), extra_fixtures)
    texts = _read_cited(
        repo_root, (source_file, *imports.values(), *(item[0] for item in locations))
    )
    for path, symbol in locations:
        if not re.search(rf"\b{re.escape(symbol)}\b", strip_comments(texts[path])):
            raise PropertyConfigError("property_source_mismatch", f"{symbol} is not in {path}")
    if kind == "initialization_once":
        _validate_initialization_once(
            texts,
            source_file=source_file,
            contract=contract,
            entry=entry,
            getter=getter,
            error=error,
            deployment=deployment,
            imports=imports,
        )
        harness = render_initialization_harness(
            texts,
            contract=contract,
            source_file=source_file,
            error=error,
            imports=imports,
        )
        test_entry = "test_initialize_once"
        test_file = "InitializeOnce.t.sol"
        expected = (
            f"the second {entry} reverts with {error} and {getter} still returns "
            "the first configuration"
        )
    else:
        if kind == "deposit_twice_accounting":
            _validate_second_deposit(
                texts,
                source_file=source_file,
                contract=contract,
                entry=entry,
                getter=getter,
                deployment=deployment,
                imports=imports,
            )
            harness = render_second_deposit_harness(
                texts,
                contract=contract,
                source_file=source_file,
                imports=imports,
            )
            test_entry = "test_deposit_twice_accounting"
            test_file = "DepositTwiceAccounting.t.sol"
            expected = (
                "after one deposit has funded the market, a second depositor's previewDeposit "
                "and minted shares follow the floor conversion of the observed totals plus the "
                "decimals offset, and the token, share, and collateral totals move by that deposit"
            )
        elif kind == "partial_withdrawal_accounting":
            _validate_partial_withdrawal(
                texts,
                source_file=source_file,
                contract=contract,
                entry=entry,
                getter=getter,
                deployment=deployment,
                imports=imports,
            )
            harness = render_partial_withdrawal_harness(
                texts,
                contract=contract,
                source_file=source_file,
                imports=imports,
            )
            test_entry = "test_partial_withdrawal_accounting"
            test_file = "PartialWithdrawalAccounting.t.sol"
            expected = (
                "after a funded market is taken off the exact offset ratio by minting shares, "
                "previewWithdraw and withdraw burn the ceil share conversion of the pre-operation "
                "totals, the receiver gets the requested assets, and share supply and stored "
                "collateral decrease by the burned shares and withdrawn assets"
            )
        else:
            _validate_deposit_accounting(
                texts,
                source_file=source_file,
                contract=contract,
                entry=entry,
                getter=getter,
                deployment=deployment,
                imports=imports,
            )
            harness = render_deposit_harness(
                texts,
                contract=contract,
                source_file=source_file,
                imports=imports,
            )
            test_entry = "test_deposit_accounting"
            test_file = "DepositAccounting.t.sol"
            expected = (
                "on an empty zero-fee market, previewDeposit equals the shares minted by "
                "deposit, the receiver balance increases by those shares, and the underlying "
                "token and collateral total move by the deposited assets"
            )
    return {
        "property_id": property_id,
        "source": "researcher_supplied",
        "kind": kind,
        "contract": contract,
        "source_file": source_file,
        "entry_point": entry,
        "state_getter": getter,
        "expected_error": error,
        "expected_outcome": expected,
        "deployment": deployment,
        "rationale": rationale,
        "locations": [{"path": path, "symbol": symbol} for path, symbol in locations],
        "imports": imports,
        "fixture_dependencies": list(fixtures),
        "test_entry_point": test_entry,
        "test_file": test_file,
        "harness_sha256": sha256_text(harness),
        "validation": "accepted",
        "vulnerability_finding": False,
    }


def render_initialization_harness(
    texts: Mapping[str, str],
    *,
    contract: str,
    source_file: str,
    error: str,
    imports: Mapping[str, str],
) -> str:
    """A local clone test. The config mock only ABI-encodes getConfig."""
    factory_text = strip_comments(texts[imports["factory_interface"]])
    config_text = strip_comments(texts[imports["config_interface"]])
    error_text = strip_comments(texts[imports["error_interface"]])
    factory = _declared_name(factory_text, "interface")
    config = _declared_name(config_text, "interface")
    error_type = _declared_name(error_text, "interface") or _declared_name(error_text, "contract")
    fields = _struct_fields(config_text, "ConfigData")
    if not factory or not config or not error_type or not fields:
        raise PropertyConfigError(
            "property_source_mismatch", "interface declarations are incomplete"
        )
    if not any(name == "hookReceiver" and type_name == "address" for type_name, name in fields):
        raise PropertyConfigError(
            "property_source_mismatch", "ConfigData has no address hookReceiver"
        )
    hook_index = next(
        index for index, (type_name, name) in enumerate(fields) if name == "hookReceiver"
    )
    # A Solidity `getConfig` with one return slot per ConfigData field does not
    # pass legacy codegen (solc stack-too-deep) once the struct reaches the
    # pinned 17-field layout. The fallback returns the same ABI encoding and
    # does not implement Silo's initialization guard.
    mock = f"""contract LocalFactory {{}}

contract LocalSiloConfig {{
    address public immutable configuredHook;

    constructor(address hook) {{
        configuredHook = hook;
    }}

    fallback() external {{
        address hook = configuredHook;
        assembly {{
            let ptr := mload(0x40)
            mstore(add(ptr, {hook_index * 32}), hook)
            return(ptr, {len(fields) * 32})
        }}
    }}
}}
"""
    if "SiloInitialized" in mock or "require" in mock:
        raise PropertyConfigError(
            "property_malformed", "the config mock must not implement the guard"
        )
    contract_text = strip_comments(texts[source_file])
    payable = bool(
        re.search(r"\breceive\s*\(\s*\)\s+external\s+payable\b", contract_text)
        or re.search(r"\bfallback\s*\(\s*\)\s+external\s+payable\b", contract_text)
    )
    clone_expr = (
        "payable(Clones.clone(address(implementation)))"
        if payable
        else "Clones.clone(address(implementation))"
    )
    entry = _entry_name(texts[source_file])
    getter = _getter_name(texts[source_file])
    rel = {
        "contract": _test_import(source_file),
        "factory": _test_import(imports["factory_interface"]),
        "config": _test_import(imports["config_interface"]),
        "error": _test_import(imports["error_interface"]),
        "clones": _test_import(imports["clones"]),
    }
    return f"""// SPDX-License-Identifier: UNLICENSED
// Researcher-supplied local property. Not a vulnerability assertion.
pragma solidity 0.8.28;

import {{{contract}}} from "{rel["contract"]}";
import {{{factory}}} from "{rel["factory"]}";
import {{{config}}} from "{rel["config"]}";
import {{{error_type}}} from "{rel["error"]}";
import {{Clones}} from "{rel["clones"]}";

error BugForgeFixture(bytes data);
error BugForgeProperty(string reason);

{mock}
contract InitializeOnceTest {{
    event BugForgeState(string label, address value);

    function test_initialize_once() public {{
        {contract} silo = _deploy();
        {config} configA = _config(address(0));
        {config} configB = _config(address(1));
        _requireFirst(silo, configA);
        _requireSecond(silo, configA, configB);
    }}

    function _deploy() internal returns ({contract} silo) {{
        LocalFactory deployedFactory = new LocalFactory();
        {contract} implementation = new {contract}({factory}(address(deployedFactory)));
        silo = {contract}({clone_expr});
    }}

    function _config(address hook) internal returns ({config} config_) {{
        config_ = {config}(address(new LocalSiloConfig(hook)));
    }}

    function _requireFirst({contract} silo, {config} configA) internal {{
        (bool ok, bytes memory data) = address(silo).call(
            abi.encodeCall({contract}.{entry}, (configA))
        );
        if (!ok) revert BugForgeFixture(data);
        address stored = address(silo.{getter}());
        emit BugForgeState("after_first", stored);
        if (stored != address(configA)) revert BugForgeProperty("config_after_first");
    }}

    function _requireSecond({contract} silo, {config} configA, {config} configB) internal {{
        (bool ok, bytes memory data) = address(silo).call(
            abi.encodeCall({contract}.{entry}, (configB))
        );
        if (ok) revert BugForgeProperty("second_initialize_succeeded");
        if (data.length < 4 || bytes4(data) != {error_type}.{error}.selector) {{
            revert BugForgeProperty("unexpected_revert");
        }}
        address storedAfter = address(silo.{getter}());
        emit BugForgeState("after_second", storedAfter);
        if (storedAfter != address(configA)) revert BugForgeProperty("config_replaced");
    }}
}}
"""


def _validate_deposit_accounting(
    texts: Mapping[str, str],
    *,
    source_file: str,
    contract: str,
    entry: str,
    getter: str,
    deployment: str,
    imports: Mapping[str, str],
) -> None:
    if entry != "deposit" or getter != "previewDeposit":
        raise PropertyConfigError(
            "property_source_mismatch",
            "the deposit property must target deposit and previewDeposit",
        )
    contract_text = strip_comments(texts[source_file])
    if not re.search(rf"\b(?:contract|abstract\s+contract)\s+{contract}\b", contract_text):
        raise PropertyConfigError("property_source_mismatch", f"{contract} is not declared")
    if not re.search(r"function\s+deposit\s*\(\s*uint256\b[^)]*\baddress\b", contract_text):
        raise PropertyConfigError(
            "property_source_mismatch", "deposit(uint256,address) is not declared"
        )
    if not re.search(r"function\s+previewDeposit\s*\(\s*uint256\b", contract_text):
        raise PropertyConfigError(
            "property_source_mismatch", "previewDeposit(uint256) is not declared"
        )
    if not re.search(r"constructor\s*\(\s*ISiloFactory\b", contract_text):
        raise PropertyConfigError(
            "property_source_mismatch", "the constructor does not take ISiloFactory"
        )
    if not any("_deposit(" in body for body in _function_bodies(contract_text, "deposit")):
        raise PropertyConfigError("property_source_mismatch", "deposit does not call _deposit")
    if not any("Actions.deposit" in body for body in _function_bodies(contract_text, "_deposit")):
        raise PropertyConfigError(
            "property_source_mismatch", "_deposit does not call Actions.deposit"
        )
    clean = {path: strip_comments(text) for path, text in texts.items()}
    joined = "\n".join(clean.values())
    action_bodies = [body for text in clean.values() for body in _function_bodies(text, "deposit")]
    if not any(
        "SiloERC4626Lib.deposit" in body
        and "getCollateralShareTokenAndAsset" in body
        and "accrueInterestForSilo" in body
        for body in action_bodies
    ):
        raise PropertyConfigError(
            "property_source_mismatch",
            "Actions.deposit does not accrue interest, read the share token, and deposit",
        )
    if not re.search(r"_DECIMALS_OFFSET\s*=\s*3\b", joined):
        raise PropertyConfigError(
            "property_source_mismatch", "the share offset is not the expected value of 3"
        )
    if "DEPOSIT_TO_SHARES" not in joined or "Math.Rounding.Floor" not in joined:
        raise PropertyConfigError("property_source_mismatch", "deposit share rounding is not floor")
    if not re.search(r"if\s*\(\s*lastTimestamp\s*==\s*0\s*\)", joined):
        raise PropertyConfigError(
            "property_source_mismatch",
            "the first interest accrual does not return before applying a rate",
        )
    if "function mint(address" not in joined:
        raise PropertyConfigError(
            "property_source_mismatch", "the collateral share token does not mint"
        )
    if "_disableInitializers()" not in joined:
        raise PropertyConfigError(
            "property_source_mismatch",
            "this source does not disable initializers on the implementation",
        )
    if deployment != "eip1167_clone":
        raise PropertyConfigError(
            "property_fixture_rejected",
            "the implementation constructor disables initializers, so the instance must be a clone",
        )
    if "function clone(address" not in clean[imports["clones"]]:
        raise PropertyConfigError("property_source_mismatch", "Clones.clone is not available")
    collateral = _enum_index(joined, "CollateralType", "Collateral")
    asset_type = _enum_index(joined, "AssetType", "Collateral")
    if collateral is None or collateral != asset_type:
        raise PropertyConfigError(
            "property_source_mismatch",
            "CollateralType.Collateral and AssetType.Collateral do not share an index",
        )
    fields = _struct_fields(clean[imports["config_interface"]], "ConfigData")
    names = {name for _type_name, name in fields}
    required = {"silo", "token", "collateralShareToken", "interestRateModel", "hookReceiver"}
    if not required <= names:
        raise PropertyConfigError(
            "property_source_mismatch", "ConfigData is missing a field the deposit path reads"
        )


def _validate_second_deposit(
    texts: Mapping[str, str],
    *,
    source_file: str,
    contract: str,
    entry: str,
    getter: str,
    deployment: str,
    imports: Mapping[str, str],
) -> None:
    """The second deposit uses the same path, plus the offset conversion."""
    _validate_deposit_accounting(
        texts,
        source_file=source_file,
        contract=contract,
        entry=entry,
        getter=getter,
        deployment=deployment,
        imports=imports,
    )
    joined = "\n".join(strip_comments(text) for text in texts.values())
    if "function convertToShares" not in joined:
        raise PropertyConfigError("property_source_mismatch", "convertToShares is not declared")
    if "_totalShares + _DECIMALS_OFFSET_POW" not in joined or "_totalAssets + 1" not in joined:
        raise PropertyConfigError(
            "property_source_mismatch",
            "collateral conversion does not add the decimals offset",
        )
    if not re.search(r"if\s*\(\s*_totalShares\s*==\s*0\s*\)", joined):
        raise PropertyConfigError(
            "property_source_mismatch",
            "the empty-market conversion branch is not present",
        )


def _validate_partial_withdrawal(
    texts: Mapping[str, str],
    *,
    source_file: str,
    contract: str,
    entry: str,
    getter: str,
    deployment: str,
    imports: Mapping[str, str],
) -> None:
    """Collateral withdraw rounds shares up. The setup mint rounds assets up."""
    if entry != "withdraw" or getter != "previewWithdraw":
        raise PropertyConfigError(
            "property_source_mismatch",
            "the withdrawal property must target withdraw and previewWithdraw",
        )
    _validate_deposit_accounting(
        texts,
        source_file=source_file,
        contract=contract,
        entry="deposit",
        getter="previewDeposit",
        deployment=deployment,
        imports=imports,
    )
    clean = {path: strip_comments(text) for path, text in texts.items()}
    joined = "\n".join(clean.values())
    contract_text = clean[source_file]
    if "function convertToShares" not in joined or "function convertToAssets" not in joined:
        raise PropertyConfigError(
            "property_source_mismatch", "share conversion functions are not declared"
        )
    if "function convertToAssetsOrToShares" not in joined:
        raise PropertyConfigError(
            "property_source_mismatch", "convertToAssetsOrToShares is not declared"
        )
    if "_totalShares + _DECIMALS_OFFSET_POW" not in joined or "_totalAssets + 1" not in joined:
        raise PropertyConfigError(
            "property_source_mismatch",
            "collateral conversion does not add the decimals offset",
        )
    if not re.search(r"if\s*\(\s*_totalShares\s*==\s*0\s*\)", joined):
        raise PropertyConfigError(
            "property_source_mismatch",
            "the empty-market conversion branch is not present",
        )
    if not re.search(
        r"function\s+withdraw\s*\(\s*uint256\b[^)]*\baddress\b[^)]*\baddress\b", contract_text
    ):
        raise PropertyConfigError(
            "property_source_mismatch", "withdraw(uint256,address,address) is not declared"
        )
    if not re.search(r"function\s+previewWithdraw\s*\(\s*uint256\b", contract_text):
        raise PropertyConfigError(
            "property_source_mismatch", "previewWithdraw(uint256) is not declared"
        )
    if not re.search(r"function\s+mint\s*\(\s*uint256\b[^)]*\baddress\b", contract_text):
        raise PropertyConfigError(
            "property_source_mismatch", "mint(uint256,address) is not declared"
        )
    withdraw_bodies = _function_bodies(contract_text, "withdraw")
    if not any(
        "_withdraw" in body and "CollateralType.Collateral" in body for body in withdraw_bodies
    ):
        raise PropertyConfigError(
            "property_source_mismatch",
            "withdraw(uint256,address,address) does not withdraw collateral",
        )
    if not any("Actions.withdraw" in body for body in _function_bodies(contract_text, "_withdraw")):
        raise PropertyConfigError(
            "property_source_mismatch", "_withdraw does not call Actions.withdraw"
        )
    if not any(
        "WITHDRAW_TO_SHARES" in body for body in _function_bodies(contract_text, "_previewWithdraw")
    ):
        raise PropertyConfigError(
            "property_source_mismatch", "previewWithdraw does not use WITHDRAW_TO_SHARES"
        )
    action_bodies = [body for text in clean.values() for body in _function_bodies(text, "withdraw")]
    if not any(
        "SiloERC4626Lib.withdraw" in body
        and "accrueInterestForBothSilos" in body
        and "getConfigsForWithdraw" in body
        and "depositConfig.silo == collateralConfig.silo" in body
        for body in action_bodies
    ):
        raise PropertyConfigError(
            "property_source_mismatch",
            "Actions.withdraw does not accrue, load withdraw config, and withdraw",
        )
    if not any(".burn(" in body and "safeTransfer" in body for body in action_bodies):
        raise PropertyConfigError(
            "property_source_mismatch",
            "the withdraw library does not burn shares and transfer assets",
        )
    if "WITHDRAW_TO_SHARES = Math.Rounding.Ceil" not in joined:
        raise PropertyConfigError(
            "property_source_mismatch", "asset withdrawal does not round shares up"
        )
    if "WITHDRAW_TO_ASSETS = Math.Rounding.Floor" not in joined:
        raise PropertyConfigError(
            "property_source_mismatch", "share redemption does not round assets down"
        )
    if "DEPOSIT_TO_ASSETS = Math.Rounding.Ceil" not in joined:
        raise PropertyConfigError(
            "property_source_mismatch", "minting shares does not round assets up"
        )
    if "function burn(address" not in joined:
        raise PropertyConfigError(
            "property_source_mismatch", "the collateral share token does not burn"
        )
    config_text = clean[imports["config_interface"]]
    if tuple(_struct_fields(config_text, "DepositConfig")) != _DEPOSIT_CONFIG_FIELDS:
        raise PropertyConfigError(
            "property_source_mismatch", "DepositConfig does not match the pinned field order"
        )
    if tuple(_struct_fields(config_text, "ConfigData")) != _CONFIG_DATA_FIELDS:
        raise PropertyConfigError(
            "property_source_mismatch", "ConfigData does not match the pinned field order"
        )


def render_deposit_harness(
    texts: Mapping[str, str],
    *,
    contract: str,
    source_file: str,
    imports: Mapping[str, str],
    include_withdraw: bool = False,
) -> str:
    """Local empty-market deposit. Mocks do not implement Silo accounting."""
    factory = _declared_name(strip_comments(texts[imports["factory_interface"]]), "interface")
    config = _declared_name(strip_comments(texts[imports["config_interface"]]), "interface")
    silo_iface = _declared_name(strip_comments(texts[imports["error_interface"]]), "interface")
    fields = _struct_fields(strip_comments(texts[imports["config_interface"]]), "ConfigData")
    if not factory or not config or not silo_iface or not fields:
        raise PropertyConfigError(
            "property_source_mismatch", "interface declarations are incomplete"
        )
    index = {name: position for position, (_type_name, name) in enumerate(fields)}
    joined = "\n".join(strip_comments(text) for text in texts.values())
    collateral = _enum_index(joined, "CollateralType", "Collateral")
    if collateral is None:
        raise PropertyConfigError(
            "property_source_mismatch", "CollateralType.Collateral is missing"
        )
    contract_text = strip_comments(texts[source_file])
    payable = bool(
        re.search(r"\breceive\s*\(\s*\)\s+external\s+payable\b", contract_text)
        or re.search(r"\bfallback\s*\(\s*\)\s+external\s+payable\b", contract_text)
    )
    clone_expr = (
        "payable(Clones.clone(address(implementation)))"
        if payable
        else "Clones.clone(address(implementation))"
    )
    rel = {
        key: _test_import(imports[key])
        for key in ("factory_interface", "config_interface", "error_interface", "clones")
    }
    width = len(fields) * 32
    mock = f"""contract LocalFactory {{}}

error LocalAssetError(string reason);
error LocalConfig(string reason);

contract LocalAsset {{
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function credit(address to, uint256 amount) external {{
        balanceOf[to] += amount;
    }}

    function approve(address spender, uint256 amount) external returns (bool) {{
        allowance[msg.sender][spender] = amount;
        return true;
    }}

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {{
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {{
            if (allowed < amount) revert LocalAssetError("allowance");
            allowance[from][msg.sender] = allowed - amount;
        }}
        if (balanceOf[from] < amount) revert LocalAssetError("balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }}
}}

contract LocalInterestRateModel {{
    function getCompoundInterestRate(address, uint256) external pure returns (uint256) {{
        return 0;
    }}
}}

contract LocalSiloConfig {{
    address public boundSilo;
    address public immutable asset;
    address public immutable rateModel;
    bool private entered;

    constructor(address asset_, address rate_) {{
        asset = asset_;
        rateModel = rate_;
    }}

    function bind(address silo) external {{
        if (boundSilo != address(0) || silo == address(0)) revert LocalConfig("bind");
        boundSilo = silo;
    }}

    function accrueInterestForSilo(address silo_) external {{
        if (msg.sender != boundSilo || silo_ != boundSilo) revert LocalConfig("accrue");
        {silo_iface}(silo_).accrueInterestForConfig(rateModel, 0, 0);
    }}

    function turnOnReentrancyProtection() external {{
        if (msg.sender != boundSilo) revert LocalConfig("caller");
        if (entered) revert LocalConfig("entered");
        entered = true;
    }}

    function turnOffReentrancyProtection() external {{
        if (msg.sender != boundSilo) revert LocalConfig("caller");
        if (!entered) revert LocalConfig("inactive");
        entered = false;
    }}

    function getCollateralShareTokenAndAsset(address silo_, uint8 kind)
        external
        view
        returns (address shareToken, address token)
    {{
        if (silo_ != boundSilo || kind != {collateral}) revert LocalConfig("collateral");
        shareToken = boundSilo;
        token = asset;
    }}

    fallback() external {{
        if (msg.sig != bytes4(0xe48a5f7b)) revert LocalConfig("selector");
        address silo_ = boundSilo;
        address token_ = asset;
        address rate_ = rateModel;
        assembly {{
            let ptr := mload(0x40)
            mstore(add(ptr, {index["silo"] * 32}), silo_)
            mstore(add(ptr, {index["token"] * 32}), token_)
            mstore(add(ptr, {index["collateralShareToken"] * 32}), silo_)
            mstore(add(ptr, {index["interestRateModel"] * 32}), rate_)
            return(ptr, {width})
        }}
    }}
}}
"""
    if include_withdraw:
        mock = _with_withdraw_fixture(mock, silo_iface, len(fields))
    if "SiloInitialized" in mock or "require" in mock:
        raise PropertyConfigError(
            "property_malformed", "the deposit mock must not implement Silo's guards"
        )
    return f"""// SPDX-License-Identifier: UNLICENSED
// Researcher-supplied local property. Not a vulnerability assertion.
pragma solidity 0.8.28;

import {{{contract}}} from "{_test_import(source_file)}";
import {{{factory}}} from "{rel["factory_interface"]}";
import {{{config}}} from "{rel["config_interface"]}";
import {{{silo_iface}}} from "{rel["error_interface"]}";
import {{Clones}} from "{rel["clones"]}";

error BugForgeFixture(bytes data);
error BugForgeProperty(string reason);

{mock}
contract DepositAccountingTest {{
    uint256 internal constant AMOUNT = 1_000_000;
    event BugForgeState(string label, uint256 value);

    function test_deposit_accounting() public {{
        ({contract} silo, LocalAsset asset_) = _setup();
        uint256 previewed = _preview(silo);
        uint256 userBefore = asset_.balanceOf(address(this));
        uint256 siloBefore = asset_.balanceOf(address(silo));
        uint256 sharesBefore = silo.balanceOf(address(this));
        uint256 collateralBefore = silo.getTotalAssetsStorage({silo_iface}.AssetType.Collateral);
        uint256 minted = _deposit(silo);
        _check(
            silo,
            asset_,
            previewed,
            minted,
            userBefore,
            siloBefore,
            sharesBefore,
            collateralBefore
        );
    }}

    function _setup() internal returns ({contract} silo, LocalAsset asset_) {{
        asset_ = new LocalAsset();
        LocalInterestRateModel rate = new LocalInterestRateModel();
        LocalSiloConfig config_ = new LocalSiloConfig(address(asset_), address(rate));
        LocalFactory deployedFactory = new LocalFactory();
        {contract} implementation = new {contract}({factory}(address(deployedFactory)));
        silo = {contract}({clone_expr});
        config_.bind(address(silo));
        (bool ok, bytes memory data) = address(silo).call(
            abi.encodeCall({contract}.initialize, ({config}(address(config_))))
        );
        if (!ok) revert BugForgeFixture(data);
        asset_.credit(address(this), AMOUNT);
        asset_.approve(address(silo), AMOUNT);
    }}

    function _preview({contract} silo) internal view returns (uint256 previewed) {{
        (bool ok, bytes memory data) = address(silo).staticcall(
            abi.encodeWithSelector(bytes4(keccak256("previewDeposit(uint256)")), AMOUNT)
        );
        if (!ok || data.length < 32) revert BugForgeFixture(data);
        previewed = abi.decode(data, (uint256));
        if (previewed == 0) revert BugForgeFixture(bytes("preview_zero"));
    }}

    function _deposit({contract} silo) internal returns (uint256 minted) {{
        (bool ok, bytes memory data) = address(silo).call(
            abi.encodeWithSelector(
                bytes4(keccak256("deposit(uint256,address)")), AMOUNT, address(this)
            )
        );
        if (!ok || data.length < 32) revert BugForgeFixture(data);
        minted = abi.decode(data, (uint256));
    }}

    function _check(
        {contract} silo,
        LocalAsset asset_,
        uint256 previewed,
        uint256 minted,
        uint256 userBefore,
        uint256 siloBefore,
        uint256 sharesBefore,
        uint256 collateralBefore
    ) internal {{
        uint256 userAfter = asset_.balanceOf(address(this));
        uint256 siloAfter = asset_.balanceOf(address(silo));
        uint256 sharesAfter = silo.balanceOf(address(this));
        uint256 collateralAfter = silo.getTotalAssetsStorage({silo_iface}.AssetType.Collateral);
        emit BugForgeState("preview_shares", previewed);
        emit BugForgeState("minted_shares", minted);
        emit BugForgeState("user_assets_before", userBefore);
        emit BugForgeState("user_assets_after", userAfter);
        emit BugForgeState("silo_assets_before", siloBefore);
        emit BugForgeState("silo_assets_after", siloAfter);
        emit BugForgeState("share_balance_before", sharesBefore);
        emit BugForgeState("share_balance_after", sharesAfter);
        emit BugForgeState("collateral_before", collateralBefore);
        emit BugForgeState("collateral_after", collateralAfter);
        if (minted != previewed) revert BugForgeProperty("preview_mismatch");
        if (sharesAfter != sharesBefore + minted) revert BugForgeProperty("share_balance");
        if (userAfter != userBefore - AMOUNT) revert BugForgeProperty("user_asset");
        if (siloAfter != siloBefore + AMOUNT) revert BugForgeProperty("silo_asset");
        if (collateralAfter != collateralBefore + AMOUNT) revert BugForgeProperty("collateral_assets");
    }}
}}
"""


def render_second_deposit_harness(
    texts: Mapping[str, str],
    *,
    contract: str,
    source_file: str,
    imports: Mapping[str, str],
) -> str:
    """A funded market, then a second depositor. The mock does not price shares."""
    first = render_deposit_harness(
        texts, contract=contract, source_file=source_file, imports=imports
    )
    marker = "contract DepositAccountingTest {"
    if marker not in first:
        raise PropertyConfigError("property_malformed", "the deposit fixture could not be reused")
    prelude = first.split(marker)[0]
    if "contract LocalDepositor" not in prelude:
        prelude = (
            prelude.rstrip()
            + """

contract LocalDepositor {
    function fundAndDeposit(LocalAsset asset_, address silo, uint256 amount)
        external
        returns (uint256 minted)
    {
        asset_.approve(silo, amount);
        (bool ok, bytes memory data) = silo.call(
            abi.encodeWithSelector(
                bytes4(keccak256("deposit(uint256,address)")), amount, address(this)
            )
        );
        if (!ok || data.length < 32) revert BugForgeFixture(data);
        minted = abi.decode(data, (uint256));
    }
}
"""
        )
    silo_iface = _declared_name(strip_comments(texts[imports["error_interface"]]), "interface")
    factory = _declared_name(strip_comments(texts[imports["factory_interface"]]), "interface")
    config = _declared_name(strip_comments(texts[imports["config_interface"]]), "interface")
    if not silo_iface or not factory or not config:
        raise PropertyConfigError("property_source_mismatch", "the Silo interface is missing")
    clone_expr = _clone_expr(texts[source_file])
    return (
        prelude
        + f"""
contract DepositTwiceAccountingTest {{
    uint256 internal constant SEED = 1_000_000;
    uint256 internal constant OFFSET = 1000;
    event BugForgeState(string label, uint256 value);

    function test_deposit_twice_accounting() public {{
        _case(0, 1);
        _case(1, 7);
        _case(2, 1_000_000);
        _case(3, 1_000_001);
    }}

    struct Case {{
        uint256 assetsBefore;
        uint256 supplyBefore;
        uint256 userBefore;
        uint256 siloBefore;
        uint256 receiverBefore;
        uint256 firstBalance;
        uint256 viewBefore;
        uint256 previewed;
        uint256 minted;
        uint256 firstMinted;
        uint256 formula;
        uint256 remainder;
    }}

    Case internal currentCase;

    function _case(uint256 index, uint256 amount) internal {{
        ({contract} silo, LocalAsset asset_) = _setup();
        LocalDepositor first = new LocalDepositor();
        LocalDepositor second = new LocalDepositor();
        if (address(first) == address(second)) revert BugForgeFixture(bytes("same_actor"));
        _seed(silo, asset_, first);
        _beforeSecond(silo, asset_, first, second, amount);
        _afterSecond(index, amount, silo, asset_, first, second);
    }}

    function _seed({contract} silo, LocalAsset asset_, LocalDepositor first) internal {{
        asset_.credit(address(first), SEED);
        uint256 minted = first.fundAndDeposit(asset_, address(silo), SEED);
        uint256 assetsBefore = silo.getTotalAssetsStorage({silo_iface}.AssetType.Collateral);
        uint256 supplyBefore = silo.totalSupply();
        if (minted == 0 || assetsBefore == 0 || supplyBefore == 0) {{
            revert BugForgeProperty("still_empty");
        }}
        if (assetsBefore != SEED || supplyBefore != minted) revert BugForgeProperty("seed_accounting");
        if (silo.balanceOf(address(first)) != minted) revert BugForgeProperty("seed_receiver");
        if (supplyBefore + OFFSET != OFFSET * (assetsBefore + 1)) {{
            revert BugForgeProperty("offset_identity");
        }}
        currentCase.firstMinted = minted;
        currentCase.assetsBefore = assetsBefore;
        currentCase.supplyBefore = supplyBefore;
    }}

    function _beforeSecond(
        {contract} silo,
        LocalAsset asset_,
        LocalDepositor first,
        LocalDepositor second,
        uint256 amount
    ) internal {{
        asset_.credit(address(second), amount);
        currentCase.userBefore = asset_.balanceOf(address(second));
        currentCase.siloBefore = asset_.balanceOf(address(silo));
        currentCase.receiverBefore = silo.balanceOf(address(second));
        currentCase.firstBalance = silo.balanceOf(address(first));
        currentCase.viewBefore = silo.totalAssets();
        currentCase.previewed = _preview(silo, amount);
        currentCase.minted = second.fundAndDeposit(asset_, address(silo), amount);
        uint256 virtualShares = currentCase.supplyBefore + OFFSET;
        uint256 virtualAssets = currentCase.assetsBefore + 1;
        uint256 product = amount * virtualShares;
        currentCase.formula = product / virtualAssets;
        currentCase.remainder = product % virtualAssets;
    }}

    function _afterSecond(
        uint256 index,
        uint256 amount,
        {contract} silo,
        LocalAsset asset_,
        LocalDepositor first,
        LocalDepositor second
    ) internal {{
        uint256 userAfter = asset_.balanceOf(address(second));
        uint256 siloAfter = asset_.balanceOf(address(silo));
        uint256 receiverAfter = silo.balanceOf(address(second));
        uint256 supplyAfter = silo.totalSupply();
        uint256 collateralAfter = silo.getTotalAssetsStorage({silo_iface}.AssetType.Collateral);
        uint256 viewAfter = silo.totalAssets();
        _emit(index, "amount", amount);
        _emit(index, "assets_before", currentCase.assetsBefore);
        _emit(index, "supply_before", currentCase.supplyBefore);
        _emit(index, "preview", currentCase.previewed);
        _emit(index, "minted", currentCase.minted);
        _emit(index, "formula", currentCase.formula);
        _emit(index, "remainder", currentCase.remainder);
        _emit(index, "receiver_delta", receiverAfter - currentCase.receiverBefore);
        _emit(index, "silo_delta", siloAfter - currentCase.siloBefore);
        _emit(index, "supply_delta", supplyAfter - currentCase.supplyBefore);
        _emit(index, "collateral_delta", collateralAfter - currentCase.assetsBefore);
        _emit(index, "first_minted", currentCase.firstMinted);
        _emit(index, "view_before", currentCase.viewBefore);
        if (currentCase.viewBefore != currentCase.assetsBefore || viewAfter != collateralAfter) {{
            revert BugForgeProperty("view_storage");
        }}
        if (currentCase.minted < currentCase.previewed) revert BugForgeProperty("preview_exceeds_mint");
        if (currentCase.minted != currentCase.formula || currentCase.previewed != currentCase.formula) {{
            revert BugForgeProperty("formula_mismatch");
        }}
        if (userAfter != currentCase.userBefore - amount) revert BugForgeProperty("user_asset");
        if (siloAfter != currentCase.siloBefore + amount) revert BugForgeProperty("silo_asset");
        if (receiverAfter != currentCase.receiverBefore + currentCase.minted) {{
            revert BugForgeProperty("share_balance");
        }}
        if (supplyAfter != currentCase.supplyBefore + currentCase.minted) {{
            revert BugForgeProperty("total_supply");
        }}
        if (collateralAfter != currentCase.assetsBefore + amount) {{
            revert BugForgeProperty("collateral_assets");
        }}
        if (silo.balanceOf(address(first)) != currentCase.firstBalance) {{
            revert BugForgeProperty("first_depositor");
        }}
        if (currentCase.receiverBefore != 0) revert BugForgeProperty("receiver_not_fresh");
    }}

    function _setup() internal returns ({contract} silo, LocalAsset asset_) {{
        asset_ = new LocalAsset();
        LocalInterestRateModel rate = new LocalInterestRateModel();
        LocalSiloConfig config_ = new LocalSiloConfig(address(asset_), address(rate));
        LocalFactory deployedFactory = new LocalFactory();
        {contract} implementation = new {contract}({factory}(address(deployedFactory)));
        silo = {contract}({clone_expr});
        config_.bind(address(silo));
        (bool ok, bytes memory data) = address(silo).call(
            abi.encodeCall({contract}.initialize, ({config}(address(config_))))
        );
        if (!ok) revert BugForgeFixture(data);
    }}

    function _preview({contract} silo, uint256 amount) internal view returns (uint256 previewed) {{
        (bool ok, bytes memory data) = address(silo).staticcall(
            abi.encodeWithSelector(bytes4(keccak256("previewDeposit(uint256)")), amount)
        );
        if (!ok || data.length < 32) revert BugForgeFixture(data);
        previewed = abi.decode(data, (uint256));
    }}

    function _emit(uint256 index, string memory key, uint256 value) internal {{
        string memory prefix = "a3_";
        if (index == 0) prefix = "a0_";
        else if (index == 1) prefix = "a1_";
        else if (index == 2) prefix = "a2_";
        else if (index != 3) revert BugForgeFixture(bytes("index"));
        emit BugForgeState(string.concat(prefix, key), value);
    }}
}}
"""
    )


def _with_withdraw_fixture(mock: str, silo_iface: str, config_words: int) -> str:
    """Add the token transfer and no-debt withdraw config the real path calls.

    The paired silo is not deployed. Accrual runs only on the bound silo. With
    zero debt and a zero rate, the other silo cannot change this silo's stored
    collateral. The two ConfigData tails stay zero, so solvency is skipped the
    same way ``getConfigsForSolvency`` returns empty configs when there is no debt.
    """
    if config_words != len(_CONFIG_DATA_FIELDS):
        raise PropertyConfigError(
            "property_source_mismatch", "withdraw config width does not match ConfigData"
        )
    transfer_anchor = """        return true;
    }
}

contract LocalInterestRateModel {"""
    transfer = """        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (balanceOf[msg.sender] < amount) revert LocalAssetError("balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract LocalInterestRateModel {"""
    accrue_anchor = (
        f"        {silo_iface}(silo_).accrueInterestForConfig(rateModel, 0, 0);\n    }}\n"
    )
    both = f"""
    function accrueInterestForBothSilos() external {{
        if (msg.sender != boundSilo) revert LocalConfig("both");
        {silo_iface}(boundSilo).accrueInterestForConfig(rateModel, 0, 0);
    }}
"""
    selector = '        if (msg.sig != bytes4(0xe48a5f7b)) revert LocalConfig("selector");'
    selector_branch = """        if (msg.sig == bytes4(0x1544a6db)) {
            _withdrawConfig();
        }
        if (msg.sig != bytes4(0xe48a5f7b)) revert LocalConfig("selector");"""
    if (
        mock.count(transfer_anchor) != 1
        or mock.count(accrue_anchor) != 1
        or mock.count(selector) != 1
        or mock.count("    fallback() external {") != 1
    ):
        raise PropertyConfigError(
            "property_malformed", "the deposit mock layout could not be extended"
        )
    total_words = len(_DEPOSIT_CONFIG_FIELDS) + 2 * config_words
    slots = {name: index for index, (_type_name, name) in enumerate(_DEPOSIT_CONFIG_FIELDS)}
    helper = f"""    function _withdrawConfig() internal view {{
        address siloArg;
        assembly {{
            siloArg := calldataload(4)
        }}
        if (msg.sender != boundSilo || siloArg != boundSilo) revert LocalConfig("withdraw");
        address silo_ = boundSilo;
        address token_ = asset;
        address rate_ = rateModel;
        assembly {{
            let ptr := mload(0x40)
            for {{ let i := 0 }} lt(i, {total_words}) {{ i := add(i, 1) }} {{
                mstore(add(ptr, mul(i, 32)), 0)
            }}
            mstore(add(ptr, {slots["silo"] * 32}), silo_)
            mstore(add(ptr, {slots["token"] * 32}), token_)
            mstore(add(ptr, {slots["collateralShareToken"] * 32}), silo_)
            mstore(add(ptr, {slots["interestRateModel"] * 32}), rate_)
            return(ptr, {total_words * 32})
        }}
    }}

"""
    mock = mock.replace(transfer_anchor, transfer, 1)
    mock = mock.replace(accrue_anchor, accrue_anchor + both, 1)
    mock = mock.replace("    fallback() external {", helper + "    fallback() external {", 1)
    return mock.replace(selector, selector_branch, 1)


def render_partial_withdrawal_harness(
    texts: Mapping[str, str],
    *,
    contract: str,
    source_file: str,
    imports: Mapping[str, str],
) -> str:
    """Partial collateral withdraw after a mint breaks the exact offset ratio."""
    first = render_deposit_harness(
        texts,
        contract=contract,
        source_file=source_file,
        imports=imports,
        include_withdraw=True,
    )
    marker = "contract DepositAccountingTest {"
    if marker not in first:
        raise PropertyConfigError("property_malformed", "the deposit fixture could not be reused")
    prelude = first.split(marker)[0]
    silo_iface = _declared_name(strip_comments(texts[imports["error_interface"]]), "interface")
    factory = _declared_name(strip_comments(texts[imports["factory_interface"]]), "interface")
    config = _declared_name(strip_comments(texts[imports["config_interface"]]), "interface")
    if not silo_iface or not factory or not config:
        raise PropertyConfigError("property_source_mismatch", "the Silo interface is missing")
    clone_expr = _clone_expr(texts[source_file])
    return (
        prelude
        + f"""
contract LocalWithdrawer {{
    function fundAndDeposit(LocalAsset asset_, address silo, uint256 amount)
        external
        returns (uint256 minted)
    {{
        asset_.approve(silo, amount);
        (bool ok, bytes memory data) = silo.call(
            abi.encodeWithSelector(
                bytes4(keccak256("deposit(uint256,address)")), amount, address(this)
            )
        );
        if (!ok || data.length < 32) revert BugForgeFixture(data);
        minted = abi.decode(data, (uint256));
    }}

    function approveAndMint(LocalAsset asset_, address silo, uint256 shares)
        external
        returns (uint256 assets)
    {{
        asset_.approve(silo, asset_.balanceOf(address(this)));
        (bool ok, bytes memory data) = silo.call(
            abi.encodeWithSelector(
                bytes4(keccak256("mint(uint256,address)")), shares, address(this)
            )
        );
        if (!ok || data.length < 32) revert BugForgeFixture(data);
        assets = abi.decode(data, (uint256));
    }}

    function withdrawTo(address silo, uint256 amount, address receiver)
        external
        returns (bool ok, bytes memory data)
    {{
        (ok, data) = silo.call(
            abi.encodeWithSelector(
                bytes4(keccak256("withdraw(uint256,address,address)")),
                amount,
                receiver,
                address(this)
            )
        );
    }}
}}

contract PartialWithdrawalAccountingTest {{
    uint256 internal constant SEED = 1_000_000;
    uint256 internal constant OFFSET = 1000;
    uint256 internal constant MINT_SHARES = 2_001;
    event BugForgeState(string label, uint256 value);

    struct Case {{
        uint256 assetsBefore;
        uint256 supplyBefore;
        uint256 bShares;
        uint256 bTokens;
        uint256 siloTokens;
        uint256 receiverBefore;
        uint256 aShares;
        uint256 viewBefore;
        uint256 previewed;
        uint256 burned;
        uint256 formula;
        uint256 remainder;
        uint256 mintAssets;
        uint256 mintRemainder;
        uint256 ratioRemainder;
        uint256 boundary;
        uint256 receiverNow;
        uint256 siloNow;
        uint256 sharesNow;
        uint256 supplyNow;
        uint256 collateralNow;
        uint256 viewNow;
    }}

    Case internal currentCase;

    function test_partial_withdrawal_accounting() public {{
        _case(0, 1);
        _case(1, 2);
        _case(2, 3);
    }}

    function _case(uint256 index, uint256 amount) internal {{
        delete currentCase;
        ({contract} silo, LocalAsset asset_) = _setup();
        LocalWithdrawer first = new LocalWithdrawer();
        LocalWithdrawer second = new LocalWithdrawer();
        if (address(first) == address(second) || address(second) == address(this)) {{
            revert BugForgeFixture(bytes("same_actor"));
        }}
        _seed(silo, asset_, first);
        _mintNonExact(silo, asset_, second);
        _prepare(silo, asset_, first, second, amount);
        if (currentCase.previewed != currentCase.formula) {{
            revert BugForgeProperty("formula_mismatch");
        }}
        if (currentCase.formula > currentCase.bShares) {{
            if (index < 2) revert BugForgeProperty("expected_success");
            _boundary(index, amount, silo, asset_, first, second);
        }} else {{
            if (index == 2) revert BugForgeProperty("expected_boundary");
            if (currentCase.remainder == 0) revert BugForgeProperty("expected_remainder");
            _success(index, amount, silo, asset_, first, second);
        }}
    }}

    function _seed({contract} silo, LocalAsset asset_, LocalWithdrawer first) internal {{
        asset_.credit(address(first), SEED);
        uint256 minted = first.fundAndDeposit(asset_, address(silo), SEED);
        uint256 assetsBefore = silo.getTotalAssetsStorage({silo_iface}.AssetType.Collateral);
        uint256 supplyBefore = silo.totalSupply();
        if (minted == 0 || assetsBefore != SEED || supplyBefore != minted) {{
            revert BugForgeProperty("seed_accounting");
        }}
        if (silo.balanceOf(address(first)) != minted) revert BugForgeProperty("seed_receiver");
        if (supplyBefore + OFFSET != OFFSET * (assetsBefore + 1)) {{
            revert BugForgeProperty("offset_identity");
        }}
    }}

    function _mintNonExact({contract} silo, LocalAsset asset_, LocalWithdrawer second) internal {{
        uint256 assetsBefore = silo.getTotalAssetsStorage({silo_iface}.AssetType.Collateral);
        uint256 supplyBefore = silo.totalSupply();
        uint256 virtualShares = supplyBefore + OFFSET;
        uint256 virtualAssets = assetsBefore + 1;
        uint256 product = MINT_SHARES * virtualAssets;
        uint256 remainder = product % virtualShares;
        if (remainder == 0) revert BugForgeProperty("mint_exact");
        uint256 mintAssets = product / virtualShares + 1;
        asset_.credit(address(second), mintAssets);
        uint256 pulled = second.approveAndMint(asset_, address(silo), MINT_SHARES);
        if (pulled != mintAssets) revert BugForgeProperty("mint_assets");
        uint256 assetsAfter = silo.getTotalAssetsStorage({silo_iface}.AssetType.Collateral);
        uint256 supplyAfter = silo.totalSupply();
        if (assetsAfter != assetsBefore + pulled) revert BugForgeProperty("mint_collateral");
        if (supplyAfter != supplyBefore + MINT_SHARES) revert BugForgeProperty("mint_supply");
        if (silo.balanceOf(address(second)) != MINT_SHARES) revert BugForgeProperty("mint_receiver");
        uint256 ratioRemainder = (supplyAfter + OFFSET) % (assetsAfter + 1);
        if (ratioRemainder == 0) revert BugForgeProperty("ratio_exact");
        currentCase.assetsBefore = assetsAfter;
        currentCase.supplyBefore = supplyAfter;
        currentCase.mintAssets = pulled;
        currentCase.mintRemainder = remainder;
        currentCase.ratioRemainder = ratioRemainder;
    }}

    function _prepare(
        {contract} silo,
        LocalAsset asset_,
        LocalWithdrawer first,
        LocalWithdrawer second,
        uint256 amount
    ) internal {{
        currentCase.bShares = silo.balanceOf(address(second));
        currentCase.bTokens = asset_.balanceOf(address(second));
        currentCase.siloTokens = asset_.balanceOf(address(silo));
        currentCase.receiverBefore = asset_.balanceOf(address(this));
        currentCase.aShares = silo.balanceOf(address(first));
        currentCase.viewBefore = silo.totalAssets();
        if (currentCase.bTokens != 0) revert BugForgeProperty("mint_balance");
        if (currentCase.siloTokens != SEED + currentCase.mintAssets) {{
            revert BugForgeProperty("silo_balance");
        }}
        if (currentCase.receiverBefore != 0) revert BugForgeProperty("receiver_not_fresh");
        if (currentCase.viewBefore != currentCase.assetsBefore) {{
            revert BugForgeProperty("view_storage");
        }}
        uint256 virtualShares = currentCase.supplyBefore + OFFSET;
        uint256 virtualAssets = currentCase.assetsBefore + 1;
        uint256 product = amount * virtualShares;
        currentCase.remainder = product % virtualAssets;
        uint256 rounded = currentCase.remainder == 0 ? 0 : 1;
        currentCase.formula = product / virtualAssets + rounded;
        currentCase.previewed = _preview(silo, amount);
    }}

    function _success(
        uint256 index,
        uint256 amount,
        {contract} silo,
        LocalAsset asset_,
        LocalWithdrawer first,
        LocalWithdrawer second
    ) internal {{
        (bool ok, bytes memory data) = second.withdrawTo(address(silo), amount, address(this));
        if (!ok || data.length < 32) revert BugForgeFixture(data);
        currentCase.burned = abi.decode(data, (uint256));
        currentCase.boundary = 0;
        _capture(silo, asset_, second);
        _emitObserved(index, amount);
        _assertOwner(silo, first);
        _assertSuccess(amount);
    }}

    function _boundary(
        uint256 index,
        uint256 amount,
        {contract} silo,
        LocalAsset asset_,
        LocalWithdrawer first,
        LocalWithdrawer second
    ) internal {{
        (bool ok, bytes memory data) = second.withdrawTo(address(silo), amount, address(this));
        if (ok) revert BugForgeProperty("boundary_succeeded");
        bytes4 insufficient = bytes4(keccak256("ERC20InsufficientBalance(address,uint256,uint256)"));
        if (data.length < 4 || bytes4(data) != insufficient) revert BugForgeFixture(data);
        currentCase.burned = 0;
        currentCase.boundary = 1;
        _capture(silo, asset_, second);
        _emitObserved(index, amount);
        _assertOwner(silo, first);
        _assertBoundary();
    }}

    function _capture({contract} silo, LocalAsset asset_, LocalWithdrawer second) internal {{
        currentCase.receiverNow = asset_.balanceOf(address(this));
        currentCase.siloNow = asset_.balanceOf(address(silo));
        currentCase.sharesNow = silo.balanceOf(address(second));
        currentCase.supplyNow = silo.totalSupply();
        currentCase.collateralNow = silo.getTotalAssetsStorage({silo_iface}.AssetType.Collateral);
        currentCase.viewNow = silo.totalAssets();
    }}

    function _emitObserved(uint256 index, uint256 amount) internal {{
        _emit(index, "amount", amount);
        _emit(index, "assets_before", currentCase.assetsBefore);
        _emit(index, "supply_before", currentCase.supplyBefore);
        _emit(index, "b_shares", currentCase.bShares);
        _emit(index, "b_tokens", currentCase.bTokens);
        _emit(index, "silo_tokens", currentCase.siloTokens);
        _emit(index, "preview", currentCase.previewed);
        _emit(index, "burned", currentCase.burned);
        _emit(index, "formula", currentCase.formula);
        _emit(index, "remainder", currentCase.remainder);
        _emitDeltas(index);
    }}

    function _emitDeltas(uint256 index) internal {{
        _emit(index, "receiver_delta", currentCase.receiverNow - currentCase.receiverBefore);
        _emit(index, "silo_delta", currentCase.siloTokens - currentCase.siloNow);
        _emit(index, "supply_delta", currentCase.supplyBefore - currentCase.supplyNow);
        _emit(index, "collateral_delta", currentCase.assetsBefore - currentCase.collateralNow);
        _emit(index, "b_shares_after", currentCase.sharesNow);
        _emit(index, "mint_assets", currentCase.mintAssets);
        _emit(index, "mint_remainder", currentCase.mintRemainder);
        _emit(index, "ratio_remainder", currentCase.ratioRemainder);
        _emit(index, "view_before", currentCase.viewBefore);
        _emit(index, "boundary", currentCase.boundary);
    }}

    function _assertOwner({contract} silo, LocalWithdrawer first) internal view {{
        if (silo.balanceOf(address(first)) != currentCase.aShares) {{
            revert BugForgeProperty("first_depositor");
        }}
    }}

    function _assertBoundary() internal view {{
        if (currentCase.receiverNow != currentCase.receiverBefore) revert BugForgeProperty("boundary_mutated");
        if (currentCase.siloNow != currentCase.siloTokens) revert BugForgeProperty("boundary_mutated");
        if (currentCase.supplyNow != currentCase.supplyBefore) revert BugForgeProperty("boundary_mutated");
        if (currentCase.collateralNow != currentCase.assetsBefore) revert BugForgeProperty("boundary_mutated");
        if (currentCase.sharesNow != currentCase.bShares) revert BugForgeProperty("boundary_mutated");
        if (currentCase.viewNow != currentCase.viewBefore) revert BugForgeProperty("boundary_mutated");
        if (currentCase.burned != 0 || currentCase.sharesNow == 0) revert BugForgeProperty("boundary_mutated");
    }}

    function _assertSuccess(uint256 amount) internal view {{
        if (currentCase.burned > currentCase.previewed) revert BugForgeProperty("preview_short");
        if (currentCase.burned != currentCase.formula) revert BugForgeProperty("formula_mismatch");
        if (currentCase.burned == 0 || currentCase.sharesNow == 0) revert BugForgeProperty("owner_exited");
        if (currentCase.receiverNow != currentCase.receiverBefore + amount) revert BugForgeProperty("asset_delta");
        if (currentCase.siloNow + amount != currentCase.siloTokens) revert BugForgeProperty("asset_delta");
        if (currentCase.collateralNow + amount != currentCase.assetsBefore) revert BugForgeProperty("asset_delta");
        if (currentCase.supplyNow + currentCase.burned != currentCase.supplyBefore) {{
            revert BugForgeProperty("share_delta");
        }}
        if (currentCase.sharesNow + currentCase.burned != currentCase.bShares) {{
            revert BugForgeProperty("share_delta");
        }}
        if (currentCase.viewNow + amount != currentCase.viewBefore) revert BugForgeProperty("view_after");
    }}

    function _setup() internal returns ({contract} silo, LocalAsset asset_) {{
        asset_ = new LocalAsset();
        LocalInterestRateModel rate = new LocalInterestRateModel();
        LocalSiloConfig config_ = new LocalSiloConfig(address(asset_), address(rate));
        LocalFactory deployedFactory = new LocalFactory();
        {contract} implementation = new {contract}({factory}(address(deployedFactory)));
        silo = {contract}({clone_expr});
        config_.bind(address(silo));
        (bool ok, bytes memory data) = address(silo).call(
            abi.encodeCall({contract}.initialize, ({config}(address(config_))))
        );
        if (!ok) revert BugForgeFixture(data);
    }}

    function _preview({contract} silo, uint256 amount) internal view returns (uint256 previewed) {{
        (bool ok, bytes memory data) = address(silo).staticcall(
            abi.encodeWithSelector(bytes4(keccak256("previewWithdraw(uint256)")), amount)
        );
        if (!ok || data.length < 32) revert BugForgeFixture(data);
        previewed = abi.decode(data, (uint256));
    }}

    function _emit(uint256 index, string memory key, uint256 value) internal {{
        string memory prefix = "w2_";
        if (index == 0) prefix = "w0_";
        else if (index == 1) prefix = "w1_";
        else if (index != 2) revert BugForgeFixture(bytes("index"));
        emit BugForgeState(string.concat(prefix, key), value);
    }}
}}
"""
    )


def _clone_expr(contract_text: str) -> str:
    clean = strip_comments(contract_text)
    payable = bool(
        re.search(r"\breceive\s*\(\s*\)\s+external\s+payable\b", clean)
        or re.search(r"\bfallback\s*\(\s*\)\s+external\s+payable\b", clean)
    )
    cloned = "Clones.clone(address(implementation))"
    return f"payable({cloned})" if payable else cloned


def _enum_index(text: str, enum: str, member: str) -> int | None:
    match = re.search(rf"enum\s+{enum}\s*\{{([^}}]*)\}}", text)
    if match is None:
        return None
    members = [item.strip().split()[0] for item in match.group(1).split(",") if item.strip()]
    return members.index(member) if member in members else None


def _function_bodies(text: str, name: str) -> list[str]:
    return [
        body
        for match in re.finditer(rf"function\s+{name}\b", text)
        if (body := _brace_block(text, match.start()))
    ]


def _execute_one(
    prop: Mapping[str, Any],
    repo_root: Path,
    sources: Mapping[str, str],
    *,
    compiler_path: str,
    project: ProjectSettings | None,
    timeout: int,
) -> tuple[dict[str, Any], int]:
    base = _base_record(prop)
    try:
        current = _normalize_one(repo_root, prop)
    except PropertyConfigError as exc:
        return {
            **base,
            "outcome": "inconclusive",
            "reason": exc.reason,
            "reason_code": exc.code,
            "process_status": "not_run",
            "compiler_status": "not_run",
            "test_status": "not_run",
            "sequence_status": "not_run",
            "property_status": "not_run",
            "forge_invoked": False,
        }, 0
    if not tool_path("forge") or not compiler_path:
        missing = "forge" if not tool_path("forge") else "solc"
        return {
            **base,
            "outcome": "unavailable",
            "reason": f"{missing} is not installed",
            "reason_code": "tool_missing",
            "process_status": "not_run",
            "compiler_status": "not_run",
            "test_status": "not_run",
            "sequence_status": "not_run",
            "property_status": "not_run",
            "forge_invoked": False,
        }, 0
    try:
        compiled = _compile_sources(repo_root, current, sources)
        texts = _read_cited(
            repo_root,
            (
                str(current["source_file"]),
                *dict(current["imports"]).values(),
                *(item["path"] for item in current["locations"]),
            ),
        )
        if current["kind"] == "initialization_once":
            harness = render_initialization_harness(
                texts,
                contract=str(current["contract"]),
                source_file=str(current["source_file"]),
                error=str(current["expected_error"]),
                imports=dict(current["imports"]),
            )
        elif current["kind"] == "deposit_twice_accounting":
            harness = render_second_deposit_harness(
                texts,
                contract=str(current["contract"]),
                source_file=str(current["source_file"]),
                imports=dict(current["imports"]),
            )
        elif current["kind"] == "partial_withdrawal_accounting":
            harness = render_partial_withdrawal_harness(
                texts,
                contract=str(current["contract"]),
                source_file=str(current["source_file"]),
                imports=dict(current["imports"]),
            )
        else:
            harness = render_deposit_harness(
                texts,
                contract=str(current["contract"]),
                source_file=str(current["source_file"]),
                imports=dict(current["imports"]),
            )
    except (OSError, UnicodeError, PropertyConfigError) as exc:
        reason = exc.reason if isinstance(exc, PropertyConfigError) else str(exc)[:200]
        code = exc.code if isinstance(exc, PropertyConfigError) else "source_unreadable"
        return {
            **base,
            "outcome": "inconclusive",
            "reason": reason,
            "reason_code": code,
            "process_status": "not_run",
            "compiler_status": "not_run",
            "test_status": "not_run",
            "sequence_status": "not_run",
            "property_status": "not_run",
            "forge_invoked": False,
        }, 0
    cheats = untrusted_cheatcode_use({**compiled, str(current["test_file"]): harness})
    if cheats:
        return {
            **base,
            "outcome": "inconclusive",
            "reason": "cheatcode references block local execution: " + "; ".join(cheats),
            "reason_code": "blocked_by_policy:cheatcode_in_source",
            "process_status": "not_run",
            "compiler_status": "not_run",
            "test_status": "not_run",
            "sequence_status": "not_run",
            "property_status": "not_run",
            "forge_invoked": False,
        }, 0
    remappings = _safe_remappings(repo_root, set(compiled))
    config = foundry_config("default", compiler_path, project, remappings)
    forge = tool_path("forge") or "forge"
    with tempfile.TemporaryDirectory(prefix="bugforge-explicit-") as tmp:
        root = Path(tmp)
        scaffold(root, compiled, harness, config, test_filename=str(current["test_file"]))
        build = run_local_forge(forge, ["build", "--offline"], root, timeout)
        if build["process_status"] != "completed":
            judged = classify_explicit_result(
                process_status=build["process_status"],
                compiler_status="not_run",
                return_code=build["return_code"],
                stdout=build["stdout"],
                stderr=build["stderr"],
                expected_test=str(current["test_entry_point"]),
            )
            return _finish(base, judged, build, harness, forged=True), 1
        if build["return_code"] != 0:
            judged = classify_explicit_result(
                process_status="completed",
                compiler_status="failed",
                return_code=build["return_code"],
                stdout=build["stdout"],
                stderr=build["stderr"],
                expected_test=str(current["test_entry_point"]),
            )
            return _finish(base, judged, build, harness, forged=True), 1
        test = run_local_forge(
            forge,
            ["test", "--offline", "--json", "-vv", "--match-path", f"test/{current['test_file']}"],
            root,
            timeout,
        )
    judged = classify_explicit_result(
        process_status=test["process_status"],
        compiler_status="ok",
        return_code=test["return_code"],
        stdout=test["stdout"],
        stderr=test["stderr"],
        expected_test=str(current["test_entry_point"]),
    )
    record = _finish(base, judged, test, harness, forged=True)
    record["compiler_status"] = "ok"
    record["state_observations"] = _state_observations(test["stdout"])
    record["verdict"] = _verdict(judged["outcome"])
    return record, 1


def _finish(
    base: dict[str, Any],
    judged: Mapping[str, str],
    proc: Mapping[str, Any],
    harness: str,
    *,
    forged: bool,
) -> dict[str, Any]:
    return {
        **base,
        **judged,
        "process_status": proc["process_status"],
        "return_code": proc["return_code"],
        "stdout_tail": str(proc["stdout"])[-2000:],
        "stderr_tail": str(proc["stderr"])[-2000:],
        "harness_sha256": sha256_text(harness),
        "forge_invoked": forged,
        "executed": judged["property_status"] in {"held", "violated"},
        "verdict": _verdict(judged["outcome"]),
        "verified": False,
        "vulnerability_finding": False,
        "strong_candidate": False,
    }


def _verdict(outcome: str) -> str:
    if outcome in {"property_held", "property_violated", "not_tested"}:
        return outcome
    return "not_evaluated"


def _base_record(prop: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "sequence_id": str(prop.get("property_id", "explicit")),
        "derived_from": "",
        "origin": "researcher_supplied",
        "property_source": "researcher_supplied",
        "property_id": str(prop.get("property_id", "")),
        "declaration": "property_under_test",
        "verdict": "not_evaluated",
        "oracle_kind": str(prop.get("kind", "initialization_once")),
        "candidate": False,
        "strong_candidate": False,
        "verified": False,
        "vulnerability_finding": False,
        "test_entry_point": str(prop.get("test_entry_point", "")),
    }


def _validate_initialization_once(
    texts: Mapping[str, str],
    *,
    source_file: str,
    contract: str,
    entry: str,
    getter: str,
    error: str,
    deployment: str,
    imports: Mapping[str, str],
) -> None:
    contract_text = strip_comments(texts[source_file])
    if not re.search(rf"\b(?:contract|abstract\s+contract)\s+{contract}\b", contract_text):
        raise PropertyConfigError("property_source_mismatch", f"{contract} is not declared")
    body = _function_body(contract_text, entry)
    if not body or "Actions.initialize" not in body:
        raise PropertyConfigError(
            "property_source_mismatch", f"{entry} does not call Actions.initialize"
        )
    if not re.search(rf"function\s+{entry}\s*\(\s*ISiloConfig\b", contract_text):
        raise PropertyConfigError(
            "property_source_mismatch", f"{entry} does not take an ISiloConfig argument"
        )
    if not re.search(r"constructor\s*\(\s*ISiloFactory\b", contract_text):
        raise PropertyConfigError(
            "property_source_mismatch", "the constructor does not take ISiloFactory"
        )
    getter_body = _function_body(contract_text, getter)
    if not getter_body or "siloConfig()" not in getter_body:
        raise PropertyConfigError(
            "property_source_mismatch", f"{getter} does not read the stored configuration"
        )
    actions = _actions_body(texts)
    if actions is None:
        raise PropertyConfigError(
            "property_source_mismatch",
            "the source has no zero-address initialization guard to test",
        )
    require = _REQUIRE.search(actions)
    assign = _ASSIGN.search(actions)
    if require is None or assign is None or require.end() > assign.start():
        raise PropertyConfigError(
            "property_source_mismatch",
            "the initialization guard does not revert before the configuration is stored",
        )
    if require.group(1) != error:
        raise PropertyConfigError(
            "property_source_mismatch",
            f"the source reverts with {require.group(1)}, not {error}",
        )
    if "configData.hookReceiver" not in actions:
        raise PropertyConfigError(
            "property_source_mismatch", "initialization does not read hookReceiver"
        )
    if not any(re.search(rf"\berror\s+{error}\s*\(", text) for text in texts.values()):
        raise PropertyConfigError("property_source_mismatch", f"error {error} is not declared")
    disables = any("_disableInitializers()" in text for text in texts.values())
    if disables and deployment != "eip1167_clone":
        raise PropertyConfigError(
            "property_fixture_rejected",
            "the implementation constructor disables initializers, so the instance must be a clone",
        )
    if not disables:
        raise PropertyConfigError(
            "property_source_mismatch",
            "this source does not disable initializers on the implementation; the clone fixture "
            "was not established",
        )
    clones = strip_comments(texts[imports["clones"]])
    if "function clone(address" not in clones:
        raise PropertyConfigError("property_source_mismatch", "Clones.clone is not available")


def _actions_body(texts: Mapping[str, str]) -> str | None:
    for text in texts.values():
        clean = strip_comments(text)
        body = _function_body(clean, "initialize")
        if body and _REQUIRE.search(body):
            return body
    return None


def _compile_sources(
    repo_root: Path, prop: Mapping[str, Any], sources: Mapping[str, str]
) -> dict[str, str]:
    targets = [str(prop["source_file"]), str(dict(prop["imports"])["clones"])]
    closure = resolve_import_closure(repo_root, tuple(dict.fromkeys(targets)))
    if not closure.closure_complete:
        missing = ", ".join(edge.spec for edge in closure.unresolved[:4])
        raise PropertyConfigError(
            "dependency_unresolved", f"the property closure is incomplete ({missing})"
        )
    compiled: dict[str, str] = {}
    for path in (*closure.targets, *closure.dependencies):
        if path in sources:
            compiled[path] = sources[path]
            continue
        file_path = repo_root / path
        compiled[path] = file_path.read_text(encoding="utf-8")
    return compiled


def _safe_remappings(repo_root: Path, copied: set[str]) -> tuple[str, ...]:
    raw, notes = _read_remappings(repo_root)
    if notes and not raw:
        return ()
    found: list[str] = []
    for line in raw:
        mapped = _solc_remapping(line)
        if "=" not in mapped:
            continue
        prefix, target = mapped.split("=", 1)
        if target.startswith("/") or ".." in target or ".." in prefix:
            continue
        folder = target.lstrip("./").rstrip("/")
        if not folder:
            continue
        if any(path == folder or path.startswith(folder + "/") for path in copied):
            found.append(f"{prefix}=src/{folder}/")
    return tuple(found)


def _state_observations(stdout: str) -> list[dict[str, str]]:
    """Addresses emitted by the harness, when Forge includes the decoded logs."""
    found: list[dict[str, str]] = []
    decoder = json.JSONDecoder()
    index = stdout.find("{")
    while index >= 0:
        try:
            payload, end = decoder.raw_decode(stdout[index:])
        except json.JSONDecodeError:
            index = stdout.find("{", index + 1)
            continue
        _collect_states(payload, found)
        index = stdout.find("{", index + end)
        if found:
            break
    return found


def _collect_states(node: Any, found: list[dict[str, str]]) -> None:
    if isinstance(node, dict):
        data = node.get("decoded_logs") or node.get("logs")
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                decoded = _decode_state_log(item)
                if decoded is not None:
                    found.append(decoded)
                    continue
                topics = item.get("topics") or item.get("data")
                label = str(item.get("name") or item.get("label") or "")
                if "BugForgeState" in json.dumps(item)[:500]:
                    found.append(
                        {"raw": json.dumps(item)[:300], "label": label, "topics": str(topics)[:120]}
                    )
        for value in node.values():
            if len(found) >= 64:
                return
            _collect_states(value, found)
    elif isinstance(node, list):
        for value in node:
            if len(found) >= 64:
                return
            _collect_states(value, found)


_ADDRESS_LABELS = frozenset({"after_first", "after_second"})
_NUMBER_LABELS = frozenset(
    {
        "preview_shares",
        "minted_shares",
        "user_assets_before",
        "user_assets_after",
        "silo_assets_before",
        "silo_assets_after",
        "share_balance_before",
        "share_balance_after",
        "collateral_before",
        "collateral_after",
    }
)
_CASE_LABEL = re.compile(
    r"^a[0-3]_(?:amount|assets_before|supply_before|preview|minted|formula|remainder|"
    r"receiver_delta|silo_delta|supply_delta|collateral_delta|first_minted|view_before)$"
)
_WITHDRAW_LABEL = re.compile(
    r"^w[0-2]_(?:amount|assets_before|supply_before|b_shares|b_tokens|silo_tokens|"
    r"preview|burned|formula|remainder|receiver_delta|silo_delta|supply_delta|"
    r"collateral_delta|b_shares_after|mint_assets|mint_remainder|ratio_remainder|"
    r"view_before|boundary)$"
)


def _decode_state_log(item: Mapping[str, Any]) -> dict[str, str] | None:
    """Decode BugForgeState(string,word) from a raw Forge log."""
    data = item.get("data")
    if not isinstance(data, str) or not data.startswith("0x"):
        return None
    raw = data[2:]
    if len(raw) < 256 or len(raw) % 64 != 0:
        return None
    try:
        words = [raw[index : index + 64] for index in range(0, len(raw), 64)]
        offset = int(words[0], 16) // 32
        if offset >= len(words) - 1:
            return None
        length = int(words[offset], 16)
        if not 0 < length <= 32:
            return None
        label = bytes.fromhex(words[offset + 1])[:length].decode("ascii")
    except (ValueError, UnicodeError, IndexError):
        return None
    if label in _ADDRESS_LABELS:
        value = "0x" + words[1][-40:]
        if int(value, 16) == 0:
            return None
        return {"label": label, "value": value}
    if label in _NUMBER_LABELS or _CASE_LABEL.fullmatch(label) or _WITHDRAW_LABEL.fullmatch(label):
        return {"label": label, "value": str(int(words[1], 16))}
    return None


def _read_cited(repo_root: Path, paths: Sequence[str]) -> dict[str, str]:
    texts: dict[str, str] = {}
    root = repo_root.resolve()
    for path in paths:
        relative = _relative(path)
        file_path = (root / relative).resolve()
        if root not in file_path.parents or not file_path.is_file():
            raise PropertyConfigError("property_incomplete", f"missing source file {relative}")
        texts[relative] = file_path.read_text(encoding="utf-8")
    return texts


def _locations(raw: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, str) or not raw:
        raise PropertyConfigError("property_incomplete", "locations must name the source symbols")
    found: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise PropertyConfigError("property_incomplete", "a location must be an object")
        path = _relative(item.get("path"))
        symbol = _identifier(item.get("symbol"), "symbol")
        found.append((path, symbol))
    return tuple(found)


def _imports(raw: Any) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise PropertyConfigError("property_incomplete", "imports must name the fixture files")
    required = ("factory_interface", "config_interface", "error_interface", "clones")
    found: dict[str, str] = {}
    for key in required:
        found[key] = _relative(raw.get(key))
    return found


def _fixtures(raw: Any, extra: set[str] | None = None) -> tuple[str, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, str) or not raw:
        raise PropertyConfigError("property_incomplete", "fixture_dependencies are required")
    found = tuple(str(item).strip() for item in raw if str(item).strip())
    required = {"local_factory", "local_silo_config", "eip1167_clone"} | set(extra or ())
    if not required <= set(found):
        missing = ", ".join(sorted(required - set(found)))
        raise PropertyConfigError(
            "property_incomplete", f"fixture_dependencies must include {missing}"
        )
    return found


def _function_body(text: str, name: str) -> str:
    match = re.search(rf"function\s+{name}\b", text)
    if match is None:
        return ""
    return _brace_block(text, match.start())


def _brace_block(text: str, start: int) -> str:
    opened = text.find("{", start)
    if opened < 0:
        return ""
    depth = 0
    for index in range(opened, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[opened : index + 1]
    return ""


def _struct_fields(text: str, name: str) -> list[tuple[str, str]]:
    match = re.search(rf"struct\s+{name}\b", text)
    if match is None:
        return []
    body = _brace_block(text, match.start())
    fields: list[tuple[str, str]] = []
    for part in body.strip("{}").split(";"):
        tokens = part.split()
        if len(tokens) < 2:
            continue
        type_name, field = tokens[0], tokens[1]
        if type_name not in _ALLOWED_FIELD or not _IDENT.fullmatch(field):
            raise PropertyConfigError(
                "property_fixture_rejected", f"ConfigData field {field} is not a supported type"
            )
        fields.append((type_name, field))
    return fields


def _declared_name(text: str, kind: str) -> str:
    match = re.search(rf"\b{kind}\s+([A-Za-z_]\w*)", text)
    return match.group(1) if match else ""


def _entry_name(text: str) -> str:
    match = re.search(r"function\s+(initialize)\b", strip_comments(text))
    return match.group(1) if match else "initialize"


def _getter_name(text: str) -> str:
    match = re.search(r"function\s+(config)\b", strip_comments(text))
    return match.group(1) if match else "config"


def _test_import(path: str) -> str:
    return f"../src/{path}"


def _relative(value: Any) -> str:
    text = str(value or "").strip()
    if not _RELATIVE.fullmatch(text) or ".." in text or text.startswith("/"):
        raise PropertyConfigError("property_incomplete", f"unsafe source path {value!r}")
    return text


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _IDENT.fullmatch(text):
        raise PropertyConfigError("property_incomplete", f"{label} is missing or malformed")
    return text
