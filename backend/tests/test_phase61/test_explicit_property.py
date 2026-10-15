"""Researcher-supplied properties execute without becoming detector candidates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.discovery.bounty.explicit_property import (
    PropertyConfigError,
    _base_record,
    _state_observations,
    classify_explicit_result,
    normalize_explicit_properties,
    render_initialization_harness,
)
from app.discovery.bounty.research_ledger import campaign_coverage
from app.discovery.bounty.service import BountyCampaignService, CampaignError, CampaignSpec
from app.discovery.process import tool_path
from tests.test_phase51.phase51_support import manifest

ACTIONS = """
import {ISiloConfig} from "./ISiloConfig.sol";
import {ISilo} from "./ISilo.sol";
library Actions {
    struct Slot { address siloConfig; }
    function slot() internal pure returns (Slot storage s) {
        assembly { s.slot := 0 }
    }
    function initialize(ISiloConfig _siloConfig) internal {
        Slot storage _sharedStorage = slot();
        require(address(_sharedStorage.siloConfig) == address(0), ISilo.SiloInitialized());
        ISiloConfig.ConfigData memory configData = _siloConfig.getConfig(address(this));
        _sharedStorage.siloConfig = address(_siloConfig);
        if (configData.hookReceiver == address(this)) return;
    }
}
"""

FACTORY = "interface ISiloFactory {}\n"
CONFIG = """
interface ISiloConfig {
    struct ConfigData { address hookReceiver; }
    function getConfig(address _silo) external view returns (ConfigData memory config);
}
"""
ERROR = "interface ISilo { error SiloInitialized(); }\n"
SHARE = """
contract ShareToken {
    function _disableInitializers() internal {}
    constructor() { _disableInitializers(); }
}
"""
CLONES = """
library Clones {
    function clone(address implementation) internal returns (address instance) {
        assembly {
            mstore(0x20, 0x5af43d82803e903d91602b57fd5bf3)
            mstore(0x11, implementation)
            mstore(0x00, or(shr(0x88, implementation), 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000))
            instance := create(0, 0x09, 0x37)
        }
        require(instance != address(0));
    }
}
"""
CONTRACT = """
import {ISiloFactory} from "./ISiloFactory.sol";
import {ISiloConfig} from "./ISiloConfig.sol";
import {Actions} from "./Actions.sol";
import {ShareToken} from "./ShareToken.sol";
contract Silo is ShareToken {
    constructor(ISiloFactory) {}
    function initialize(ISiloConfig _config) external {
        Actions.initialize(_config);
    }
    function siloConfig() internal view returns (address) {
        return Actions.slot().siloConfig;
    }
    function config() external view returns (ISiloConfig) {
        return ISiloConfig(siloConfig());
    }
}
"""


def _write(root: Path) -> None:
    files = {
        "Silo.sol": CONTRACT,
        "Actions.sol": ACTIONS,
        "ISiloFactory.sol": FACTORY,
        "ISiloConfig.sol": CONFIG,
        "ISilo.sol": ERROR,
        "ShareToken.sol": SHARE,
        "Clones.sol": CLONES,
    }
    for name, body in files.items():
        (root / name).write_text(
            f"// SPDX-License-Identifier: MIT\npragma solidity 0.8.28;\n{body}\n",
            encoding="utf-8",
        )


def _property(**overrides: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "property_id": "silo.initialize_once",
        "source": "researcher_supplied",
        "kind": "initialization_once",
        "contract": "Silo",
        "source_file": "Silo.sol",
        "entry_point": "initialize",
        "state_getter": "config",
        "expected_error": "SiloInitialized",
        "deployment": "eip1167_clone",
        "rationale": "A second initialize must revert and leave the first configuration in place.",
        "locations": [
            {"path": "Silo.sol", "symbol": "initialize"},
            {"path": "Actions.sol", "symbol": "SiloInitialized"},
            {"path": "ISilo.sol", "symbol": "SiloInitialized"},
            {"path": "ShareToken.sol", "symbol": "_disableInitializers"},
        ],
        "imports": {
            "factory_interface": "ISiloFactory.sol",
            "config_interface": "ISiloConfig.sol",
            "error_interface": "ISilo.sol",
            "clones": "Clones.sol",
        },
        "fixture_dependencies": ["local_factory", "local_silo_config", "eip1167_clone"],
    }
    raw.update(overrides)
    return raw


def test_a_source_backed_property_is_accepted_and_the_mock_has_no_guard(tmp_path: Path) -> None:
    _write(tmp_path)
    accepted = normalize_explicit_properties(tmp_path, (_property(),))
    assert accepted[0]["source"] == "researcher_supplied"
    assert accepted[0]["validation"] == "accepted"
    assert accepted[0]["vulnerability_finding"] is False
    texts = {path.name: path.read_text(encoding="utf-8") for path in tmp_path.glob("*.sol")}
    harness = render_initialization_harness(
        texts,
        contract="Silo",
        source_file="Silo.sol",
        error="SiloInitialized",
        imports=dict(accepted[0]["imports"]),
    )
    mock = harness.split("contract InitializeOnceTest")[0]
    assert "require" not in mock
    assert "SiloInitialized" not in mock
    assert "Clones.clone" in harness
    assert "config_replaced" in harness


def test_incomplete_and_contradictory_properties_are_rejected(tmp_path: Path) -> None:
    _write(tmp_path)
    with pytest.raises(PropertyConfigError, match="rationale"):
        normalize_explicit_properties(tmp_path, (_property(rationale="too short"),))
    with pytest.raises(PropertyConfigError, match="not a detector"):
        normalize_explicit_properties(tmp_path, (_property(detector="sol.initializer"),))
    with pytest.raises(PropertyConfigError, match="not MissingError"):
        normalize_explicit_properties(tmp_path, (_property(expected_error="MissingError"),))
    with pytest.raises(PropertyConfigError, match="must be a clone"):
        normalize_explicit_properties(tmp_path, (_property(deployment="direct"),))
    missing = _property()
    locations = list(missing["locations"])
    locations[1] = {"path": "Actions.sol", "symbol": "NotInSource"}
    missing["locations"] = locations
    with pytest.raises(PropertyConfigError, match="NotInSource"):
        normalize_explicit_properties(tmp_path, (missing,))


def _forge(name: str) -> str:
    return (Path(__file__).parent / "fixtures" / name).read_text(encoding="utf-8")


def _judge(stdout: str, *, return_code: int | None = 0, stderr: str = "", **overrides: object):
    payload = {
        "process_status": "completed",
        "compiler_status": "ok",
        "return_code": return_code,
        "stdout": stdout,
        "stderr": stderr,
        "expected_test": "test_initialize_once",
    }
    payload.update(overrides)
    return classify_explicit_result(**payload)


def test_foundry_json_classifies_only_the_executed_test() -> None:
    held = _judge(_forge("foundry_1_4_4_initialize_campaign.json"))
    assert held["outcome"] == "property_held"
    assert held["property_status"] == "held"
    assert held["test_status"] == "passed"
    assert held["matched_test"] == "test_initialize_once()"
    plain = _judge(_forge("foundry_1_4_4_pass.json"))
    assert plain["outcome"] == "property_held"
    assert plain["matched_test"] == "test_initialize_once()"
    unrelated = _judge(
        _forge("foundry_1_4_4_pass.json"),
        stderr='BugForgeProperty("config_replaced")',
    )
    assert unrelated["outcome"] == "property_held"
    missing = _judge("", stderr="Warning: no tests match the provided pattern:\n")
    assert missing["outcome"] == "not_tested"
    assert missing["reason_code"] == "no_tests_matched"
    assert missing["property_status"] == "not_run"
    other = _judge(_forge("foundry_1_4_4_other_test.json"))
    assert other["outcome"] == "not_tested"
    assert other["reason_code"] == "expected_test_missing"
    skipped = _judge(_forge("foundry_1_4_4_skipped.json"))
    assert skipped["outcome"] == "not_tested"
    assert skipped["test_status"] == "skipped"
    assert skipped["reason_code"] == "test_skipped"
    violated = _judge(_forge("foundry_1_4_4_property_failure.json"), return_code=1)
    assert violated["outcome"] == "property_violated"
    assert violated["property_status"] == "violated"
    assert "config_replaced" in violated["reason"]
    fixture = _judge(_forge("foundry_1_4_4_fixture_failure.json"), return_code=1)
    assert fixture["outcome"] == "inconclusive"
    assert fixture["reason_code"] == "fixture_failed"
    assert fixture["property_status"] == "not_evaluated"
    text_only = _judge('BugForgeProperty("config_replaced")', return_code=1)
    assert text_only["outcome"] == "inconclusive"
    assert text_only["reason_code"] == "malformed_output"
    assert text_only["property_status"] == "not_run"
    malformed = _judge('{"test_results":')
    assert malformed["outcome"] == "inconclusive"
    assert malformed["reason_code"] == "malformed_output"
    compiled = _judge(
        "",
        compiler_status="failed",
        return_code=1,
        stderr="Compiler run failed",
    )
    assert compiled["outcome"] == "compile_failed"
    assert compiled["test_status"] == "not_run"
    assert compiled["property_status"] == "not_run"
    timed = classify_explicit_result(
        process_status="timeout",
        compiler_status="ok",
        return_code=None,
        stdout=_forge("foundry_1_4_4_pass.json"),
        stderr="",
        expected_test="test_initialize_once",
    )
    assert timed["outcome"] == "timeout"
    assert timed["property_status"] == "not_run"


def test_raw_forge_logs_record_the_configuration_before_and_after() -> None:
    stdout = json.dumps(
        {
            "logs": [
                {
                    "data": (
                        "0x"
                        "0000000000000000000000000000000000000000000000000000000000000040"
                        "0000000000000000000000005991a2df15a8f6a256d3ec51e99254cd3fb576a9"
                        "000000000000000000000000000000000000000000000000000000000000000b"
                        "61667465725f6669727374000000000000000000000000000000000000000000"
                    )
                },
                {
                    "data": (
                        "0x"
                        "0000000000000000000000000000000000000000000000000000000000000040"
                        "0000000000000000000000005991a2df15a8f6a256d3ec51e99254cd3fb576a9"
                        "000000000000000000000000000000000000000000000000000000000000000c"
                        "61667465725f7365636f6e640000000000000000000000000000000000000000"
                    )
                },
            ]
        }
    )
    observed = _state_observations(stdout)
    assert observed == [
        {"label": "after_first", "value": "0x5991a2df15a8f6a256d3ec51e99254cd3fb576a9"},
        {"label": "after_second", "value": "0x5991a2df15a8f6a256d3ec51e99254cd3fb576a9"},
    ]


def test_a_held_explicit_property_is_not_a_verified_finding() -> None:
    summary = campaign_coverage(
        files_selected=1,
        files_read=1,
        candidates=0,
        sequences=0,
        executions={
            "silo.initialize_once": {
                "outcome": "property_held",
                "process_status": "completed",
                "compiler_status": "ok",
                "test_status": "passed",
                "sequence_status": "completed",
                "property_status": "held",
                "origin": "researcher_supplied",
            }
        },
        forge_runs=1,
        explicit_properties=(
            {"property_id": "silo.initialize_once", "source": "researcher_supplied"},
        ),
    )
    assert summary["candidates"] == 0
    assert summary["verified"] is False
    assert summary["blocker"] == ""
    assert summary["property_evaluation_demonstrated"] is True
    assert summary["explicit_properties_registered"] == 1
    assert summary["by_outcome"] == {"property_held": 1}


def test_create_rejects_an_incomplete_property(tmp_path: Path) -> None:
    _write(tmp_path)
    spec = CampaignSpec(
        manifest=_scoped_manifest(),
        repo_root=tmp_path,
        contract="Silo",
        source_file="Silo.sol",
        files=("Silo.sol",),
        explicit_properties=(_property(rationale="short"),),
    )
    with pytest.raises(CampaignError, match="property_incomplete"):
        BountyCampaignService().create(spec)


def test_an_explicit_property_reaches_foundry_without_a_detector_candidate(tmp_path: Path) -> None:
    _write(tmp_path)
    spec = CampaignSpec(
        manifest=_scoped_manifest(),
        repo_root=tmp_path,
        contract="Silo",
        source_file="Silo.sol",
        files=("Silo.sol",),
        explicit_properties=(_property(),),
    )
    svc = BountyCampaignService()
    campaign = svc.create(spec)
    assert campaign.spec.explicit_properties[0]["source"] == "researcher_supplied"
    analysis = svc._analysis(campaign)
    assert all(item.detector != "researcher_supplied" for item in analysis.candidates)
    if tool_path("forge") is None:
        result = svc.stateful_execute(campaign.campaign_id, rounds=1)
        explicit = result["explicit_properties"]["silo.initialize_once"]
        assert explicit["outcome"] == "unavailable"
        assert explicit["property_status"] == "not_run"
        assert explicit["vulnerability_finding"] is False
        assert result["campaign_summary"]["verified"] is False
        return
    result = svc.stateful_execute(campaign.campaign_id, rounds=1)
    explicit = result["explicit_properties"]["silo.initialize_once"]
    assert explicit["forge_invoked"] is True
    assert explicit["test_entry_point"] == "test_initialize_once"
    assert explicit["outcome"] == "property_held", explicit.get("stderr_tail", "")[-500:]
    assert explicit["property_status"] == "held"
    assert explicit["compiler_status"] == "ok"
    assert explicit["test_status"] == "passed"
    assert explicit["executed"] is True
    assert explicit["vulnerability_finding"] is False
    assert explicit["strong_candidate"] is False
    summary = result["campaign_summary"]
    assert summary["candidates"] == len(analysis.candidates)
    assert summary["verified"] is False
    assert summary["property_evaluation_demonstrated"] is True
    assert summary["foundry_invoked"] is True
    assert "property_held" in summary["by_outcome"]


DEPOSIT_SILO = """
import {ISiloFactory} from "./ISiloFactory.sol";
import {ISiloConfig} from "./ISiloConfig.sol";
import {Actions} from "./Actions.sol";
import {ShareToken} from "./ShareToken.sol";
contract Silo is ShareToken {
    constructor(ISiloFactory) {}
    function initialize(ISiloConfig _config) external { Actions.initialize(_config); }
    function deposit(uint256 _assets, address _receiver) external returns (uint256 shares) {
        (, shares) = _deposit(_assets, _receiver);
    }
    function previewDeposit(uint256 _assets) external view returns (uint256 shares) {
        shares = _assets;
    }
    function _deposit(uint256 _assets, address) internal returns (uint256, uint256) {
        return Actions.deposit(_assets);
    }
    function config() external view returns (ISiloConfig) { return ISiloConfig(siloConfig()); }
    function siloConfig() internal view returns (address) { return address(0); }
}
"""
DEPOSIT_ACTIONS = """
library Actions {
    function initialize(address) internal {}
    function deposit(uint256 _assets) internal returns (uint256, uint256) {
        accrueInterestForSilo(address(0));
        getCollateralShareTokenAndAsset(address(0), 1);
        SiloERC4626Lib.deposit(_assets);
        return (_assets, _assets);
    }
}
"""
DEPOSIT_MATH = """
library SiloMathLib { uint256 internal constant _DECIMALS_OFFSET = 3; }
library Rounding { uint256 internal constant DEPOSIT_TO_SHARES = 0; }
library Interest { function accrue() internal pure { uint256 lastTimestamp = 0; if (lastTimestamp == 0) return; } }
"""
DEPOSIT_SHARE = """
contract ShareToken {
    function _disableInitializers() internal {}
    constructor() { _disableInitializers(); }
    function mint(address _owner, address, uint256) external {}
}
"""
DEPOSIT_CONFIG = """
interface ISiloConfig {
    struct ConfigData {
        uint256 daoFee;
        address silo;
        address token;
        address collateralShareToken;
        address interestRateModel;
        address hookReceiver;
    }
    function getConfig(address) external view returns (ConfigData memory);
}
"""
DEPOSIT_SILO_IFACE = """
interface ISilo {
    enum AssetType { Protected, Collateral, Debt }
    enum CollateralType { Protected, Collateral }
    error SiloInitialized();
}
library FloorLib { function mark() internal pure returns (uint256) { return uint256(Math.Rounding.Floor); } }
"""


def _write_deposit(root: Path) -> None:
    files = {
        "Silo.sol": DEPOSIT_SILO,
        "Actions.sol": DEPOSIT_ACTIONS,
        "SiloMathLib.sol": DEPOSIT_MATH,
        "ShareToken.sol": DEPOSIT_SHARE,
        "ISiloConfig.sol": DEPOSIT_CONFIG,
        "ISilo.sol": DEPOSIT_SILO_IFACE,
        "ISiloFactory.sol": FACTORY,
        "Clones.sol": CLONES,
    }
    for name, body in files.items():
        (root / name).write_text(
            f"// SPDX-License-Identifier: MIT\npragma solidity 0.8.28;\n{body}\n",
            encoding="utf-8",
        )


def _deposit_property(**overrides: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "property_id": "silo.deposit_accounting",
        "source": "researcher_supplied",
        "kind": "erc4626_deposit_accounting",
        "contract": "Silo",
        "source_file": "Silo.sol",
        "entry_point": "deposit",
        "state_getter": "previewDeposit",
        "deployment": "eip1167_clone",
        "rationale": (
            "On an empty market, previewDeposit and deposit use the same floor conversion, "
            "so minted shares match the preview and balances move by the deposited assets."
        ),
        "locations": [
            {"path": "Silo.sol", "symbol": "deposit"},
            {"path": "Actions.sol", "symbol": "deposit"},
            {"path": "SiloMathLib.sol", "symbol": "_DECIMALS_OFFSET"},
            {"path": "ShareToken.sol", "symbol": "mint"},
        ],
        "imports": {
            "factory_interface": "ISiloFactory.sol",
            "config_interface": "ISiloConfig.sol",
            "error_interface": "ISilo.sol",
            "clones": "Clones.sol",
        },
        "fixture_dependencies": [
            "local_factory",
            "local_silo_config",
            "eip1167_clone",
            "local_asset",
            "zero_interest_model",
        ],
    }
    raw.update(overrides)
    return raw


def test_the_execution_record_keeps_the_property_test_entry() -> None:
    record = _base_record(
        {
            "property_id": "silo.deposit_accounting",
            "kind": "erc4626_deposit_accounting",
            "test_entry_point": "test_deposit_accounting",
        }
    )
    assert record["test_entry_point"] == "test_deposit_accounting"
    assert record["vulnerability_finding"] is False
    assert record["verified"] is False


def test_a_second_deposit_label_decodes_as_a_number() -> None:
    label = b"a0_preview"
    data = "0x" + f"{64:064x}" + f"{1000:064x}" + f"{len(label):064x}" + label.hex().ljust(64, "0")
    observed = _state_observations(json.dumps({"logs": [{"data": data}]}))
    assert observed == [{"label": "a0_preview", "value": "1000"}]


def test_a_round_trip_label_decodes_as_a_number() -> None:
    label = b"t1_remainder"
    data = (
        "0x" + f"{64:064x}" + f"{999004:064x}" + f"{len(label):064x}" + label.hex().ljust(64, "0")
    )
    observed = _state_observations(json.dumps({"logs": [{"data": data}]}))
    assert observed == [{"label": "t1_remainder", "value": "999004"}]


def test_a_sequence_label_decodes_as_a_number() -> None:
    label = b"q00_steps"
    data = "0x" + f"{64:064x}" + f"{6:064x}" + f"{len(label):064x}" + label.hex().ljust(64, "0")
    observed = _state_observations(json.dumps({"logs": [{"data": data}]}))
    assert observed == [{"label": "q00_steps", "value": "6"}]


def test_a_withdrawal_label_decodes_as_a_number() -> None:
    label = b"w0_remainder"
    data = (
        "0x" + f"{64:064x}" + f"{999005:064x}" + f"{len(label):064x}" + label.hex().ljust(64, "0")
    )
    observed = _state_observations(json.dumps({"logs": [{"data": data}]}))
    assert observed == [{"label": "w0_remainder", "value": "999005"}]


def test_a_second_deposit_property_uses_the_funded_market_formula(tmp_path: Path) -> None:
    _write_deposit(tmp_path)
    (tmp_path / "SiloMathLib.sol").write_text(
        "\n".join(
            (
                "// SPDX-License-Identifier: MIT",
                "pragma solidity 0.8.28;",
                "library SiloMathLib {",
                "    uint256 internal constant _DECIMALS_OFFSET = 3;",
                "    uint256 internal constant _DECIMALS_OFFSET_POW = 1000;",
                "    function convertToShares(",
                "        uint256 _assets,",
                "        uint256 _totalAssets,",
                "        uint256 _totalShares",
                "    ) internal pure returns (uint256) {",
                "        if (_totalShares == 0) { _totalAssets = 0; }",
                "        return _assets * (_totalShares + _DECIMALS_OFFSET_POW) / (_totalAssets + 1);",
                "    }",
                "}",
                "library Rounding { uint256 internal constant DEPOSIT_TO_SHARES = 0; }",
                "library Interest {",
                "    function accrue() internal pure {",
                "        uint256 lastTimestamp = 0;",
                "        if (lastTimestamp == 0) return;",
                "    }",
                "}",
                "",
            )
        ),
        encoding="utf-8",
    )
    raw = _deposit_property(
        property_id="silo.deposit_twice_accounting",
        kind="deposit_twice_accounting",
        rationale=(
            "After the market holds assets and shares, the next deposit converts with the "
            "observed totals plus the decimals offset."
        ),
        locations=[
            {"path": "Silo.sol", "symbol": "deposit"},
            {"path": "Actions.sol", "symbol": "deposit"},
            {"path": "SiloMathLib.sol", "symbol": "convertToShares"},
            {"path": "SiloMathLib.sol", "symbol": "_DECIMALS_OFFSET"},
            {"path": "ShareToken.sol", "symbol": "mint"},
        ],
        fixture_dependencies=[
            "local_factory",
            "local_silo_config",
            "eip1167_clone",
            "local_asset",
            "zero_interest_model",
            "second_depositor",
        ],
    )
    accepted = normalize_explicit_properties(tmp_path, (raw,))
    assert accepted[0]["kind"] == "deposit_twice_accounting"
    assert accepted[0]["test_entry_point"] == "test_deposit_twice_accounting"
    assert accepted[0]["vulnerability_finding"] is False
    from app.discovery.bounty.explicit_property import render_second_deposit_harness

    texts = {path.name: path.read_text(encoding="utf-8") for path in tmp_path.glob("*.sol")}
    rendered = render_second_deposit_harness(
        texts,
        contract="Silo",
        source_file="Silo.sol",
        imports=dict(accepted[0]["imports"]),
    )
    assert "contract LocalDepositor" in rendered
    assert "still_empty" in rendered
    assert "formula_mismatch" in rendered
    assert "preview_exceeds_mint" in rendered
    assert "1000000000" not in rendered
    assert "vm." not in rendered
    missing = _deposit_property(
        property_id="silo.deposit_twice_accounting",
        kind="deposit_twice_accounting",
        fixture_dependencies=[
            "local_factory",
            "local_silo_config",
            "eip1167_clone",
            "local_asset",
            "zero_interest_model",
        ],
    )
    with pytest.raises(PropertyConfigError, match="second_depositor"):
        normalize_explicit_properties(tmp_path, (missing,))


def test_a_deposit_property_is_validated_against_the_source(tmp_path: Path) -> None:
    _write_deposit(tmp_path)
    accepted = normalize_explicit_properties(tmp_path, (_deposit_property(),))
    assert accepted[0]["kind"] == "erc4626_deposit_accounting"
    assert accepted[0]["test_entry_point"] == "test_deposit_accounting"
    assert accepted[0]["vulnerability_finding"] is False
    assert accepted[0]["validation"] == "accepted"
    harness = accepted[0]["harness_sha256"]
    assert isinstance(harness, str) and len(harness) == 64
    from app.discovery.bounty.explicit_property import render_deposit_harness

    texts = {path.name: path.read_text(encoding="utf-8") for path in tmp_path.glob("*.sol")}
    rendered = render_deposit_harness(
        texts,
        contract="Silo",
        source_file="Silo.sol",
        imports=dict(accepted[0]["imports"]),
    )
    mock = rendered.split("contract DepositAccountingTest")[0]
    assert "require" not in mock
    assert "SiloInitialized" not in mock
    assert "preview_mismatch" in rendered
    assert "Clones.clone" in rendered
    incomplete = _deposit_property()
    incomplete["fixture_dependencies"] = ["local_factory", "local_silo_config", "eip1167_clone"]
    with pytest.raises(PropertyConfigError, match="local_asset"):
        normalize_explicit_properties(tmp_path, (incomplete,))


def test_a_partial_withdrawal_property_uses_the_ceil_share_formula(tmp_path: Path) -> None:
    _write_withdrawal(tmp_path)
    raw = _deposit_property(
        property_id="silo.partial_withdrawal_accounting",
        kind="partial_withdrawal_accounting",
        entry_point="withdraw",
        state_getter="previewWithdraw",
        rationale=(
            "After minting shares rounds the deposit up, a partial collateral withdrawal "
            "burns the ceil share conversion and transfers the requested assets."
        ),
        locations=[
            {"path": "Silo.sol", "symbol": "withdraw"},
            {"path": "Silo.sol", "symbol": "previewWithdraw"},
            {"path": "Actions.sol", "symbol": "withdraw"},
            {"path": "SiloMathLib.sol", "symbol": "convertToShares"},
            {"path": "ShareToken.sol", "symbol": "burn"},
            {"path": "ISiloConfig.sol", "symbol": "getConfigsForWithdraw"},
        ],
        fixture_dependencies=[
            "local_factory",
            "local_silo_config",
            "eip1167_clone",
            "local_asset",
            "zero_interest_model",
            "second_depositor",
            "partial_withdraw",
        ],
    )
    accepted = normalize_explicit_properties(tmp_path, (raw,))
    assert accepted[0]["kind"] == "partial_withdrawal_accounting"
    assert accepted[0]["test_entry_point"] == "test_partial_withdrawal_accounting"
    assert accepted[0]["test_file"] == "PartialWithdrawalAccounting.t.sol"
    assert accepted[0]["vulnerability_finding"] is False
    assert accepted[0]["source"] == "researcher_supplied"
    from app.discovery.bounty.explicit_property import (
        render_deposit_harness,
        render_partial_withdrawal_harness,
    )

    texts = {path.name: path.read_text(encoding="utf-8") for path in tmp_path.glob("*.sol")}
    imports = dict(accepted[0]["imports"])
    rendered = render_partial_withdrawal_harness(
        texts, contract="Silo", source_file="Silo.sol", imports=imports
    )
    assert "test_partial_withdrawal_accounting" in rendered
    assert "previewWithdraw(uint256)" in rendered
    assert 'keccak256("withdraw(uint256,address,address)")' in rendered
    asset = rendered.split("contract LocalAsset", 1)[1].split("contract LocalInterestRateModel", 1)[
        0
    ]
    assert asset.count("function transfer(") == 1
    assert rendered.count("contract LocalInterestRateModel") == 1
    assert "accrueInterestForBothSilos" in rendered
    assert "0x1544a6db" in rendered
    assert "ratio_exact" in rendered
    assert "preview_short" in rendered
    assert "ERC20InsufficientBalance" in rendered
    assert "vm." not in rendered
    mock = rendered.split("contract LocalWithdrawer")[0]
    assert "require" not in mock
    deposit = render_deposit_harness(
        texts, contract="Silo", source_file="Silo.sol", imports=imports
    )
    assert "function transfer(" not in deposit
    assert "accrueInterestForBothSilos" not in deposit
    missing = dict(raw)
    missing["fixture_dependencies"] = [
        "local_factory",
        "local_silo_config",
        "eip1167_clone",
        "local_asset",
        "zero_interest_model",
        "second_depositor",
    ]
    with pytest.raises(PropertyConfigError, match="partial_withdraw"):
        normalize_explicit_properties(tmp_path, (missing,))


def test_round_trip_and_zero_supply_properties_use_the_pinned_formulas(tmp_path: Path) -> None:
    _write_withdrawal(tmp_path)
    accepted = normalize_explicit_properties(
        tmp_path,
        (
            _flow_property("silo.withdraw_redeposit_roundtrip", "withdraw_redeposit_roundtrip"),
            _flow_property(
                "silo.zero_share_supply_redeposit",
                "zero_share_supply_redeposit",
                entry="redeem",
                getter="previewRedeem",
                fixture="zero_share_supply",
            ),
        ),
    )
    assert accepted[0]["test_entry_point"] == "test_withdraw_redeposit_roundtrip"
    assert accepted[1]["test_entry_point"] == "test_zero_share_supply_redeposit"
    assert accepted[0]["vulnerability_finding"] is False
    assert accepted[0]["sequence_generation"] is None
    from app.discovery.bounty.explicit_property import render_round_trip_harness

    texts = {path.name: path.read_text(encoding="utf-8") for path in tmp_path.glob("*.sol")}
    rendered = render_round_trip_harness(
        texts,
        contract="Silo",
        source_file="Silo.sol",
        imports=dict(accepted[0]["imports"]),
    )
    assert "test_withdraw_redeposit_roundtrip" in rendered
    assert "previewRedeem(uint256)" in rendered
    assert "999004" not in rendered
    assert "vm." not in rendered
    mock = rendered.split("contract LocalActor")[0]
    assert "require" not in mock
    missing = _flow_property("silo.withdraw_redeposit_roundtrip", "withdraw_redeposit_roundtrip")
    missing["fixture_dependencies"] = [
        item for item in missing["fixture_dependencies"] if item != "round_trip"
    ]
    with pytest.raises(PropertyConfigError, match="round_trip"):
        normalize_explicit_properties(tmp_path, (missing,))


def _flow_property(
    property_id: str,
    kind: str,
    *,
    entry: str = "withdraw",
    getter: str = "previewWithdraw",
    fixture: str = "round_trip",
) -> dict[str, object]:
    raw = _deposit_property(
        property_id=property_id,
        kind=kind,
        entry_point=entry,
        state_getter=getter,
        rationale=(
            "Collateral deposit, mint, withdraw, and redeem round in the directions declared "
            "by the pinned Silo source, including a zero share supply."
        ),
        locations=[
            {"path": "Silo.sol", "symbol": "withdraw"},
            {"path": "Silo.sol", "symbol": "previewWithdraw"},
            {"path": "Actions.sol", "symbol": "withdraw"},
            {"path": "SiloMathLib.sol", "symbol": "convertToShares"},
            {"path": "ShareToken.sol", "symbol": "burn"},
            {"path": "ISiloConfig.sol", "symbol": "getConfigsForWithdraw"},
        ],
        fixture_dependencies=[
            "local_factory",
            "local_silo_config",
            "eip1167_clone",
            "local_asset",
            "zero_interest_model",
            "second_depositor",
            "partial_withdraw",
            fixture,
        ],
    )
    return raw


def _write_withdrawal(root: Path) -> None:
    _write_deposit(root)
    (root / "Silo.sol").write_text(
        "\n".join(
            (
                "// SPDX-License-Identifier: MIT",
                "pragma solidity 0.8.28;",
                'import {ISiloFactory} from "./ISiloFactory.sol";',
                'import {ISiloConfig} from "./ISiloConfig.sol";',
                'import {ISilo} from "./ISilo.sol";',
                'import {Actions} from "./Actions.sol";',
                'import {ShareToken} from "./ShareToken.sol";',
                "contract Silo is ShareToken {",
                "    constructor(ISiloFactory) {}",
                "    function initialize(ISiloConfig _config) external { Actions.initialize(_config); }",
                "    function deposit(uint256 _assets, address _receiver) external returns (uint256 shares) {",
                "        (, shares) = _deposit(_assets, _receiver);",
                "    }",
                "    function previewDeposit(uint256 _assets) external view returns (uint256 shares) {",
                "        shares = _assets;",
                "    }",
                "    function _deposit(uint256 _assets, address) internal returns (uint256, uint256) {",
                "        return Actions.deposit(_assets);",
                "    }",
                "    function mint(uint256 _shares, address _receiver) external returns (uint256 assets) {",
                "        (assets,) = _deposit(0, _receiver);",
                "    }",
                "    function previewMint(uint256 _shares) external pure returns (uint256) { return _shares; }",
                "    function previewRedeem(uint256 _shares) external pure returns (uint256) { return _shares; }",
                "    function redeem(uint256 _shares, address _receiver, address _owner)",
                "        external returns (uint256 assets)",
                "    {",
                "        (assets,) = _withdraw(_shares, _owner, ISilo.CollateralType.Collateral);",
                "    }",
                "    function previewWithdraw(uint256 _assets) external view returns (uint256 shares) {",
                "        return _previewWithdraw(_assets);",
                "    }",
                "    function _previewWithdraw(uint256) internal pure returns (uint256) {",
                "        return uint256(Rounding.WITHDRAW_TO_SHARES);",
                "    }",
                "    function withdraw(uint256 _assets, address _receiver, address _owner)",
                "        external returns (uint256 shares)",
                "    {",
                "        (, shares) = _withdraw(_assets, _owner, ISilo.CollateralType.Collateral);",
                "    }",
                "    function withdraw(uint256 _assets, address, address _owner, uint8 kind)",
                "        external returns (uint256 shares)",
                "    {",
                "        (, shares) = _withdraw(_assets, _owner, kind);",
                "    }",
                "    function _withdraw(uint256 _assets, address, ISilo.CollateralType)",
                "        internal returns (uint256, uint256)",
                "    {",
                "        return Actions.withdraw(_assets);",
                "    }",
                "    function _withdraw(uint256 _assets, address, uint8) internal returns (uint256, uint256) {",
                "        return Actions.withdraw(_assets);",
                "    }",
                "    function config() external view returns (ISiloConfig) { return ISiloConfig(siloConfig()); }",
                "    function siloConfig() internal view returns (address) { return address(0); }",
                "}",
                "",
            )
        ),
        encoding="utf-8",
    )
    (root / "Actions.sol").write_text(
        "\n".join(
            (
                "// SPDX-License-Identifier: MIT",
                "pragma solidity 0.8.28;",
                "library Actions {",
                "    function initialize(address) internal {}",
                "    function deposit(uint256 _assets) internal returns (uint256, uint256) {",
                "        accrueInterestForSilo(address(0));",
                "        getCollateralShareTokenAndAsset(address(0), 1);",
                "        SiloERC4626Lib.deposit(_assets);",
                "        return (_assets, _assets);",
                "    }",
                "    function withdraw(uint256 _assets) internal returns (uint256, uint256) {",
                "        accrueInterestForBothSilos();",
                "        getConfigsForWithdraw(address(this), address(0));",
                "        SiloERC4626Lib.withdraw(_assets);",
                "        if (depositConfig.silo == collateralConfig.silo) { return (_assets, _assets); }",
                "        return (_assets, _assets);",
                "    }",
                "}",
                "library SiloERC4626Lib {",
                "    function withdraw(uint256) internal {",
                "        token.burn(owner, spender, shares);",
                "        token.safeTransfer(receiver, assets);",
                "    }",
                "}",
                "",
            )
        ),
        encoding="utf-8",
    )
    (root / "SiloMathLib.sol").write_text(
        "\n".join(
            (
                "// SPDX-License-Identifier: MIT",
                "pragma solidity 0.8.28;",
                "library SiloMathLib {",
                "    uint256 internal constant _DECIMALS_OFFSET = 3;",
                "    uint256 internal constant _DECIMALS_OFFSET_POW = 1000;",
                "    function convertToShares(uint256 _assets, uint256 _totalAssets, uint256 _totalShares)",
                "        internal pure returns (uint256)",
                "    {",
                "        if (_totalShares == 0) { _totalAssets = 0; }",
                "        return _assets * (_totalShares + _DECIMALS_OFFSET_POW) / (_totalAssets + 1);",
                "    }",
                "    function convertToAssets(uint256 _shares, uint256 _totalAssets, uint256 _totalShares)",
                "        internal pure returns (uint256)",
                "    {",
                "        return convertToShares(_shares, _totalAssets, _totalShares);",
                "    }",
                "    function convertToAssetsOrToShares(uint256, uint256) internal pure returns (uint256, uint256) {",
                "        return (0, 0);",
                "    }",
                "}",
                "library Rounding {",
                "    uint256 internal constant DEPOSIT_TO_SHARES = 0;",
                "    Math.Rounding internal constant WITHDRAW_TO_SHARES = Math.Rounding.Ceil;",
                "    Math.Rounding internal constant WITHDRAW_TO_ASSETS = Math.Rounding.Floor;",
                "    Math.Rounding internal constant DEPOSIT_TO_ASSETS = Math.Rounding.Ceil;",
                "    Math.Rounding internal constant DEPOSIT_TO_SHARES = Math.Rounding.Floor;",
                "}",
                "library Interest {",
                "    function accrue() internal pure {",
                "        uint256 lastTimestamp = 0;",
                "        if (lastTimestamp == 0) return;",
                "    }",
                "}",
                "",
            )
        ),
        encoding="utf-8",
    )
    (root / "ShareToken.sol").write_text(
        "\n".join(
            (
                "// SPDX-License-Identifier: MIT",
                "pragma solidity 0.8.28;",
                "contract ShareToken {",
                "    function _disableInitializers() internal {}",
                "    constructor() { _disableInitializers(); }",
                "    function mint(address _owner, address, uint256) external {}",
                "    function burn(address _owner, address, uint256) external {}",
                "}",
                "",
            )
        ),
        encoding="utf-8",
    )
    fields = "\n".join(
        f"        {type_name} {name};"
        for type_name, name in (
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
    )
    deposit_fields = "\n".join(
        (
            "        address silo;",
            "        address token;",
            "        address collateralShareToken;",
            "        address protectedShareToken;",
            "        uint256 daoFee;",
            "        uint256 deployerFee;",
            "        address interestRateModel;",
        )
    )
    (root / "ISiloConfig.sol").write_text(
        "\n".join(
            (
                "// SPDX-License-Identifier: MIT",
                "pragma solidity 0.8.28;",
                "interface ISiloConfig {",
                "    struct ConfigData {",
                fields,
                "    }",
                "    struct DepositConfig {",
                deposit_fields,
                "    }",
                "    function getConfig(address) external view returns (ConfigData memory);",
                "    function getConfigsForWithdraw(address, address) external view returns (",
                "        DepositConfig memory, ConfigData memory, ConfigData memory",
                "    );",
                "}",
                "",
            )
        ),
        encoding="utf-8",
    )


def _scoped_manifest():
    base = manifest()
    data = base.to_dict()
    data["in_scope"] = [
        {"kind": "contract", "identifier": "Silo"},
        {"kind": "path", "identifier": "Silo.sol"},
    ]
    data["compiler"] = {
        "version": "0.8.28",
        "optimizer": "enabled",
        "optimizer_runs": "200",
        "via_ir": "false",
        "evm_version": "cancun",
    }
    data["testing_mode"] = "local_only"
    data["fork"] = None
    from app.discovery.bounty.campaign import BountyManifest

    return BountyManifest.from_dict(data)
