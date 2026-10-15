"""Researcher-supplied properties execute without becoming detector candidates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.discovery.bounty.explicit_property import (
    PropertyConfigError,
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


def test_forge_results_stay_distinct_from_a_passing_property() -> None:
    held = classify_explicit_result(
        process_status="completed",
        compiler_status="ok",
        return_code=0,
        stdout="Suite result: ok",
        stderr="",
    )
    assert held["outcome"] == "property_held"
    assert held["property_status"] == "held"
    violated = classify_explicit_result(
        process_status="completed",
        compiler_status="ok",
        return_code=1,
        stdout="BugForgeProperty(second_initialize_succeeded)",
        stderr="",
    )
    assert violated["outcome"] == "property_violated"
    fixture = classify_explicit_result(
        process_status="completed",
        compiler_status="ok",
        return_code=1,
        stdout="BugForgeFixture",
        stderr="",
    )
    assert fixture["outcome"] == "inconclusive"
    assert fixture["property_status"] == "not_evaluated"
    compiled = classify_explicit_result(
        process_status="completed",
        compiler_status="failed",
        return_code=1,
        stdout="",
        stderr="Compiler run failed",
    )
    assert compiled["outcome"] == "compile_failed"
    assert compiled["test_status"] == "not_run"
    assert compiled["property_status"] == "not_run"
    timed = classify_explicit_result(
        process_status="timeout",
        compiler_status="ok",
        return_code=None,
        stdout="",
        stderr="",
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
