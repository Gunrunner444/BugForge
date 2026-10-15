"""Positive and negative controls for the floor-share burn detector.

The campaign path is ``analyze_campaign``. The static path is
``SecurityAnalysisEngine``. A passing control is a candidate, not a finding.
"""

from __future__ import annotations

from pathlib import Path

from app.discovery.bounty.analysis import analyze_campaign
from app.discovery.bounty.campaign import BountyManifest
from app.discovery.bounty.source_selection import select_named
from app.parsing.solidity_research_suite import analyze_sources
from app.security.engine import SecurityAnalysisEngine

_INTERFACE = """
pragma solidity ^0.8.20;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
library Math {
    enum Rounding { Floor, Ceil, Up, Down }
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256) {
        return x * y / denominator;
    }
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding) internal pure returns (uint256) {
        return x * y / denominator;
    }
}
"""

_FLOOR = (
    _INTERFACE
    + """
contract FloorMulDiv {
    using Math for uint256;
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    function withdraw(uint256 assets) external {
        uint256 burned = assets.mulDiv(totalShares, totalAssets, Math.Rounding.Floor);
        balances[msg.sender] -= burned;
        totalShares -= burned;
        totalAssets -= assets;
        require(asset.transfer(msg.sender, assets), "transfer");
    }
}

contract StaticMulDiv {
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    function withdraw(uint256 assets) external {
        uint256 burned = Math.mulDiv(assets, totalShares, totalAssets);
        balances[msg.sender] -= burned;
        totalShares -= burned;
        totalAssets -= assets;
        require(asset.transfer(msg.sender, assets), "transfer");
    }
}
"""
)

_SAFE = (
    _INTERFACE
    + """
contract CeilMulDiv {
    using Math for uint256;
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    function withdraw(uint256 assets) external {
        uint256 burned = assets.mulDiv(totalShares, totalAssets, Math.Rounding.Ceil);
        balances[msg.sender] -= burned;
        totalShares -= burned;
        totalAssets -= assets;
        require(asset.transfer(msg.sender, assets), "transfer");
    }
}

contract VariableRounding {
    using Math for uint256;
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    function withdraw(uint256 assets, Math.Rounding rounding) external {
        uint256 burned = assets.mulDiv(totalShares, totalAssets, rounding);
        balances[msg.sender] -= burned;
        totalShares -= burned;
        totalAssets -= assets;
        require(asset.transfer(msg.sender, assets), "transfer");
    }
}

contract FloorDeposit {
    using Math for uint256;
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    function deposit(uint256 assets) external {
        uint256 minted = assets.mulDiv(totalShares, totalAssets, Math.Rounding.Floor);
        balances[msg.sender] += minted;
        totalShares += minted;
        totalAssets += assets;
        asset.transferFrom(msg.sender, address(this), assets);
    }
}

contract SplitWithdraw {
    using Math for uint256;
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    function withdraw(uint256 assets) external {
        uint256 burned = _shares(assets);
        balances[msg.sender] -= burned;
        require(asset.transfer(msg.sender, assets), "transfer");
    }

    function _shares(uint256 assets) internal view returns (uint256) {
        return assets.mulDiv(totalShares, totalAssets, Math.Rounding.Floor);
    }
}
"""
)

_DETECTOR = "arithmetic.rounding_burn_floor"


def _where(sources: dict[str, str]) -> set[tuple[str, str]]:
    result = analyze_sources(sources, ("arithmetic",))
    return {
        (item.contract, item.function.split("(")[0])
        for item in result.candidates
        if item.detector == _DETECTOR
    }


def test_floor_muldiv_is_reported_and_safe_rounding_is_not() -> None:
    found = _where({"floor.sol": _FLOOR, "safe.sol": _SAFE})
    assert found == {("FloorMulDiv", "withdraw"), ("StaticMulDiv", "withdraw")}
    forms = {
        item.fact("conversion")
        for item in analyze_sources({"floor.sol": _FLOOR}, ("arithmetic",)).candidates
        if item.detector == _DETECTOR
    }
    assert forms == {"muldiv_floor"}


def test_security_engine_emits_the_floor_candidate_only_for_the_vulnerable_file(
    tmp_path: Path,
) -> None:
    vulnerable = tmp_path / "floor.sol"
    safe = tmp_path / "safe.sol"
    vulnerable.write_text(_FLOOR, encoding="utf-8")
    safe.write_text(_SAFE, encoding="utf-8")
    engine = SecurityAnalysisEngine()
    bad = engine.analyze_repository(tmp_path, [vulnerable])
    good = engine.analyze_repository(tmp_path, [safe])
    assert _engine_hits(bad) == {("FloorMulDiv", "withdraw"), ("StaticMulDiv", "withdraw")}
    assert _engine_hits(good) == set()


def test_campaign_analysis_keeps_a_target_hit_and_skips_its_sequence(tmp_path: Path) -> None:
    path = tmp_path / "FloorMulDiv.sol"
    path.write_text("pragma solidity ^0.8.20;\n" + _FLOOR, encoding="utf-8")
    analysis = _campaign(tmp_path, ("FloorMulDiv.sol",))
    hits = [
        item
        for item in analysis.candidates
        if item.detector == _DETECTOR and item.file == "FloorMulDiv.sol"
    ]
    assert {item.contract for item in hits} == {"FloorMulDiv", "StaticMulDiv"}
    assert hits
    assert all(seq.derived_from.split("@", 1)[0] != _DETECTOR for seq in analysis.sequences)
    skipped = [
        reason
        for key, reason in analysis.sequence_skipped.items()
        if key.startswith(_DETECTOR + "@")
    ]
    assert skipped
    assert all(reason == "no sequence template applies to this detector" for reason in skipped)


def test_campaign_analysis_drops_a_floor_burn_that_lives_only_in_a_dependency(
    tmp_path: Path,
) -> None:
    library = tmp_path / "lib" / "BurnLib.sol"
    library.parent.mkdir()
    library.write_text(
        _INTERFACE
        + """
contract BurnLib {
    using Math for uint256;
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;
    function withdraw(uint256 assets) external {
        uint256 burned = assets.mulDiv(totalShares, totalAssets, Math.Rounding.Floor);
        balances[msg.sender] -= burned;
        totalAssets -= assets;
        require(asset.transfer(msg.sender, assets), "transfer");
    }
}
""",
        encoding="utf-8",
    )
    target = tmp_path / "Wrapper.sol"
    target.write_text(
        """
pragma solidity ^0.8.20;
import "./lib/BurnLib.sol";
contract Wrapper {
    function ping() external pure returns (uint256) { return 1; }
}
""",
        encoding="utf-8",
    )
    direct = analyze_sources(
        {"lib/BurnLib.sol": library.read_text(encoding="utf-8")}, ("arithmetic",)
    )
    assert any(item.detector == _DETECTOR for item in direct.candidates)
    analysis = _campaign(tmp_path, ("Wrapper.sol",))
    assert all(item.file == "Wrapper.sol" for item in analysis.candidates)
    assert not any(item.detector == _DETECTOR for item in analysis.candidates)


def _campaign(tmp_path: Path, files: tuple[str, ...]):
    manifest = BountyManifest.from_dict(
        {
            "platform": "immunefi",
            "program_id": "detector-control",
            "testing_mode": "local_only",
            "poc_requirement": "required",
            "source_commit": "local",
            "repository": "https://example.test/detector-control",
            "compiler": {
                "version": "0.8.28",
                "optimizer": "enabled",
                "optimizer_runs": "200",
                "via_ir": "false",
                "evm_version": "cancun",
            },
            "in_scope": [{"kind": "path", "identifier": files[0]}],
        }
    )
    selection = select_named(tmp_path, files)
    return analyze_campaign(
        manifest=manifest,
        identity=manifest.to_campaign_identity(
            campaign_id="cp_detector_control",
            source_file=files[0],
            repository_root=str(tmp_path),
        ),
        repo_root=tmp_path,
        files=selection.selected,
        selection=selection,
    )


def _engine_hits(result) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for item in result.observations:
        if item.metadata.get("detector") != _DETECTOR:
            continue
        function = str(item.metadata.get("function", "")).split("(")[0]
        found.add((str(item.metadata.get("contract", "")), function))
    return found
