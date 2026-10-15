"""Controls for floor-share burn detection.

``SplitWithdraw`` used to be grouped with the safe fixtures. That expectation was
wrong: the floor conversion lives in ``_shares``, and ``withdraw`` burns the
result while transferring the requested assets. The helper case is a positive
control. A matching helper that rounds up, a rounding variable, a floor deposit,
and an unreachable helper are not floor-burn candidates.

A candidate is a detection result, not a confirmed vulnerability.
"""

from __future__ import annotations

from pathlib import Path

from app.discovery.bounty.analysis import analyze_campaign
from app.discovery.bounty.campaign import BountyManifest
from app.discovery.bounty.source_selection import select_named
from app.parsing.solidity_arithmetic import connected_rounding_payouts
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

_POSITIVE = (
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

contract Scope {
    using Math for uint256;
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    function withdraw(uint256 assets) external {
        require(asset.transfer(msg.sender, assets), "transfer");
    }

    function drain(uint256 assets) external {
        _hidden(assets);
    }

    function _hidden(uint256 assets) internal {
        uint256 burned = assets.mulDiv(totalShares, totalAssets, Math.Rounding.Floor);
        balances[msg.sender] -= burned;
        require(asset.transfer(msg.sender, assets), "transfer");
    }
}
"""
)

_NEGATIVE = (
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

contract CeilHelper {
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
        return assets.mulDiv(totalShares, totalAssets, Math.Rounding.Up);
    }
}

library CeilMath {
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256) {
        return (x * y + denominator - 1) / denominator;
    }
}

contract CeilBody {
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    function withdraw(uint256 assets) external {
        uint256 burned = CeilMath.mulDiv(assets, totalShares, totalAssets);
        balances[msg.sender] -= burned;
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
"""
)

_UNRESOLVED = (
    _INTERFACE
    + """
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

interface IMath {
    function mulDiv(uint256 x, uint256 y, uint256 denominator) external pure returns (uint256);
}

contract UnknownMulDiv {
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    function withdraw(uint256 assets) external {
        uint256 burned = IMath.mulDiv(assets, totalShares, totalAssets);
        balances[msg.sender] -= burned;
        require(asset.transfer(msg.sender, assets), "transfer");
    }
}

contract VariableHelper {
    using Math for uint256;
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    function withdraw(uint256 assets, Math.Rounding rounding) external {
        uint256 burned = _shares(assets, rounding);
        balances[msg.sender] -= burned;
        require(asset.transfer(msg.sender, assets), "transfer");
    }

    function _shares(uint256 assets, Math.Rounding rounding) internal view returns (uint256) {
        return assets.mulDiv(totalShares, totalAssets, rounding);
    }
}
"""
)

_CONSTANT = (
    _INTERFACE
    + """
library Round {
    Math.Rounding internal constant TO_SHARES_CEIL = Math.Rounding.Ceil;
    Math.Rounding internal constant TO_SHARES_FLOOR = Math.Rounding.Floor;
}
library Conv {
    using Math for uint256;
    function shares(
        uint256 assets,
        uint256 totalShares,
        uint256 totalAssets,
        Math.Rounding rounding
    ) internal pure returns (uint256) {
        return assets.mulDiv(totalShares, totalAssets, rounding);
    }
}
contract CeilPass {
    using Math for uint256;
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    function withdraw(uint256 assets) external {
        _go({assets: assets});
    }

    function _go(uint256 assets) internal {
        uint256 burned = Conv.shares(assets, totalShares, totalAssets, Round.TO_SHARES_CEIL);
        balances[msg.sender] -= burned;
        require(asset.transfer(msg.sender, assets), "transfer");
    }
}
contract FloorPass {
    using Math for uint256;
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    function withdraw(uint256 assets) external {
        uint256 burned = Conv.shares(assets, totalShares, totalAssets, Round.TO_SHARES_FLOOR);
        balances[msg.sender] -= burned;
        require(asset.transfer(msg.sender, assets), "transfer");
    }
}
"""
)

_FLOOR = "arithmetic.rounding_burn_floor"
_UNKNOWN = "arithmetic.rounding_direction_unresolved"


def _hits(sources: dict[str, str], detector: str) -> set[tuple[str, str]]:
    result = analyze_sources(sources, ("arithmetic",))
    return {
        (item.contract, item.function.split("(")[0])
        for item in result.candidates
        if item.detector == detector
    }


def _candidates(sources: dict[str, str], detector: str):
    return [
        item
        for item in analyze_sources(sources, ("arithmetic",)).candidates
        if item.detector == detector
    ]


def test_direct_floor_and_three_argument_muldiv_are_candidates() -> None:
    found = _hits({"positive.sol": _POSITIVE}, _FLOOR)
    assert ("FloorMulDiv", "withdraw") in found
    assert ("StaticMulDiv", "withdraw") in found
    forms = {item.fact("conversion") for item in _candidates({"positive.sol": _POSITIVE}, _FLOOR)}
    assert "muldiv_floor" in forms
    assert _hits({"positive.sol": _POSITIVE}, _UNKNOWN) == set()


def test_floor_helper_is_attributed_to_the_public_withdraw_with_its_path() -> None:
    found = _candidates({"positive.sol": _POSITIVE}, _FLOOR)
    split = [item for item in found if item.contract == "SplitWithdraw"]
    assert [item.function.split("(")[0] for item in split] == ["withdraw"]
    path = split[0].fact("helper_path")
    assert "SplitWithdraw.withdraw" in path
    assert "SplitWithdraw._shares" in path
    assert path.index("withdraw") < path.index("_shares")
    assert split[0].fact("assets_parameter") == "assets"
    assert split[0].fact("rounding") == "floor"
    assert not any(item.function.startswith("_shares") for item in found)


def test_unreachable_helper_is_not_attributed_to_withdraw_but_drain_is() -> None:
    found = _hits({"positive.sol": _POSITIVE}, _FLOOR)
    assert ("Scope", "drain") in found
    assert ("Scope", "withdraw") not in found
    assert ("Scope", "_hidden") not in found
    drain = next(
        item
        for item in _candidates({"positive.sol": _POSITIVE}, _FLOOR)
        if item.contract == "Scope"
    )
    assert "Scope._hidden" in drain.fact("helper_path")
    assert "Scope.withdraw" not in drain.fact("helper_path")


def test_ceiling_custom_muldiv_and_deposit_are_not_floor_candidates() -> None:
    sources = {"negative.sol": _NEGATIVE}
    assert _hits(sources, _FLOOR) == set()
    assert _hits(sources, _UNKNOWN) == set()


def test_variable_and_unknown_muldiv_are_unresolved_not_floor() -> None:
    sources = {"unresolved.sol": _UNRESOLVED}
    assert _hits(sources, _FLOOR) == set()
    assert _hits(sources, _UNKNOWN) == {
        ("VariableRounding", "withdraw"),
        ("UnknownMulDiv", "withdraw"),
        ("VariableHelper", "withdraw"),
    }
    helper = next(
        item for item in _candidates(sources, _UNKNOWN) if item.contract == "VariableHelper"
    )
    assert "VariableHelper._shares" in helper.fact("helper_path")
    assert helper.fact("rounding") == "unknown"


def test_rounding_constant_is_resolved_through_the_helper_chain() -> None:
    sources = {"constant.sol": _CONSTANT}
    assert ("CeilPass", "withdraw") not in _hits(sources, _FLOOR)
    assert ("CeilPass", "withdraw") not in _hits(sources, _UNKNOWN)
    floor = [item for item in _candidates(sources, _FLOOR) if item.contract == "FloorPass"]
    assert [item.function.split("(")[0] for item in floor] == ["withdraw"]
    assert "Conv.shares" in floor[0].fact("helper_path")
    result = analyze_sources(sources, ("arithmetic",))
    ceil = [
        item
        for item in connected_rounding_payouts(result.model)
        if item.contract == "CeilPass" and item.function.startswith("withdraw")
    ]
    assert ceil
    assert {item.direction for item in ceil} == {"ceil"}
    assert "Conv.shares" in ceil[0].helper_path
    assert "CeilPass._go" in ceil[0].helper_path
    assert "Round." not in ceil[0].helper_path


def test_security_engine_separates_floor_ceiling_and_unresolved(tmp_path: Path) -> None:
    positive = tmp_path / "positive.sol"
    negative = tmp_path / "negative.sol"
    unresolved = tmp_path / "unresolved.sol"
    positive.write_text(_POSITIVE, encoding="utf-8")
    negative.write_text(_NEGATIVE, encoding="utf-8")
    unresolved.write_text(_UNRESOLVED, encoding="utf-8")
    engine = SecurityAnalysisEngine()
    bad = engine.analyze_repository(tmp_path, [positive])
    good = engine.analyze_repository(tmp_path, [negative])
    open_case = engine.analyze_repository(tmp_path, [unresolved])
    assert _engine_hits(bad, _FLOOR) == {
        ("FloorMulDiv", "withdraw"),
        ("StaticMulDiv", "withdraw"),
        ("SplitWithdraw", "withdraw"),
        ("Scope", "drain"),
    }
    assert _engine_hits(bad, _UNKNOWN) == set()
    assert _engine_hits(good, _FLOOR) == set()
    assert _engine_hits(good, _UNKNOWN) == set()
    assert _engine_hits(open_case, _FLOOR) == set()
    assert ("VariableRounding", "withdraw") in _engine_hits(open_case, _UNKNOWN)
    assert ("UnknownMulDiv", "withdraw") in _engine_hits(open_case, _UNKNOWN)


def test_campaign_keeps_a_target_helper_hit_and_skips_its_sequence(tmp_path: Path) -> None:
    path = tmp_path / "FloorMulDiv.sol"
    path.write_text(_POSITIVE, encoding="utf-8")
    analysis = _campaign(tmp_path, ("FloorMulDiv.sol",))
    hits = [item for item in analysis.candidates if item.detector == _FLOOR]
    assert {item.contract for item in hits} == {
        "FloorMulDiv",
        "StaticMulDiv",
        "SplitWithdraw",
        "Scope",
    }
    assert all(item.file == "FloorMulDiv.sol" for item in hits)
    split = next(item for item in hits if item.contract == "SplitWithdraw")
    assert "SplitWithdraw._shares" in split.fact("helper_path")
    assert all(seq.derived_from.split("@", 1)[0] != _FLOOR for seq in analysis.sequences)
    skipped = [
        reason for key, reason in analysis.sequence_skipped.items() if key.startswith(_FLOOR + "@")
    ]
    assert skipped
    assert all(reason == "no sequence template applies to this detector" for reason in skipped)


def test_campaign_attributes_an_imported_helper_to_the_selected_target(tmp_path: Path) -> None:
    library = tmp_path / "lib" / "FloorLib.sol"
    library.parent.mkdir()
    library.write_text(
        _INTERFACE
        + """
library FloorLib {
    using Math for uint256;
    function shares(uint256 assets, uint256 totalShares, uint256 totalAssets) internal pure returns (uint256) {
        return assets.mulDiv(totalShares, totalAssets, Math.Rounding.Floor);
    }
}
""",
        encoding="utf-8",
    )
    target = tmp_path / "Target.sol"
    target.write_text(
        """
pragma solidity ^0.8.20;
import "./lib/FloorLib.sol";
interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }
contract Target {
    IERC20 public asset;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;
    function withdraw(uint256 assets) external {
        uint256 burned = FloorLib.shares(assets, totalShares, totalAssets);
        balances[msg.sender] -= burned;
        require(asset.transfer(msg.sender, assets), "transfer");
    }
    function ping() external pure returns (uint256) { return 1; }
}
""",
        encoding="utf-8",
    )
    analysis = _campaign(tmp_path, ("Target.sol",))
    hits = [item for item in analysis.candidates if item.detector == _FLOOR]
    assert len(hits) == 1
    assert hits[0].file == "Target.sol"
    assert hits[0].contract == "Target"
    assert hits[0].function.startswith("withdraw")
    assert "FloorLib.shares" in hits[0].fact("helper_path")
    assert "Target.withdraw" in hits[0].fact("helper_path")


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
    assert any(item.detector == _FLOOR for item in direct.candidates)
    analysis = _campaign(tmp_path, ("Wrapper.sol",))
    assert all(item.file == "Wrapper.sol" for item in analysis.candidates)
    assert not any(item.detector == _FLOOR for item in analysis.candidates)


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


def _engine_hits(result, detector: str) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for item in result.observations:
        if item.metadata.get("detector") != detector:
            continue
        function = str(item.metadata.get("function", "")).split("(")[0]
        found.add((str(item.metadata.get("contract", "")), function))
    return found
