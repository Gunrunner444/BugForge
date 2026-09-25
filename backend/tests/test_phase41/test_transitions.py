"""Phase 41 state transitions and Phase 40 property regressions."""

from __future__ import annotations

from pathlib import Path

from app.parsing.engine import parse_source, reset_syntax_registry
from app.parsing.solidity_cross_dataflow import (
    analyze_asset_flow,
    analyze_reentrancy,
    graph_edges_are_connected,
)
from app.parsing.solidity_dataflow import analyze_dataflow
from app.parsing.solidity_ir import build_semantic_program
from app.parsing.solidity_state_transitions import find_candidate_exploit_paths
from app.plugins import reset_plugin_catalog

FALSE_NEGATIVES = (
    {
        "phase": "41",
        "vulnerability_class": "reentrancy",
        "fixture": "read-local-call-write",
        "expected_semantic_path": "state read -> local -> call -> state write",
        "previous_miss": "same variable name before and after a call",
        "corrected_behavior": "requires a dependency edge",
    },
)


def _program(tmp_path: Path, source: str):
    reset_syntax_registry()
    reset_plugin_catalog()
    return build_semantic_program(parse_source("solidity", tmp_path / "C.sol", source))


def test_reentrancy_requires_a_dependency_not_a_shared_name(tmp_path: Path) -> None:
    dependent = """
    pragma solidity ^0.8.20;
    contract Vault {
        uint256 totalAssets;
        function withdraw() external {
            uint256 owed = totalAssets;
            msg.sender.call("");
            totalAssets = owed;
        }
    }
    """
    independent = """
    pragma solidity ^0.8.20;
    contract Vault {
        uint256 totalAssets;
        uint256 other;
        function withdraw() external {
            uint256 owed = totalAssets;
            msg.sender.call("");
            other = 1;
        }
    }
    """
    assert analyze_reentrancy(_program(tmp_path, dependent), "withdraw").status == "potential"
    assert analyze_reentrancy(_program(tmp_path, independent), "withdraw").status == "unknown"


def test_state_load_reaches_a_later_store(tmp_path: Path) -> None:
    source = """
    pragma solidity ^0.8.20;
    contract Vault {
        mapping(address => uint256) balances;
        uint256 totalAssets;
        function run(address user) external {
            uint256 amount = balances[user];
            uint256 fee = amount / 10;
            uint256 payout = amount - fee;
            totalAssets = payout;
        }
    }
    """
    flow = analyze_dataflow(_program(tmp_path, source))
    assert graph_edges_are_connected(flow)
    summary = flow._summary("run")
    assert summary is not None
    assert any(edge.kind == "local-dependency" for edge in summary.edges)
    assert any(edge.kind == "local-to-state" for edge in summary.edges)


def test_asset_flow_is_not_a_violation(tmp_path: Path) -> None:
    source = """
    pragma solidity ^0.8.20;
    contract Vault {
        function pay(address user, uint256 amount) external {
            user.call{value: amount}("");
        }
    }
    """
    result = analyze_asset_flow(_program(tmp_path, source), "pay")
    assert result.status == "unknown"


def test_candidate_path_is_not_reproduced(tmp_path: Path) -> None:
    source = """
    pragma solidity ^0.8.20;
    contract Vault {
        uint256 totalAssets;
        function withdraw() external {
            uint256 owed = totalAssets;
            msg.sender.call("");
            totalAssets = owed;
        }
    }
    """
    paths = find_candidate_exploit_paths(_program(tmp_path, source))
    assert paths
    assert {item.status for item in paths} == {"candidate"}
    assert "reproduced" not in {item.status for item in paths}


def test_false_negative_registry() -> None:
    assert FALSE_NEGATIVES[0]["corrected_behavior"]
