"""Custody facts survive a direct body, an internal helper, and an imported library."""

from __future__ import annotations

from app.parsing.solidity_conservation import custody_pairs
from app.parsing.solidity_research import build_research_model

_ERC20 = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""


def test_an_imported_library_keeps_the_same_custody_facts_as_the_direct_body() -> None:
    direct = (
        _ERC20
        + """
contract Desk {
    IERC20 public immutable token;
    mapping(address => uint256) public credit;
    constructor(IERC20 token_) { token = token_; }
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        credit[msg.sender] += amount;
    }
    function withdraw(uint256 amount) external {
        require(credit[msg.sender] >= amount);
        credit[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""
    )
    helper = (
        _ERC20
        + """
contract Desk {
    IERC20 public immutable token;
    mapping(address => uint256) public credit;
    constructor(IERC20 token_) { token = token_; }
    function deposit(uint256 amount) external { _deposit(amount); }
    function withdraw(uint256 amount) external { _withdraw(amount); }
    function _deposit(uint256 amount) internal {
        token.transferFrom(msg.sender, address(this), amount);
        credit[msg.sender] += amount;
    }
    function _withdraw(uint256 amount) internal {
        require(credit[msg.sender] >= amount);
        credit[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""
    )
    library = """
pragma solidity ^0.8.20;
import "./token_iface.sol";
library Mover {
    function pull(IERC20 token, address from, uint256 amount) internal {
        require(token.transferFrom(from, address(this), amount));
    }
    function push(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount));
    }
}
"""
    vault = """
pragma solidity ^0.8.20;
import "./token_iface.sol";
import "./mover.sol";
contract Desk {
    using Mover for IERC20;
    IERC20 public immutable token;
    mapping(address => uint256) public credit;
    constructor(IERC20 token_) { token = token_; }
    function deposit(uint256 amount) external {
        token.pull(msg.sender, amount);
        credit[msg.sender] += amount;
    }
    function withdraw(uint256 amount) external {
        require(credit[msg.sender] >= amount);
        credit[msg.sender] -= amount;
        token.push(msg.sender, amount);
    }
}
"""
    iface = "pragma solidity ^0.8.20;\n" + _ERC20
    direct_pair = custody_pairs(build_research_model({"desk.sol": direct}), "Desk")[0][0]
    helper_pair = custody_pairs(build_research_model({"desk.sol": helper}), "Desk")[0][0]
    imported = build_research_model(
        {"token_iface.sol": iface, "mover.sol": library, "desk.sol": vault}
    )
    imported_pair = custody_pairs(imported, "Desk")[0][0]
    for pair in (direct_pair, helper_pair, imported_pair):
        assert pair.mapping == "credit"
        assert pair.token_binding == "state:token"
        assert pair.incomplete == ()
    assert "Desk._deposit" in helper_pair.pull.path[1]
    assert imported_pair.pull.path[-1].startswith("Mover.pull")
    assert imported_pair.pay.path[-1].startswith("Mover.push")
