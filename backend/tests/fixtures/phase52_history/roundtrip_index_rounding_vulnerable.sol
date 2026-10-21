// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// Credit is principal at a fixed 1.5 index and is rounded up on supply. A 2-unit
/// supply credits 2 principal that withdraws as 3 units, but a 1e18 supply credits
/// 666666666666666667 principal that withdraws as exactly 1e18.
contract IndexVault {
    uint256 internal constant SCALE = 1e15;
    uint256 internal constant INDEX = 15e14;
    IERC20 public immutable token;
    mapping(address => uint256) public principal;

    constructor(IERC20 token_) {
        token = token_;
    }

    function supply(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "pull");
        principal[msg.sender] += (amount * SCALE + INDEX - 1) / INDEX;
    }

    function withdraw(uint256 amount) external {
        principal[msg.sender] -= amount;
        require(token.transfer(msg.sender, (amount * INDEX) / SCALE), "pay");
    }
}
