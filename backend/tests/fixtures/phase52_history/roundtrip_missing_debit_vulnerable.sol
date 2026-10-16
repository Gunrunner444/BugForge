// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// Withdrawal checks the credit but never reduces it, so one credit pays out twice
/// and the second payment comes from another depositor's funds.
contract LeakyVault {
    IERC20 public immutable token;
    mapping(address => uint256) public balances;

    constructor(IERC20 token_) {
        token = token_;
    }

    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "pull");
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "credit");
        require(token.transfer(msg.sender, amount), "pay");
    }
}
