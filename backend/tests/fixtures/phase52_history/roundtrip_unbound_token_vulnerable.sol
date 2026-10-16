// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// The missing-debit vault, with its token set after deployment instead of at
/// construction. The local harness cannot bind the token.
contract LateTokenVault {
    IERC20 public token;
    address public immutable owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function setToken(IERC20 token_) external {
        require(msg.sender == owner, "owner");
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
