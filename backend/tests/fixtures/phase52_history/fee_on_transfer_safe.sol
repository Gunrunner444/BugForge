// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract Vault {
    mapping(address => uint256) public balances;

    function deposit(IERC20 token, uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        require(token.transferFrom(msg.sender, address(this), amount), "pull");
        balances[msg.sender] += token.balanceOf(address(this)) - before;
    }
}
