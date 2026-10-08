// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Minter {
    mapping(address => uint256) public minted;
    mapping(address => bool) public allowed;

    function mint() external {
        require(allowed[msg.sender], "not allowed");
        minted[msg.sender] += 1;
    }
}
