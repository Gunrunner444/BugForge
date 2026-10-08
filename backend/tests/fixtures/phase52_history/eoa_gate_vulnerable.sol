// SPDX-License-Identifier: MIT
// "Only EOAs" flash-loan guard, unsound after EIP-7702.
pragma solidity ^0.8.20;

contract Minter {
    mapping(address => uint256) public minted;

    modifier onlyEOA() {
        require(msg.sender == tx.origin, "no contracts");
        _;
    }

    function mint() external onlyEOA {
        minted[msg.sender] += 1;
    }
}
