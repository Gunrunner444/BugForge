// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Acct {
    address public owner;
    bool public initialized;

    function initialize(address newOwner) external {
        require(!initialized, "initialized");
        initialized = true;
        owner = newOwner;
    }

    function validateUserOp(
        bytes calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256) {
        return 0;
    }
}
