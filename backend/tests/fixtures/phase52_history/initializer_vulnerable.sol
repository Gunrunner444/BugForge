// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Acct {
    address public owner;

    function initialize(address newOwner) external {
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
