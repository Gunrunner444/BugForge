// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Token {
    function balanceOf(address who) external pure returns (uint256) {
        if (who == address(0)) {
            return 0;
        }
        return 1;
    }
}
