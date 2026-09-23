// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Token.sol";

contract Vault {
    Token public token;

    function probe(address who) external view returns (uint256) {
        return token.balanceOf(who);
    }
}
