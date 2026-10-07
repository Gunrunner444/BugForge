// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PlainWallet {
    address public owner;

    function execute(address dest, uint256 value, bytes calldata data) external {
        (bool ok, ) = dest.call{value: value}(data);
        require(ok, "execute failed");
    }
}
