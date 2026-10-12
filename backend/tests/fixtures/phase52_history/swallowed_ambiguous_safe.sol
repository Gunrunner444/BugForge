// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Relay {
    function relay(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "propagated");
    }
}
