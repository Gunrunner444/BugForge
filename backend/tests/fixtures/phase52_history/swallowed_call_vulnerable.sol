// SPDX-License-Identifier: MIT
// Behavioral probe only: the callee revert is ignored. Not a security-property violation.
pragma solidity ^0.8.20;

contract Relay {
    function relay(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        ok;
    }
}
