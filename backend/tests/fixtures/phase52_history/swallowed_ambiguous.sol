// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Relay {
    function relay(address target, bytes calldata data) external {
        try this.relay(target, data) {} catch {}
        (bool ok, ) = target.call(data);
        if (ok == false && data.length > 0) {}
    }
}
