// SPDX-License-Identifier: MIT
// A transient flag set on entry and never cleared within the transaction.
pragma solidity ^0.8.24;

contract Router {
    function enter() external {
        _lock();
    }

    function _lock() internal {
        assembly {
            tstore(0x42, 1)
        }
    }
}
