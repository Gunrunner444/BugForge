// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Router {
    function enter() external {
        _lock();
        _unlock();
    }

    function _lock() internal {
        assembly {
            tstore(0x42, 1)
        }
    }

    function _unlock() internal {
        assembly {
            tstore(0x42, 0)
        }
    }
}
