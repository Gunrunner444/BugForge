// SPDX-License-Identifier: MIT
// Hook callbacks that any caller can invoke directly (no PoolManager check).
pragma solidity ^0.8.20;

contract CounterHook {
    address public poolManager;
    uint256 public swaps;

    constructor() {
        poolManager = address(0xA0);
    }

    function afterSwap(address sender, uint256 amount) external returns (bytes4) {
        swaps += amount;
        return this.afterSwap.selector;
    }
}
