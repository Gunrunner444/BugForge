// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CounterHook {
    address public poolManager;
    uint256 public swaps;

    constructor() {
        poolManager = address(0xA0);
    }

    modifier onlyPoolManager() {
        require(msg.sender == poolManager, "not pool manager");
        _;
    }

    function afterSwap(address sender, uint256 amount) external onlyPoolManager returns (bytes4) {
        swaps += amount;
        return this.afterSwap.selector;
    }
}
