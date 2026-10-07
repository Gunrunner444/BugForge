// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

error Failed(uint256 code, address who);

// Only the transient variable is ever cleared.
contract ClearsOne {
    uint256 public stored;
    uint256 transient flag;

    function reset() external {
        delete flag;
        stored = 0;
    }
}

// Recursion that stays inside one function.
contract SelfRecursion {
    function countdown(uint256 n) public pure returns (uint256) {
        if (n == 0) return 0;
        return countdown(n - 1) + 1;
    }

    function helper(uint256 n) public pure returns (uint256) {
        return n + 1;
    }
}

// The byte array is storage, not memory.
contract StorageDelete {
    bytes public data;

    function scrub() external {
        delete data;
    }
}

// Positional custom error arguments.
contract PositionalRequire {
    function check(uint256 x) external view {
        require(x > 0, Failed(x, msg.sender));
    }
}
