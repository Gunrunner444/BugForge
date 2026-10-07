// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

error Failed(uint256 code, address who);

// Clears a storage variable and a transient variable in the same contract.
contract ClearsBoth {
    uint256 public stored;
    uint256 transient flag;

    function reset() external {
        delete stored;
        delete flag;
    }
}

// Two functions that call each other.
contract MutualRecursion {
    function ping(uint256 n) public pure returns (uint256) {
        if (n == 0) return 0;
        return pong(n - 1) + 1;
    }

    function pong(uint256 n) public pure returns (uint256) {
        if (n == 0) return 0;
        return ping(n - 1) + 1;
    }
}

// Deletes one element of a memory byte array.
contract MemoryDelete {
    function scrub(bytes memory data) public pure returns (bytes memory) {
        delete data[0];
        return data;
    }
}

// Passes custom error arguments with the named-parameter syntax.
contract NamedRequire {
    function check(uint256 x) external view {
        require(x > 0, Failed({who: msg.sender, code: x}));
    }
}
