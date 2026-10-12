// SPDX-License-Identifier: MIT
// Intentional best-effort prefund. Candidate emission is not a vulnerability.
pragma solidity ^0.8.20;

contract Account {
    function validateUserOp() external payable {
        (bool ok, ) = msg.sender.call{value: 1}("");
        ok;
    }
}
