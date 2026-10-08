// SPDX-License-Identifier: MIT
// Compact local reconstruction of a well-known incident class: a cross-chain
// receiver that processes messages from any caller (no endpoint check).
pragma solidity ^0.8.20;

contract OpenReceiver {
    address public endpoint;
    mapping(bytes32 => bool) public processed;
    uint256 public released;

    constructor() {
        endpoint = address(0xE0);
    }

    function receiveMessage(bytes calldata message) external {
        bytes32 id = keccak256(message);
        processed[id] = true;
        released += 1;
    }
}
