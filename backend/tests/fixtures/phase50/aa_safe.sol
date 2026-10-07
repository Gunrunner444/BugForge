// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes callData;
    bytes signature;
}

library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        return address(0);
    }
}

contract SafeAccount {
    address public owner;
    address public immutable entryPoint;
    bool public initialized;

    constructor(address ep) {
        entryPoint = ep;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not entry point");
        _;
    }

    function initialize(address newOwner) external {
        require(!initialized, "initialized");
        initialized = true;
        owner = newOwner;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        address signer = ECDSA.recover(userOpHash, userOp.signature);
        if (signer != owner) {
            return 1;
        }
        if (missingAccountFunds != 0) {
            (bool ok, ) = payable(msg.sender).call{value: missingAccountFunds}("");
            ok;
        }
        return 0;
    }

    function execute(address dest, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool ok, ) = dest.call{value: value}(data);
        require(ok, "execute failed");
    }
}

contract SafePaymaster {
    address public immutable entryPoint;
    address public verifyingSigner;
    mapping(address => uint256) public charged;

    constructor(address ep) {
        entryPoint = ep;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not entry point");
        _;
    }

    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external onlyEntryPoint returns (bytes memory context, uint256 validationData) {
        bytes32 digest = keccak256(abi.encode(block.chainid, address(this), userOpHash, maxCost));
        require(ECDSA.recover(digest, userOp.signature) == verifyingSigner, "bad paymaster signature");
        return (abi.encode(userOp.sender), 0);
    }

    function postOp(uint8 mode, bytes calldata context, uint256 actualGasCost) external onlyEntryPoint {
        address sender = abi.decode(context, (address));
        charged[sender] += actualGasCost;
    }
}

contract SafeFactory {
    function createAccount(address owner, bytes32 salt) external returns (address account) {
        bytes memory code = type(SafeAccount).creationCode;
        bytes32 bound = keccak256(abi.encode(owner, salt));
        assembly {
            account := create2(0, add(code, 0x20), mload(code), bound)
        }
    }
}
