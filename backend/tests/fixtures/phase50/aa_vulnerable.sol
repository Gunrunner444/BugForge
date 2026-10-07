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

// Validation recovers a signer over a custom digest and never compares it.
contract LooseAccount {
    address public owner;
    address public entryPoint;
    bool public initialized;

    function initialize(address newOwner) external {
        owner = newOwner;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        bytes32 digest = keccak256(abi.encode(userOp.sender, userOp.nonce, userOp.callData));
        address signer = ECDSA.recover(digest, userOp.signature);
        if (missingAccountFunds != 0) {
            (bool ok, ) = payable(msg.sender).call{value: missingAccountFunds}("");
            ok;
        }
        return 0;
    }

    function execute(address dest, uint256 value, bytes calldata data) external {
        (bool ok, ) = dest.call{value: value}(data);
        require(ok, "execute failed");
    }
}

contract LoosePaymaster {
    address public entryPoint;
    address public verifyingSigner;

    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        bytes32 digest = keccak256(abi.encode(userOp.sender, userOp.nonce, maxCost));
        require(ECDSA.recover(digest, userOp.signature) == verifyingSigner, "bad paymaster signature");
        return (abi.encode(userOp.sender), 0);
    }

    function postOp(uint8 mode, bytes calldata context, uint256 actualGasCost) external {
        address sender = abi.decode(context, (address));
        charged[sender] += actualGasCost;
    }

    mapping(address => uint256) public charged;
}

contract LooseFactory {
    function createAccount(address owner, bytes32 salt) external returns (address account) {
        bytes memory code = type(LooseAccount).creationCode;
        assembly {
            account := create2(0, add(code, 0x20), mload(code), salt)
        }
    }
}
