// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        return address(0);
    }
}

library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return true;
    }
}

abstract contract EIP712Base {
    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32);
}

contract SafeBridgeVault is EIP712Base {
    address public signer;
    mapping(bytes32 => bool) public used;
    bytes32 public constant RELEASE_TYPEHASH =
        keccak256("Release(address token,address recipient,uint256 amount,uint256 nonce,uint256 deadline)");

    function release(
        IERC20 token,
        address recipient,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata sig
    ) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 structHash =
            keccak256(abi.encode(RELEASE_TYPEHASH, address(token), recipient, amount, nonce, deadline));
        bytes32 digest = _hashTypedDataV4(structHash);
        require(!used[digest], "used");
        require(ECDSA.recover(digest, sig) == signer, "bad signature");
        used[digest] = true;
        require(token.transfer(recipient, amount), "transfer failed");
    }
}

contract ChainBoundClaim {
    address public signer;
    mapping(uint256 => bool) public usedNonce;

    function claim(address to, uint256 amount, uint256 nonce, uint256 deadline, bytes calldata sig) external {
        require(block.timestamp <= deadline, "expired");
        require(!usedNonce[nonce], "used");
        bytes32 digest = keccak256(abi.encode(block.chainid, address(this), to, amount, nonce, deadline));
        require(ECDSA.recover(digest, sig) == signer, "bad signature");
        usedNonce[nonce] = true;
        payable(to).transfer(amount);
    }
}

contract BoundMerkleDistributor {
    bytes32 public root;
    IERC20 public token;
    mapping(uint256 => bool) public claimed;

    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[index], "claimed");
        bytes32 leaf = keccak256(abi.encodePacked(index, account, amount));
        require(MerkleProof.verify(proof, root, leaf), "bad proof");
        claimed[index] = true;
        require(token.transfer(account, amount), "transfer failed");
    }
}

contract CompletePermit {
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public DOMAIN_SEPARATOR;
    uint256 public immutable CACHED_CHAIN_ID;

    constructor() {
        CACHED_CHAIN_ID = block.chainid;
        DOMAIN_SEPARATOR = keccak256(abi.encode(block.chainid, address(this)));
    }

    function _domain() internal view returns (bytes32) {
        if (block.chainid == CACHED_CHAIN_ID) {
            return DOMAIN_SEPARATOR;
        }
        return keccak256(abi.encode(block.chainid, address(this)));
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes calldata sig
    ) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domain(), structHash));
        require(ECDSA.recover(digest, sig) == owner, "bad signature");
        allowance[owner][spender] = value;
    }
}
