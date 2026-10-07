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

// The digest omits the recipient and any domain information.
contract BridgeVault {
    address public signer;
    mapping(uint256 => bool) public used;

    function release(
        IERC20 token,
        address recipient,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata sig
    ) external {
        require(block.timestamp <= deadline, "expired");
        require(!used[nonce], "used");
        bytes32 digest = keccak256(abi.encode(address(token), amount, nonce, deadline));
        require(ECDSA.recover(digest, sig) == signer, "bad signature");
        used[nonce] = true;
        token.transfer(recipient, amount);
    }
}

// The same signature verifies repeatedly because nothing records it.
contract ReplayableClaim {
    address public signer;

    function claim(address to, uint256 amount, bytes calldata sig) external {
        bytes32 digest = keccak256(abi.encodePacked(to, amount));
        require(ECDSA.recover(digest, sig) == signer, "bad signature");
        payable(to).transfer(amount);
    }
}

// The leaf omits the account that receives the tokens.
contract LooseMerkleDistributor {
    bytes32 public root;
    IERC20 public token;
    mapping(uint256 => bool) public claimed;

    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[index], "claimed");
        bytes32 leaf = keccak256(abi.encodePacked(index, amount));
        require(MerkleProof.verify(proof, root, leaf), "bad proof");
        claimed[index] = true;
        token.transfer(account, amount);
    }
}

// Cross-chain message: the destination token is not part of what was signed.
contract CrossChainReceiver {
    address public signer;
    mapping(bytes32 => bool) public processed;

    function receiveMessage(
        uint256 srcChain,
        IERC20 dstToken,
        address recipient,
        uint256 amount,
        bytes calldata sig
    ) external {
        bytes32 digest = keccak256(abi.encode(block.chainid, address(this), srcChain, recipient, amount));
        require(!processed[digest], "processed");
        require(ECDSA.recover(digest, sig) == signer, "bad signature");
        processed[digest] = true;
        dstToken.transfer(recipient, amount);
    }
}

// The counter is incremented, but its value is not signed.
contract UnsignedNoncePermit {
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(block.chainid, address(this)));
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes calldata sig
    ) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        require(ECDSA.recover(digest, sig) == owner, "bad signature");
        nonces[owner]++;
        allowance[owner][spender] = value;
    }
}
