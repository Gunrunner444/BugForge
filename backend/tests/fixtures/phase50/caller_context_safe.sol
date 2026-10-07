// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// delegatecall preserves msg.sender, so nested checks still see the original actor.
contract SafeDelegateMulticall {
    address public owner;
    uint256 public fee;

    constructor() {
        owner = msg.sender;
    }

    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory out) = address(this).delegatecall(data[i]);
            require(ok, "call failed");
            results[i] = out;
        }
    }

    function setFee(uint256 next) external {
        require(msg.sender == owner, "not owner");
        fee = next;
    }
}

// A nested self-call changes the frame, but the dispatching function is itself authorized
// and the nested target is fixed in code, not chosen by the caller.
contract FixedSelfCall {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    function update(uint256 next) external {
        require(msg.sender == owner, "not owner");
        this.internalUpdate(next);
    }

    function internalUpdate(uint256 next) external {
        require(msg.sender == address(this), "only self");
        value = next;
    }
}

// Self-call multicall exists, but no function trusts the contract's own address.
contract SelfCallNoSelfTrust {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    function multicall(bytes[] calldata data) external {
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, ) = address(this).call(data[i]);
            require(ok, "call failed");
        }
    }

    function setValue(uint256 next) external {
        require(msg.sender == owner, "not owner");
        value = next;
    }
}

// Trusted-forwarder sender extraction with no delegatecall multicall.
contract ForwarderOnly {
    address public trustedForwarder;
    address public admin;

    constructor(address f) {
        trustedForwarder = f;
    }

    function _msgSender() internal view returns (address sender) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender = msg.sender;
        }
    }

    function setAdmin(address next) external {
        require(_msgSender() == admin, "not admin");
        admin = next;
    }
}

// Forwarder-aware multicall re-appends the sender to each nested call.
contract ForwarderAwareMulticall {
    address public trustedForwarder;
    address public admin;

    function _msgSender() internal view returns (address sender) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender = msg.sender;
        }
    }

    function multicall(bytes[] calldata data) external {
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, ) = address(this).delegatecall(abi.encodePacked(data[i], _msgSender()));
            require(ok, "call failed");
        }
    }

    function setAdmin(address next) external {
        require(_msgSender() == admin, "not admin");
        admin = next;
    }
}

// An approved router that only forwards to allow-listed destinations.
contract AllowListRouter {
    IERC20 public immutable token;
    mapping(address => bool) public allowedTargets;

    constructor(IERC20 t) {
        token = t;
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
    }

    function execute(address target, bytes calldata data) external {
        require(allowedTargets[target], "target not allowed");
        (bool ok, ) = target.call(data);
        require(ok, "execute failed");
    }
}

// An approved router whose forwarding entry point is owner-only.
contract OwnerRouter {
    IERC20 public immutable token;
    address public owner;

    constructor(IERC20 t) {
        token = t;
        owner = msg.sender;
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
    }

    function execute(address target, bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = target.call(data);
        require(ok, "execute failed");
    }
}

contract BoundVault {
    address public router;
    mapping(address => uint256) public balances;

    constructor(address r) {
        router = r;
    }

    function withdrawFor(address user, uint256 amount) external {
        require(msg.sender == router, "only router");
        balances[user] -= amount;
        payable(user).transfer(amount);
    }
}

// The intermediary binds the forwarded user to the original caller.
contract BoundRouter {
    BoundVault public vault;

    constructor(BoundVault v) {
        vault = v;
    }

    function relayWithdraw(address user, uint256 amount) external {
        require(msg.sender == user, "not user");
        vault.withdrawFor(user, amount);
    }
}
