// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

// Self-call multicall: nested frames run with msg.sender == address(this), and
// the privileged function trusts exactly that identity.
contract SelfTrustMulticall {
    address public treasury;
    mapping(address => uint256) public balances;

    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory out) = address(this).call(data[i]);
            require(ok, "call failed");
            results[i] = out;
        }
    }

    function setTreasury(address next) external {
        require(msg.sender == address(this), "only self");
        treasury = next;
    }
}

// A router that users approve for token pulls and that forwards caller-chosen calls.
contract ApprovedRouter {
    IERC20 public immutable token;

    constructor(IERC20 t) {
        token = t;
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
    }

    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "execute failed");
    }
}

// The vault trusts one router address, and the router does not authenticate the user it forwards.
contract TrustedVault {
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

contract UserRouter {
    TrustedVault public vault;

    constructor(TrustedVault v) {
        vault = v;
    }

    function relayWithdraw(address user, uint256 amount) external {
        vault.withdrawFor(user, amount);
    }
}

// ERC-2771 style sender extraction together with a delegatecall multicall.
contract ForwarderMulticall {
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

    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory out) = address(this).delegatecall(data[i]);
            require(ok, "call failed");
            results[i] = out;
        }
    }

    function setAdmin(address next) external {
        require(_msgSender() == admin, "not admin");
        admin = next;
    }
}
