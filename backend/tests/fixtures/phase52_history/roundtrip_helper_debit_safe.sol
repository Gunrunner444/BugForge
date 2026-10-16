// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

library TokenMover {
    function pull(IERC20 token, address from, uint256 amount) internal {
        require(token.transferFrom(from, address(this), amount), "pull");
    }

    function push(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount), "push");
    }
}

library Ledger {
    struct Position {
        uint256 shares;
        uint256 debt;
    }

    function credit(Position storage position, uint256 amount) internal {
        position.shares += amount;
    }

    function debit(Position storage position, uint256 amount) internal {
        position.shares -= amount;
    }
}

/// Every movement goes through helpers, and the withdrawal debits the position
/// through the library before paying.
contract HelperVault {
    using TokenMover for IERC20;
    using Ledger for Ledger.Position;

    IERC20 public immutable token;
    mapping(address => Ledger.Position) internal positions;

    constructor(IERC20 token_) {
        token = token_;
    }

    function deposit(uint256 amount) external {
        _deposit(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        _withdraw(msg.sender, amount);
    }

    function _position(address account) internal view returns (Ledger.Position storage) {
        return positions[account];
    }

    function _deposit(address from, uint256 amount) internal {
        token.pull(from, amount);
        _position(from).credit(amount);
    }

    function _withdraw(address to, uint256 amount) internal {
        Ledger.Position storage position = _position(to);
        require(position.shares >= amount, "credit");
        position.debit(amount);
        token.push(to, amount);
    }
}
