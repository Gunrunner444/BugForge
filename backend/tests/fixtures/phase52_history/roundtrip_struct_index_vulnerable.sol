// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// Principal is stored in index units in a packed struct written back from a
/// memory copy. The index is set once by a permissionless initializer. The
/// withdrawal burns principal for the requested amount but pays that amount again
/// scaled by the index, so it converts token units twice.
contract StructVault {
    error AlreadyInitialized();

    struct Account {
        uint128 principal;
        uint64 lastIndex;
        uint64 flags;
    }

    IERC20 public immutable token;
    uint256 public supplyIndex;
    mapping(address => Account) internal accounts;

    constructor(IERC20 token_) {
        token = token_;
    }

    function initialize() external {
        if (supplyIndex != 0) revert AlreadyInitialized();
        supplyIndex = 2e18;
    }

    function balanceOf(address account) public view returns (uint256) {
        return (uint256(accounts[account].principal) * supplyIndex) / 1e18;
    }

    function supply(address asset, uint256 amount) external {
        require(asset == address(token), "asset");
        Account memory account = accounts[msg.sender];
        account.principal += uint128((amount * 1e18) / supplyIndex);
        _write(msg.sender, account);
        require(token.transferFrom(msg.sender, address(this), amount), "pull");
    }

    function withdraw(address asset, uint256 amount) external {
        require(asset == address(token), "asset");
        if (amount == type(uint256).max) {
            amount = balanceOf(msg.sender);
        }
        Account memory account = accounts[msg.sender];
        uint128 burned = uint128((amount * 1e18) / supplyIndex);
        require(account.principal >= burned, "credit");
        account.principal -= burned;
        _write(msg.sender, account);
        require(token.transfer(msg.sender, (amount * supplyIndex) / 1e18), "pay");
    }

    function _write(address owner, Account memory account) internal {
        accounts[owner] = account;
    }
}
