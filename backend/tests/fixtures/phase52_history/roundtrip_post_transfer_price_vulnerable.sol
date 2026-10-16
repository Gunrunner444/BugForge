// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// Shares are priced with the balance measured after the deposit arrived, so a later
/// depositor is under-credited and an earlier holder redeems part of their deposit.
contract EagerShareVault {
    IERC20 public immutable asset;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    constructor(IERC20 asset_) {
        asset = asset_;
    }

    function deposit(uint256 assets) external {
        require(asset.transferFrom(msg.sender, address(this), assets), "pull");
        uint256 held = asset.balanceOf(address(this));
        uint256 minted = totalShares == 0 ? assets : (assets * totalShares) / held;
        shares[msg.sender] += minted;
        totalShares += minted;
    }

    function redeem(uint256 amount) external {
        uint256 paid = totalShares == 0 ? 0 : (amount * asset.balanceOf(address(this))) / totalShares;
        shares[msg.sender] -= amount;
        totalShares -= amount;
        require(asset.transfer(msg.sender, paid), "pay");
    }
}
