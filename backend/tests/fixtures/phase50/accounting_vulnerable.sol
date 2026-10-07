// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// Credits the requested amount, so a fee-on-transfer token over-credits the depositor.
contract RawAmountVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit(IERC20 token, uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
        totalDeposits += amount;
    }
}

// Shares are priced from the absolute balance, so a donation moves the share price.
contract DonationVault {
    IERC20 public asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    function deposit(uint256 amount) external {
        uint256 assets = asset.balanceOf(address(this));
        uint256 minted = totalShares == 0 ? amount : (amount * totalShares) / assets;
        asset.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += minted;
        totalShares += minted;
    }
}

// Whatever is already in the contract becomes the caller's deposit.
contract BalanceAsDeposit {
    IERC20 public asset;
    mapping(address => uint256) public credit;

    function creditDeposit() external {
        uint256 incoming = asset.balanceOf(address(this));
        credit[msg.sender] += incoming;
    }
}

// Sends everything the contract holds while it also tracks per-account balances.
contract SweepEverything {
    IERC20 public asset;
    mapping(address => uint256) public balances;

    function withdrawAll(address to) external {
        asset.transfer(to, asset.balanceOf(address(this)));
    }
}

// The cached balance is paid out later, so a rebasing token diverges from it.
contract CachedBalance {
    IERC20 public asset;
    uint256 public stored;

    function sync() external {
        stored = asset.balanceOf(address(this));
    }

    function payout(address to) external {
        asset.transfer(to, stored);
    }
}

// transfer returns false for some tokens instead of reverting.
contract IgnoredReturn {
    mapping(address => uint256) public balances;

    function deposit(IERC20 token, uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }
}
