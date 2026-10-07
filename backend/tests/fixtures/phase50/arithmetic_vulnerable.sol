// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// The unchecked sum of a caller-supplied array can wrap past the balance check.
contract BatchPayout {
    IERC20 public token;
    uint256 public budget;

    function payAll(address[] calldata to, uint256[] calldata amounts) external {
        uint256 total;
        unchecked {
            for (uint256 i = 0; i < amounts.length; i++) {
                total += amounts[i];
            }
        }
        require(total <= budget, "over budget");
        for (uint256 i = 0; i < to.length; i++) {
            token.transfer(to[i], amounts[i]);
        }
    }
}

contract NarrowedStorage {
    mapping(address => uint128) public stakes;
    uint256 public rate;

    function stake(uint256 amount, uint256 multiplier) external {
        stakes[msg.sender] = uint128(amount * multiplier);
    }
}

contract PrecisionLoss {
    IERC20 public token;

    function reward(address user, uint256 amount, uint256 total, uint256 pool) external {
        uint256 share = amount / total * pool;
        token.transfer(user, share);
    }
}

// Both directions floor, so burning shares for a fixed payout favors the caller.
contract FloorVault {
    IERC20 public asset;
    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;

    function deposit(uint256 assets) external {
        uint256 minted = assets * totalShares / totalAssets;
        asset.transferFrom(msg.sender, address(this), assets);
        shares[msg.sender] += minted;
        totalShares += minted;
        totalAssets += assets;
    }

    function withdraw(uint256 assets) external {
        uint256 burned = assets * totalShares / totalAssets;
        shares[msg.sender] -= burned;
        totalShares -= burned;
        totalAssets -= assets;
        asset.transfer(msg.sender, assets);
    }
}
