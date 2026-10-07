// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library SafeCast {
    function toUint128(uint256 value) internal pure returns (uint128) {
        require(value <= type(uint128).max, "overflow");
        return uint128(value);
    }
}

// Checked full-width accumulation reverts instead of wrapping.
contract CheckedBatchPayout {
    IERC20 public token;
    uint256 public budget;

    function payAll(address[] calldata to, uint256[] calldata amounts) external {
        uint256 total;
        for (uint256 i = 0; i < amounts.length; i++) {
            total += amounts[i];
        }
        require(total <= budget, "over budget");
        for (uint256 i = 0; i < to.length; i++) {
            token.transfer(to[i], amounts[i]);
        }
    }
}

contract SafeNarrowing {
    mapping(address => uint128) public stakes;

    function stake(uint256 amount, uint256 multiplier) external {
        stakes[msg.sender] = SafeCast.toUint128(amount * multiplier);
    }

    function stakeBounded(uint256 amount, uint256 multiplier) external {
        uint256 product = amount * multiplier;
        require(product <= type(uint128).max, "overflow");
        stakes[msg.sender] = uint128(amount * multiplier);
    }
}

contract MultiplyFirst {
    IERC20 public token;

    function reward(address user, uint256 amount, uint256 total, uint256 pool) external {
        uint256 share = amount * pool / total;
        token.transfer(user, share);
    }
}

// The burn side rounds up, so rounding favors the vault in both directions.
contract CeilVault {
    IERC20 public asset;
    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;

    function withdraw(uint256 assets) external {
        uint256 burned = (assets * totalShares + totalAssets - 1) / totalAssets;
        shares[msg.sender] -= burned;
        totalShares -= burned;
        totalAssets -= assets;
        asset.transfer(msg.sender, assets);
    }
}
