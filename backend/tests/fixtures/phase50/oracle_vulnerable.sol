// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPriceSource {
    function price() external view returns (uint256);
}

interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IFeed {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

// One thin-liquidity pool quote is enough to define the price.
contract ThinPoolSource {
    IPair public pair;

    function price() external view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }
}

contract WeakQuorumAggregator {
    IPriceSource[] public sources;
    uint256 public minSources = 1;

    function aggregatePrice() public view returns (uint256) {
        uint256 total;
        uint256 valid;
        for (uint256 i = 0; i < sources.length; i++) {
            try sources[i].price() returns (uint256 p) {
                if (p == 0) continue;
                total += p;
                valid++;
            } catch {
                continue;
            }
        }
        require(valid >= minSources, "no price");
        return total / valid;
    }
}

contract LendingMarket {
    WeakQuorumAggregator public aggregator;
    mapping(address => uint256) public collateralAmount;
    mapping(address => uint256) public debt;

    function collateralValue(address user) public view returns (uint256) {
        return (collateralAmount[user] * aggregator.aggregatePrice()) / 1e18;
    }

    function borrow(uint256 amount) external {
        require(collateralValue(msg.sender) >= debt[msg.sender] + amount, "undercollateralized");
        debt[msg.sender] += amount;
    }
}

contract StaleFeedConsumer {
    IFeed public feed;
    mapping(address => uint256) public collateralAmount;

    function collateralPrice() public view returns (uint256) {
        (, int256 answer, , , ) = feed.latestRoundData();
        return uint256(answer);
    }

    function collateralValue(address user) external view returns (uint256) {
        return collateralAmount[user] * collateralPrice();
    }
}

contract WeakFallbackOracle {
    IFeed public primary;
    IFeed public secondary;
    uint256 public constant MAX_AGE = 1 hours;

    function getPrice() public view returns (uint256) {
        try primary.latestRoundData() returns (uint80, int256 answer, uint256, uint256 updatedAt, uint80) {
            if (answer > 0 && block.timestamp - updatedAt < MAX_AGE) {
                return uint256(answer);
            }
        } catch {}
        (, int256 other, , , ) = secondary.latestRoundData();
        return uint256(other);
    }
}

contract SpotPriceVault {
    IPair public pair;
    mapping(address => uint256) public collateralAmount;

    function spotPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }

    function collateralValue(address user) external view returns (uint256) {
        return (collateralAmount[user] * spotPrice()) / 1e18;
    }
}
