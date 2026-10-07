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
    function decimals() external view returns (uint8);
}

interface ITwap {
    function consult(address token, uint256 amount) external view returns (uint256);
}

contract QuorumAggregator {
    IPriceSource[] public sources;
    uint256 public minSources = 3;

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
        require(valid >= minSources, "quorum not reached");
        return total / valid;
    }
}

contract LendingMarket {
    QuorumAggregator public aggregator;
    mapping(address => uint256) public collateralAmount;

    function collateralValue(address user) public view returns (uint256) {
        return (collateralAmount[user] * aggregator.aggregatePrice()) / 1e18;
    }
}

// An intentionally single-source oracle with complete validation.
contract SingleSourceOracle {
    IFeed public feed;
    uint256 public constant MAX_AGE = 1 hours;

    function getPrice() public view returns (uint256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
        require(answer > 0, "bad answer");
        require(answeredInRound >= roundId, "stale round");
        require(block.timestamp - updatedAt <= MAX_AGE, "stale price");
        return uint256(answer);
    }

    function collateralValue(uint256 amount) external view returns (uint256) {
        return (amount * getPrice()) / 1e8;
    }
}

contract ValidatedFallbackOracle {
    IFeed public primary;
    IFeed public secondary;
    uint256 public constant MAX_AGE = 1 hours;

    function getPrice() public view returns (uint256) {
        try primary.latestRoundData() returns (uint80, int256 answer, uint256, uint256 updatedAt, uint80) {
            if (answer > 0 && block.timestamp - updatedAt < MAX_AGE) {
                return uint256(answer);
            }
        } catch {}
        (, int256 other, , uint256 otherUpdated, ) = secondary.latestRoundData();
        require(other > 0 && block.timestamp - otherUpdated < MAX_AGE, "fallback invalid");
        return uint256(other);
    }
}

// A spot price that is bounded against a time-weighted source.
contract BoundedSpotVault {
    IPair public pair;
    ITwap public twap;
    address public asset;
    uint256 public maxDeviation = 200;
    mapping(address => uint256) public collateralAmount;

    function boundedPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        uint256 spot = (uint256(reserve1) * 1e18) / uint256(reserve0);
        uint256 average = twap.consult(asset, 1e18);
        uint256 diff = spot > average ? spot - average : average - spot;
        require(diff * 10_000 <= average * maxDeviation, "deviation");
        return average;
    }

    function collateralValue(address user) external view returns (uint256) {
        return (collateralAmount[user] * boundedPrice()) / 1e18;
    }
}
