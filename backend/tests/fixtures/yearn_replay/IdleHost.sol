// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.18;

import {BaseStrategy} from "./BaseStrategy.sol";

/// Local execution host for the pinned TokenizedStrategy.
/// Funds stay idle. The harvest reports the contract's real asset balance.
contract IdleHost is BaseStrategy {
    constructor(address asset_) BaseStrategy(asset_, "Idle") {}

    function _deployFunds(uint256) internal override {}

    function _freeFunds(uint256) internal override {}

    function _harvestAndReport() internal override returns (uint256) {
        return asset.balanceOf(address(this));
    }
}
