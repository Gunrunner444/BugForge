// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.18;

import {BaseStrategy} from "./BaseStrategy.sol";

/// Local host whose reportable value is idle assets plus a public deployed balance.
/// This is a fixture. It is not a production strategy and not an upstream Yearn edit.
contract DeployedHost is BaseStrategy {
    uint256 public deployed;

    constructor(address asset_) BaseStrategy(asset_, "Deployed") {}

    function _deployFunds(uint256) internal override {}

    function _freeFunds(uint256) internal override {}

    function _harvestAndReport() internal override returns (uint256) {
        return asset.balanceOf(address(this)) + deployed;
    }

    function accrue(uint256 amount) external {
        deployed += amount;
    }
}
