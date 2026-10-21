// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// A report that records an increase and ignores a later drop in the token balance.
contract ReportDesk {
    IERC20 public immutable token;
    uint256 public accounted;

    constructor(IERC20 token_) {
        token = token_;
    }

    function report() external {
        uint256 live = token.balanceOf(address(this));
        if (live > accounted) {
            accounted = live;
        }
    }

    function skim(uint256 amount) external {
        token.transfer(msg.sender, amount);
    }
}
