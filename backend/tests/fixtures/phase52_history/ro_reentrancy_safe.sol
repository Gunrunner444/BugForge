// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PoolShares {
    uint256 public totalShares = 1;
    mapping(address => uint256) public shares;

    function withdraw(uint256 amount) external {
        shares[msg.sender] -= amount;
        totalShares -= amount;
        _pay(msg.sender, amount);
    }

    function _pay(address to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "pay");
    }

    function sharePrice() external view returns (uint256) {
        return address(this).balance / totalShares;
    }
}
