// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract DeltaVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit(IERC20 token, uint256 amount) external {
        uint256 beforeBalance = token.balanceOf(address(this));
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        uint256 received = token.balanceOf(address(this)) - beforeBalance;
        balances[msg.sender] += received;
        totalDeposits += received;
    }
}

// The deposit is the difference from the recorded reserve, not the absolute balance.
contract ReserveTracked {
    IERC20 public asset;
    uint256 public reserve;
    mapping(address => uint256) public credit;

    function creditDeposit() external {
        uint256 incoming = asset.balanceOf(address(this)) - reserve;
        reserve += incoming;
        credit[msg.sender] += incoming;
    }
}

contract CheckedReturn {
    mapping(address => uint256) public balances;

    function deposit(IERC20 token, uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        balances[msg.sender] += token.balanceOf(address(this)) - before;
    }

    function withdraw(IERC20 token, uint256 amount) external {
        balances[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}

// Owner-only rescue sweeps are authorization-gated, not a public pull-all.
contract GatedSweep {
    IERC20 public asset;
    address public owner;
    mapping(address => uint256) public balances;

    function rescue(address to) external {
        require(msg.sender == owner, "not owner");
        asset.transfer(to, asset.balanceOf(address(this)));
    }
}
