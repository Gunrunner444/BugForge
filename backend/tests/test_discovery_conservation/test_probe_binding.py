"""A credit oracle stays bound to its call after a reorder mutation."""

from __future__ import annotations

from app.discovery.bounty.properties import build_property, probe_index
from app.discovery.bounty.vfcs import FeedbackSignal, generate, mutate
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite

VAULT = """pragma solidity ^0.8.20;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
contract RawVault {
    IERC20 public immutable token;
    mapping(address => uint256) public balances;
    constructor(IERC20 t) { token = t; }
    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "pull");
        balances[msg.sender] += amount;
    }
    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount), "pay");
    }
}
"""


def test_a_reordered_credit_sequence_keeps_its_probe() -> None:
    name, text = "RawVault.sol", VAULT
    model = build_research_model({name: text})
    candidate = next(
        c
        for c in run_suite(model).candidates
        if c.detector == "accounting.fee_on_transfer_mismatch"
    )
    sequence = generate(model, [candidate], sources={name: text}).sequences[0]
    assert [c.role for c in sequence.calls] == ["deposit", "withdraw"]
    signal = FeedbackSignal("near_miss", sequence.sequence_id, 0, engine="foundry")
    reordered = next(c for c in mutate([sequence], [signal]) if ":reorder:" in c.origin)
    assert [c.role for c in reordered.calls] == ["withdraw", "deposit"]
    spec = build_property(reordered, model, candidate)
    assert spec.oracle.probe_role == "deposit"
    assert probe_index(reordered, spec.oracle) == 1
    assert spec.property_id == build_property(sequence, model, candidate).property_id
