"""Share-price donation: the property measures redemption, not a successful call."""

from __future__ import annotations

from app.discovery.bounty.properties import (
    OracleKind,
    PropertyDeclaration,
    build_property,
)
from app.discovery.bounty.stateful import StatefulExecutor
from app.discovery.bounty.vfcs import generate
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite
from tests.test_phase52.phase52_support import requires_forge

_ERC20 = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""

_VULNERABLE = (
    _ERC20
    + """
contract Pool {
    IERC20 public asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    constructor(IERC20 asset_) { asset = asset_; }
    function deposit(uint256 amount) external {
        uint256 assets = asset.balanceOf(address(this));
        uint256 supply = totalShares;
        uint256 minted = supply == 0 ? amount : (amount * supply) / assets;
        require(asset.transferFrom(msg.sender, address(this), amount));
        shares[msg.sender] += minted;
        totalShares += minted;
    }
    function redeem(uint256 shareAmount) external {
        uint256 assets = asset.balanceOf(address(this));
        uint256 out = (shareAmount * assets) / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        require(asset.transfer(msg.sender, out));
    }
}
"""
)

_SAFE = (
    _ERC20
    + """
contract Pool {
    IERC20 public asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    constructor(IERC20 asset_) { asset = asset_; }
    function deposit(uint256 amount) external {
        uint256 assets = asset.balanceOf(address(this));
        uint256 supply = totalShares;
        uint256 minted = supply == 0 ? amount : (amount * (supply + 1000)) / (assets + 1000);
        require(asset.transferFrom(msg.sender, address(this), amount));
        shares[msg.sender] += minted;
        totalShares += minted;
    }
    function redeem(uint256 shareAmount) external {
        uint256 assets = asset.balanceOf(address(this));
        uint256 out = (shareAmount * (assets + 1000)) / (totalShares + 1000);
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        require(asset.transfer(msg.sender, out));
    }
}
"""
)


def _run(source: str):  # type: ignore[no-untyped-def]
    model = build_research_model({"pool.sol": source})
    hit = next(
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.donation_share_price"
        and item.function.startswith("deposit")
    )
    built = generate(model, [hit], sources={"pool.sol": source})
    sequence = next(item for item in built.sequences if item.template == "deposit→donate→withdraw")
    spec = build_property(sequence, model, hit)
    observation = StatefulExecutor().execute(sequence, model, {"pool.sol": source}, spec=spec)
    return sequence, spec, observation


def test_the_share_sequence_uses_one_unit_then_the_live_share_balance() -> None:
    model = build_research_model({"pool.sol": _VULNERABLE})
    hit = next(
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.donation_share_price"
        and item.function.startswith("deposit")
    )
    sequence = generate(model, [hit], sources={"pool.sol": _VULNERABLE}).sequences[0]
    amounts = [value for _name, value in sequence.calls[0].arguments]
    assert amounts == ["unit_amount"]
    assert sequence.calls[-1].arguments[0][1] == "all_shares"
    spec = build_property(sequence, model, hit)
    assert spec.declaration is PropertyDeclaration.PROPERTY_UNDER_TEST
    assert spec.oracle.kind is OracleKind.BALANCE_NOT_INCREASED
    assert spec.oracle.getter == "shares(address)"
    assert any(item.startswith("attacker deposit: 1") for item in spec.provenance.assumptions)
    assert any("1000000000000000000" in item for item in spec.provenance.assumptions)


@requires_forge
def test_donation_inflation_is_a_gain_and_the_offset_pool_holds() -> None:
    _sequence, spec, violated = _run(_VULNERABLE)
    assert spec.executable
    assert violated.outcome.value == "property_violated", violated.reason
    assert violated.evaluation is not None
    seen = dict(violated.evaluation.evidence)
    assert seen["attacker_balance_after"] > seen["attacker_balance_before"]
    assert "attacker_credit_before" in seen and "victim_credit_after" in seen
    _sequence, _spec, held = _run(_SAFE)
    assert held.outcome.value == "property_held", held.reason
    assert held.evaluation is not None
    fair = dict(held.evaluation.evidence)
    assert fair["attacker_balance_after"] <= fair["attacker_balance_before"]
