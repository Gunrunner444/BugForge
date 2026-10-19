"""A payout to a second attacker-controlled wallet is part of the conservation sum."""

from __future__ import annotations

from app.discovery.bounty.properties import build_property
from app.discovery.bounty.stateful import RECIPIENT_ADDR, StatefulExecutor
from app.discovery.bounty.vfcs import generate
from app.parsing.solidity_conservation import DETECTOR
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


def _vault(side: bool) -> str:
    extra = ""
    if side:
        extra = f"""
        uint256 extra = token.balanceOf(address(this));
        if (extra != 0) require(token.transfer({RECIPIENT_ADDR}, extra));
"""
    return (
        _ERC20
        + f"""
contract Desk {{
    IERC20 public immutable token;
    mapping(address => uint256) public claim;
    constructor(IERC20 token_) {{ token = token_; }}
    function deposit(uint256 amount) external {{
        require(token.transferFrom(msg.sender, address(this), amount));
        claim[msg.sender] += amount;
    }}
    function withdraw(uint256 amount) external {{
        uint256 owed = claim[msg.sender];
        require(owed >= amount);
        claim[msg.sender] = 0;
        require(token.transfer(msg.sender, owed));
        {extra}
    }}
}}
"""
    )


def _run(source: str):  # type: ignore[no-untyped-def]
    model = build_research_model({"desk.sol": source})
    hit = next(item for item in run_suite(model).candidates if item.detector == DETECTOR)
    sequence = generate(model, [hit], sources={"desk.sol": source}).sequences[0]
    spec = build_property(sequence, model, hit)
    return StatefulExecutor().execute(sequence, model, {"desk.sol": source}, spec=spec)


@requires_forge
def test_a_side_wallet_payout_is_not_reported_as_held() -> None:
    taken = _run(_vault(True))
    assert taken.outcome.value == "property_violated", taken.reason
    assert taken.evaluation is not None
    seen = dict(taken.evaluation.evidence)
    assert seen["recipient_balance_before"] == 0
    assert seen["recipient_balance_after"] > 0
    assert seen["attacker_balance_before"] == seen["attacker_balance_after"]
    fair = _run(_vault(False))
    assert fair.outcome.value == "property_held", fair.reason
    assert fair.evaluation is not None
    held = dict(fair.evaluation.evidence)
    assert held["recipient_balance_after"] == 0
