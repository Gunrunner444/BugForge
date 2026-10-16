"""The interprocedural custody trace: what it follows, what it refuses, what it reports."""

from __future__ import annotations

from pathlib import Path

from app.discovery.bounty.properties import build_property
from app.discovery.bounty.stateful import build_harness
from app.discovery.bounty.vfcs import generate
from app.parsing.solidity_conservation import (
    DETECTOR,
    MAX_TRACE_DEPTH,
    custody_pairs,
    custody_report,
)
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite

HISTORY = Path(__file__).resolve().parents[1] / "fixtures" / "phase52_history"

ERC20 = """pragma solidity ^0.8.20;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""


def _pairs(body: str, contract: str = "V"):  # type: ignore[no-untyped-def]
    model = build_research_model({"V.sol": ERC20 + body})
    return custody_pairs(model, contract)


def _fixture(stem: str, role: str):  # type: ignore[no-untyped-def]
    name = f"roundtrip_{stem}_{role}.sol"
    text = (HISTORY / name).read_text(encoding="utf-8")
    return name, text, build_research_model({name: text})


def test_helpers_libraries_and_storage_references_are_followed_with_provenance() -> None:
    name, _text, model = _fixture("helper_debit", "safe")
    (pair,), notes = custody_pairs(model, "HelperVault")
    assert notes == [] and pair.incomplete == ()
    assert pair.mapping == "positions" and pair.credit_field == "shares"
    assert pair.keys == "caller"
    assert pair.token_binding == "state:token"
    assert pair.token_source == "constructor parameter token_"
    assert [step.split("@")[0] for step in pair.pull.path] == [
        "HelperVault.deposit(uint256)",
        "HelperVault._deposit(address,uint256)",
        "TokenMover.pull(IERC20,address,uint256)",
    ]
    assert pair.pay.path[-1].startswith("TokenMover.push(IERC20,address,uint256)@")
    assert pair.write_site.endswith("Ledger.credit") and pair.write_site.startswith(name)
    assert pair.read_site.endswith("HelperVault._withdraw")
    (candidate,) = [c for c in run_suite(model).candidates if c.detector == DETECTOR]
    assert candidate.fact("helper_mediated") == "true"
    assert candidate.fact("deposit_path").startswith("HelperVault.deposit(uint256) > ")


def test_the_caller_is_followed_by_value_not_by_parameter_name() -> None:
    template = """
contract V {
    IERC20 public immutable token;
    address public treasury;
    mapping(address => uint256) public credit;
    constructor(IERC20 t, address r) { token = t; treasury = r; }
    function deposit(uint256 amount) external { _in(%s, amount); }
    function withdraw(uint256 amount) external {
        require(credit[msg.sender] >= amount);
        credit[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
    function _in(address %s, uint256 amount) internal {
        token.transferFrom(%s, address(this), amount);
        credit[%s] += amount;
    }
}
"""
    renamed, _ = _pairs(template % ("msg.sender", "who", "who", "who"))
    assert [p.deposit.signature for p in renamed] == ["deposit(uint256)"]
    named_like_sender, _ = _pairs(template % ("treasury", "sender", "sender", "sender"))
    assert named_like_sender == []


def test_tokens_are_matched_by_binding_not_by_name() -> None:
    two_tokens = """
contract V {
    IERC20 public immutable tokenA;
    IERC20 public immutable tokenB;
    mapping(address => uint256) public credit;
    constructor(IERC20 a, IERC20 b) { tokenA = a; tokenB = b; }
    function deposit(uint256 amount) external {
        tokenA.transferFrom(msg.sender, address(this), amount);
        credit[msg.sender] += amount;
    }
    function withdraw(uint256 amount) external {
        credit[msg.sender] -= amount;
        tokenB.transfer(msg.sender, amount);
    }
}
"""
    assert _pairs(two_tokens)[0] == []
    unguarded = """
contract V {
    IERC20 public immutable token;
    mapping(address => uint256) public credit;
    constructor(IERC20 t) { token = t; }
    function deposit(address asset, uint256 amount) external {
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        credit[msg.sender] += amount;
    }
    function withdraw(uint256 amount) external {
        credit[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""
    assert _pairs(unguarded)[0] == []
    guarded = unguarded.replace(
        "IERC20(asset).transferFrom",
        "require(asset == address(token));\n        IERC20(asset).transferFrom",
    )
    (pair,), _ = _pairs(guarded)
    assert pair.token_binding == "state:token" and pair.deposit_token_argument == "asset"


def test_different_fields_of_one_position_are_not_conflated() -> None:
    body = """
contract V {
    struct Position { uint256 shares; uint256 debt; }
    IERC20 public immutable token;
    mapping(address => Position) internal positions;
    constructor(IERC20 t) { token = t; }
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        positions[msg.sender].shares += amount;
    }
    function withdraw(uint256 amount) external {
        require(positions[msg.sender].debt >= amount);
        positions[msg.sender].debt -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""
    assert _pairs(body)[0] == []
    same = body.replace(".debt", ".shares")
    (pair,), _ = _pairs(same)
    assert pair.credit_field == "shares" and pair.fields == ("shares",)


def test_an_unattributable_whole_struct_write_is_incomplete_not_a_pair() -> None:
    body = """
contract V {
    struct Position { uint256 shares; uint256 debt; }
    IERC20 public immutable token;
    mapping(address => Position) internal positions;
    constructor(IERC20 t) { token = t; }
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        positions[msg.sender] = _fresh(amount);
    }
    function withdraw(uint256 amount) external {
        require(positions[msg.sender].shares >= amount);
        token.transfer(msg.sender, amount);
    }
    function _fresh(uint256 amount) internal pure returns (Position memory) {
        return Position(amount, 0);
    }
}
"""
    pairs, notes = _pairs(body)
    assert pairs == []
    assert any("written whole" in note and "cannot attribute" in note for note in notes)


def test_a_memory_copy_keeps_its_fields_through_a_write_back_helper() -> None:
    _name, _text, model = _fixture("struct_index", "safe")
    (pair,), notes = custody_pairs(model, "StructVault")
    assert notes == [] and pair.incomplete == ()
    assert pair.credit_field == "principal"
    assert pair.write_site.endswith("StructVault._write")
    assert pair.deposit_token_argument == "asset" and pair.payout_token_argument == "asset"
    assert pair.getter == "balanceOf(address)"
    assert "reads accounts[account].principal" in pair.getter_basis
    assert pair.initializer == "initialize()"
    assert "guarded by supplyIndex" in pair.initializer_basis


def test_limits_are_reported_and_an_incomplete_trace_is_not_treated_as_safe() -> None:
    hops = MAX_TRACE_DEPTH + 2
    chain = "\n".join(
        f"    function _h{i}(address a, uint256 x) internal {{ _h{i + 1}(a, x); }}"
        for i in range(hops)
    )
    deep = f"""
contract V {{
    IERC20 public immutable token;
    mapping(address => uint256) public credit;
    constructor(IERC20 t) {{ token = t; }}
    function deposit(uint256 amount) external {{ _h0(msg.sender, amount); }}
    function withdraw(uint256 amount) external {{
        credit[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }}
{chain}
    function _h{hops}(address a, uint256 x) internal {{
        token.transferFrom(a, address(this), x);
        credit[a] += x;
    }}
}}
"""
    pairs, notes = _pairs(deep)
    assert pairs == []
    assert any(f"depth limit {MAX_TRACE_DEPTH}" in note for note in notes)
    overloaded = """
contract V {
    IERC20 public immutable token;
    mapping(address => uint256) public credit;
    constructor(IERC20 t) { token = t; }
    function deposit(uint256 amount) external { _in(msg.sender, amount); }
    function withdraw(uint256 amount) external {
        credit[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
    function _in(address a, uint256 x) internal {
        token.transferFrom(a, address(this), x);
        credit[a] += x;
    }
    function _in(uint256 a, uint256 x) internal { credit[address(uint160(a))] += x; }
}
"""
    pairs, notes = _pairs(overloaded)
    assert pairs == []
    assert any("2 overloads" in note and "not followed" in note for note in notes)
    report = custody_report(build_research_model({"V.sol": ERC20 + overloaded}))
    assert report["incomplete_is_not_safe"] is True
    assert report["contracts"]["V"]["pairs"] == []
    assert report["contracts"]["V"]["incomplete"]


def test_an_unresolvable_library_receiver_is_reported() -> None:
    body = """
library L {
    struct P { uint256 shares; }
    function credit(P storage p, uint256 x) internal { p.shares += x; }
}
contract V {
    using L for L.P;
    IERC20 public immutable token;
    L.P[] internal all;
    mapping(address => L.P) internal positions;
    constructor(IERC20 t) { token = t; }
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        all[all.length - 1].credit(amount);
    }
    function withdraw(uint256 amount) external {
        require(positions[msg.sender].shares >= amount);
        token.transfer(msg.sender, amount);
    }
}
"""
    pairs, notes = _pairs(body)
    assert pairs == []
    assert any("library call credit" in note and "not followed" in note for note in notes)


def test_the_struct_twin_plans_the_initializer_and_binds_the_token_through_construction() -> None:
    name, text, model = _fixture("struct_index", "safe")
    hits = [c for c in run_suite(model).candidates if c.detector == DETECTOR]
    (sequence,) = generate(model, hits, sources={name: text}).sequences
    assert sequence.template == "initialize→deposit→deposit→withdraw"
    assert [c.role for c in sequence.calls] == [
        "initialize",
        "deposit",
        "victim_deposit",
        "withdraw",
    ]
    assert dict(sequence.calls[1].arguments)["asset"] == "custodied_token"
    spec = build_property(sequence, model, hits[0])
    assert spec.oracle.probe_role == "withdraw"
    assert spec.oracle.precondition_roles == ("initialize", "deposit", "victim_deposit")
    assert any("initialize() runs first" in item for item in spec.provenance.assumptions)
    harness = build_harness(sequence, model, oracle=spec.oracle, sources={name: text})
    assert harness.buildable, harness.reason
    assert "new StructVault(IERC20(address(bfToken)))" in harness.body
    assert 'abi.encodeWithSignature("initialize()")' in harness.body
