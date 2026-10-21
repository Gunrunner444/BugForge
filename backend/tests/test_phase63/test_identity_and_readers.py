"""Sequence identity and source-backed share readers. No transactions are findings."""

from __future__ import annotations

import textwrap

from app.discovery.bounty.engine_adapters import _judge
from app.discovery.bounty.properties import (
    OracleKind,
    OracleObservation,
    OracleSpec,
    PropertyDeclaration,
    PropertyVerdict,
    build_property,
    evaluate,
)
from app.discovery.bounty.shares import share_accounting
from app.discovery.bounty.vfcs import (
    SequenceIdentity,
    Vfcs,
    VfcsCall,
    generate,
    sequence_id_of,
)
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite

_ERC = """
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
"""


def _src(body: str) -> str:
    return textwrap.dedent(body).strip() + "\n"


def _model(body: str):
    text = _src(body)
    return build_research_model({"Vault.sol": text}), text


def _accounting(model):
    return [item for item in run_suite(model).candidates if item.detector.startswith("accounting.")]


def test_distinct_helpers_keep_distinct_sequence_ids() -> None:
    model, _text = _model(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Pool {{
            IERC20 public immutable token;
            mapping(address => uint256) public book;
            mapping(address => uint256) public bonus;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount, address receiver) external {{
                _book(amount, receiver);
                _bonus(amount, receiver);
            }}
            function _book(uint256 amount, address receiver) internal {{
                require(token.transferFrom(msg.sender, address(this), amount));
                book[receiver] += amount;
            }}
            function _bonus(uint256 amount, address receiver) internal {{
                require(token.transferFrom(msg.sender, address(this), amount));
                bonus[receiver] += amount;
            }}
        }}
        """
    )
    result = generate(model, _accounting(model), SequenceIdentity(campaign_id="id"))
    sequences = [
        item
        for item in result.sequences
        if item.derived_from.startswith("accounting.fee_on_transfer_mismatch@")
    ]
    assert len(sequences) == 2
    assert len({item.sequence_id for item in sequences}) == 2
    helpers = {item.calls[0].entrypoint_for for item in sequences}
    assert helpers == {"_book(uint256,address)", "_bonus(uint256,address)"}
    specs = [build_property(item, model) for item in sequences]
    assert {spec.oracle.getter for spec in specs} == {"book(address)", "bonus(address)"}
    assert all(spec.oracle.executable for spec in specs)


def test_equivalent_variants_of_one_candidate_still_deduplicate() -> None:
    model, _text = _model(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Pool {{
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount) external {{
                _book(amount);
            }}
            function _book(uint256 amount) internal {{
                require(token.transferFrom(msg.sender, address(this), amount));
                credit[msg.sender] += amount;
            }}
        }}
        """
    )
    candidates = _accounting(model)
    assert len(candidates) == 1
    result = generate(model, [candidates[0], candidates[0]], SequenceIdentity(campaign_id="same"))
    assert len(result.sequences) == 1
    assert any("deduplicated" in reason for _key, reason in result.skipped)
    call = VfcsCall("Pool", "deposit(uint256)", "deposit", "attacker", (("amount", "amount_one"),))
    identity = SequenceIdentity(campaign_id="same", compiler_configuration="solc=0.8.20")
    first = sequence_id_of((call,), "deposit", identity, derived_from="candidate")
    assert first == sequence_id_of((call,), "deposit", identity, derived_from="candidate")
    marked = VfcsCall(
        call.contract,
        call.function,
        call.role,
        call.actor,
        call.arguments,
        entrypoint_for="_book(uint256)",
    )
    assert sequence_id_of((marked,), "deposit", identity, derived_from="candidate") != first
    assert sequence_id_of(
        (marked,), "deposit", identity, derived_from="other-candidate"
    ) != sequence_id_of((marked,), "deposit", identity, derived_from="candidate")


def test_public_mapping_and_struct_view_are_share_readers() -> None:
    mapping_model, _text = _model(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract MapVault {{
            IERC20 public immutable token;
            mapping(address => uint256) public shares;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount) external {{
                require(token.transferFrom(msg.sender, address(this), amount));
                shares[msg.sender] += amount;
            }}
        }}
        """
    )
    deposit = next(
        item for item in mapping_model.functions_of("MapVault") if item.name == "deposit"
    )
    info = share_accounting(mapping_model, deposit)
    assert info.share_unit == "accounted_amount"
    assert info.share_reader is not None and info.share_reader.getter == "shares(address)"
    spec = build_property(
        generate(mapping_model, _accounting(mapping_model)).sequences[0], mapping_model
    )
    assert spec.oracle.getter == "shares(address)"
    assert spec.declaration is PropertyDeclaration.PROPERTY_UNDER_TEST

    view_model, _text = _model(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract ViewVault {{
            struct Position {{ mapping(address => uint256) shares; }}
            Position internal p;
            IERC20 public immutable token;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount, address receiver) external {{
                _pull(p, receiver, amount);
            }}
            function _pull(Position storage s, address receiver, uint256 amount) internal {{
                require(token.transferFrom(msg.sender, address(this), amount));
                s.shares[receiver] += amount;
            }}
            function balanceOf(address account) external view returns (uint256) {{
                return _shares(p, account);
            }}
            function _shares(Position storage s, address account) internal view returns (uint256) {{
                return s.shares[account];
            }}
        }}
        """
    )
    helper = next(item for item in view_model.functions_of("ViewVault") if item.name == "_pull")
    viewed = share_accounting(view_model, helper)
    assert viewed.share_reader is not None
    assert viewed.share_reader.getter == "balanceOf(address)"
    assert viewed.share_unit == "accounted_amount"
    view_spec = build_property(
        generate(view_model, _accounting(view_model)).sequences[0], view_model
    )
    assert view_spec.oracle.getter == "balanceOf(address)"
    assert view_spec.oracle.kind is OracleKind.CREDIT_LE_RECEIVED


def test_asset_and_share_exit_amounts_stay_in_their_units() -> None:
    model, _text = _model(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Split {{
            struct Position {{ mapping(address => uint256) shares; }}
            Position internal p;
            IERC20 public immutable asset;
            constructor(IERC20 asset_) {{ asset = asset_; }}
            function deposit(uint256 assets, address receiver) external {{
                require(asset.transferFrom(msg.sender, address(this), assets));
                _mint(p, receiver, assets * 2);
            }}
            function _mint(Position storage s, address account, uint256 amount) internal {{
                s.shares[account] += amount;
            }}
            function withdraw(uint256 assets, address receiver, address owner) external {{
                uint256 idle = asset.balanceOf(address(this));
                uint256 noted = idle;
                require(noted == idle);
                require(assets <= maxWithdraw(owner));
                _burn(p, owner, assets * 2);
                require(asset.transfer(receiver, assets));
            }}
            function redeem(uint256 shares, address receiver, address owner) external {{
                uint256 idle = asset.balanceOf(address(this));
                uint256 noted = idle;
                require(noted == idle);
                _burn(p, owner, shares);
                require(asset.transfer(receiver, shares / 2));
            }}
            function maxWithdraw(address owner) external view returns (uint256) {{
                return balanceOf(owner) / 2;
            }}
            function balanceOf(address account) external view returns (uint256) {{
                return _of(p, account);
            }}
            function _of(Position storage s, address account) internal view returns (uint256) {{
                return s.shares[account];
            }}
            function _burn(Position storage s, address account, uint256 amount) internal {{
                s.shares[account] -= amount;
            }}
        }}
        """
    )
    result = generate(model, _accounting(model), SequenceIdentity(campaign_id="units"))
    exits = {
        item.calls[-1].function: item.calls[-1].arguments
        for item in result.sequences
        if item.template == "deposit→donate→withdraw"
    }
    assert exits["withdraw(uint256,address,address)"][0] == (
        "assets",
        "asset_exit:maxWithdraw(address)",
    )
    assert exits["redeem(uint256,address,address)"][0] == ("shares", "share_balance")
    assert "share_balance" not in {
        value for _name, value in exits["withdraw(uint256,address,address)"]
    }
    assert not any(
        value.startswith("asset_exit:") for _name, value in exits["redeem(uint256,address,address)"]
    )


def test_converted_shares_are_not_compared_with_assets() -> None:
    model, _text = _model(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Converted {{
            struct Position {{ mapping(address => uint256) shares; }}
            Position internal p;
            IERC20 public immutable asset;
            constructor(IERC20 asset_) {{ asset = asset_; }}
            function deposit(uint256 assets, address receiver) external {{
                _pull(p, receiver, assets);
            }}
            function _pull(Position storage s, address receiver, uint256 assets) internal {{
                require(asset.transferFrom(msg.sender, address(this), assets));
                s.shares[receiver] += assets * 2;
            }}
            function balanceOf(address account) external view returns (uint256) {{
                return p.shares[account];
            }}
        }}
        """
    )
    # The credit mentions assets but scales them. Share units are not an asset credit.
    sequences = generate(model, _accounting(model)).sequences
    assert sequences
    spec = build_property(sequences[0], model)
    assert spec.declaration is PropertyDeclaration.PROPERTY_UNSUPPORTED
    assert "not compared" in spec.unsupported_reason or "converted" in spec.unsupported_reason


def test_generated_judge_source_rejects_a_zero_sized_exit() -> None:
    calls = (
        VfcsCall(
            "Vault",
            "deposit(uint256,address)",
            "deposit",
            "attacker",
            (("assets", "amount_one"), ("receiver", "attacker")),
        ),
        VfcsCall("token", "transfer(address,uint256)", "donate", "attacker", (), True, "donation"),
        VfcsCall(
            "Vault",
            "deposit(uint256,address)",
            "victim_deposit",
            "victim",
            (("assets", "amount_one"), ("receiver", "victim")),
        ),
        VfcsCall(
            "Vault",
            "redeem(uint256,address,address)",
            "withdraw",
            "attacker",
            (("shares", "share_balance"), ("receiver", "attacker"), ("owner", "attacker")),
            entrypoint_for="_burn(uint256)",
        ),
    )
    sequence = Vfcs(
        sequence_id="vf_test",
        template="deposit→donate→withdraw",
        origin="test",
        calls=calls,
        property_under_test="sized exit",
        derived_from="accounting.balance_as_deposit@Vault._burn(uint256)",
        identity=SequenceIdentity(campaign_id="judge"),
    )
    oracle = OracleSpec(
        kind=OracleKind.BALANCE_NOT_INCREASED,
        probe_role="withdraw",
        probe_function="redeem(uint256,address,address)",
        precondition_roles=("deposit", "donate", "victim_deposit"),
        getter="balanceOf(address)",
        getter_actor="attacker",
        token_fixture="standard",
    )
    judged, violated = _judge(sequence, oracle) or ("", "")
    assert "bfVal[17][8] == 0" in judged or "bfVal[17][8]==0" in judged.replace(" ", "")
    assert "bfVal[16][1] + bfVal[16][3] > bfVal[16][0] + bfVal[16][2]" in violated.replace("\n", "")

    def observation(**kwargs: object) -> OracleObservation:
        base = dict(
            call_ok=(1, 1, 1, 1),
            readable=True,
            actor_before=4_000,
            actor_after=3_000,
            recipient_before=0,
            recipient_after=0,
            evidence=(("attacker_withdrawal_amount", 1_000),),
        )
        base.update(kwargs)
        return OracleObservation(**base)  # type: ignore[arg-type]

    held = evaluate(sequence, oracle, observation())
    stolen = evaluate(sequence, oracle, observation(actor_after=5_000))
    empty = evaluate(sequence, oracle, observation(evidence=(("attacker_withdrawal_amount", 0),)))
    unread = evaluate(sequence, oracle, observation(evidence=()))
    reverted = evaluate(sequence, oracle, observation(call_ok=(1, 1, 1, 0)))
    assert held.verdict is PropertyVerdict.PROPERTY_HELD
    assert stolen.verdict is PropertyVerdict.PROPERTY_VIOLATED
    assert empty.verdict is PropertyVerdict.NOT_EVALUATED
    assert unread.verdict is PropertyVerdict.NOT_EVALUATED
    assert reverted.verdict is PropertyVerdict.NOT_EVALUATED
    assert "zero" in empty.reason or "not exercised" in empty.reason
