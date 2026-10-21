"""Python and in-EVM judges on one executed plan.

The production Foundry run supplies the plan. ``compare_judges`` runs that plan
through the engine harness and judges the engine events twice: ``evaluate`` in
Python, and ``_bfJudged`` / ``_bfViolated`` in the EVM. Neither verdict is copied
from the other. An oracle the engine cannot express is recorded as unsupported.
"""

from __future__ import annotations

import textwrap

from app.discovery.bounty.applicability import reconcile_identity
from app.discovery.bounty.findings import is_strong
from app.discovery.bounty.properties import PropertyDeclaration, build_property
from app.discovery.bounty.stateful import K_ACTOR, Outcome, StatefulExecutor
from app.discovery.bounty.vfcs import SequenceIdentity, generate, stamp_source_identity
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite
from tests.test_phase52.phase52_support import requires_forge
from tests.test_phase64.judge_diff import compare_judges, verdict_class

pytestmark = requires_forge

_ERC = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""


def _src(body: str) -> str:
    return textwrap.dedent(body).strip() + "\n"


def _rows(source: str, detector: str, *, filename: str = "Desk.sol", contract: str = "Desk"):
    files = {filename: source}
    model = build_research_model(files)
    found = [item for item in run_suite(model).candidates if item.detector == detector]
    assert found, [item.detector for item in run_suite(model).candidates]
    generated = generate(model, found, SequenceIdentity(campaign_id="diff"), sources=files)
    assert generated.sequences, generated.skipped
    executor = StatefulExecutor()
    rows = []
    for sequence in generated.sequences:
        bound = stamp_source_identity(sequence, files)
        spec = build_property(bound, model, found[0])
        observed = executor.execute(bound, model, files, spec=spec)
        compared = compare_judges(observed, bound, files)
        rows.append(
            {
                "template": sequence.template,
                "sequence": bound,
                "spec": spec,
                "observed": observed,
                "compared": compared,
                "calls": tuple((call.role, call.actor, call.arguments) for call in sequence.calls),
            }
        )
    return rows


def _one(rows: list[dict[str, object]], template: str) -> dict[str, object]:
    return next(row for row in rows if row["template"] == template)


def _agree(row: dict[str, object]) -> dict[str, object]:
    compared = row["compared"]
    assert isinstance(compared, dict)
    assert compared.get("supported") is True, compared
    assert compared.get("compiled") is True, compared
    python_class = verdict_class(str(compared["python_verdict"]))
    evm_class = verdict_class(str(compared["evm_verdict"]))
    production_class = verdict_class(str(compared["production_verdict"]))
    assert python_class == evm_class, compared
    assert production_class == evm_class, compared
    if python_class == "not_evaluated":
        assert evm_class == "not_evaluated"
    return compared


def _report(body: str, *, extra: str = "") -> str:
    from tests.test_phase64.test_reported_execution import _desk

    return _desk(body, extra=extra)


def _round(debits: bool) -> str:
    debit = "claim[msg.sender] -= amount;" if debits else ""
    return _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Desk {{
            IERC20 public immutable token;
            mapping(address => uint256) public claim;
            constructor(IERC20 token_) {{ token = token_; }}
            function fund(uint256 amount) external {{
                uint256 beforeBal = token.balanceOf(address(this));
                require(token.transferFrom(msg.sender, address(this), amount));
                uint256 got = token.balanceOf(address(this)) - beforeBal;
                claim[msg.sender] += got;
            }}
            function release(uint256 amount) external {{
                require(claim[msg.sender] >= amount);
                {debit}
                require(token.transfer(msg.sender, amount));
            }}
        }}
        """
    )


def test_held_and_violated_reports_agree() -> None:
    held = _agree(
        _one(
            _rows(_report("data.accounted = live;"), "accounting.reported_balance"),
            "donate→report",
        )
    )
    violated = _agree(
        _one(
            _rows(_report("data.accounted = live * 2;"), "accounting.reported_balance"),
            "donate→report",
        )
    )
    assert verdict_class(str(held["evm_verdict"])) == "held"
    assert verdict_class(str(violated["evm_verdict"])) == "violated"


def test_unauthorized_revert_is_judged_and_a_failed_role_is_not() -> None:
    authorized = _rows(_report("data.accounted = live;"), "accounting.reported_balance")
    caller = _agree(_one(authorized, "unauthorized-report"))
    assert verdict_class(str(caller["evm_verdict"])) == "held"
    assert "caller check" in str(_one(authorized, "unauthorized-report")["observed"].reason) or (
        _one(authorized, "unauthorized-report")["observed"].outcome is Outcome.PROPERTY_HELD
    )
    source = _report("data.accounted = live;").replace(
        "function keeper() external view returns (address) { return data.keeper; }",
        "function keeper() external view returns (address) { if (data.keeper == address(0)) "
        "return address(0); revert(); }",
    )
    blocked_row = _one(_rows(source, "accounting.reported_balance"), "donate→report")
    blocked = _agree(blocked_row)
    assert verdict_class(str(blocked["evm_verdict"])) == "not_evaluated"
    assert blocked_row["observed"].reason_code == "role_unconfirmed"


def _share_vault(deposit_tail: str) -> str:
    return _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Desk {{
            struct Position {{ mapping(address => uint256) shares; }}
            Position internal p;
            IERC20 public immutable token;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 assets, address receiver) external {{
                _pull(p, receiver, assets);
            }}
            function _pull(Position storage s, address receiver, uint256 assets) internal {{
                require(token.transferFrom(msg.sender, address(this), assets));
                s.shares[receiver] += assets;
                {deposit_tail}
            }}
            function balanceOf(address account) external view returns (uint256) {{
                return _shares(p, account);
            }}
            function _shares(Position storage s, address account) internal view returns (uint256) {{
                return s.shares[account];
            }}
            function redeem(uint256 shares, address receiver, address owner) external {{
                uint256 idle = token.balanceOf(address(this));
                uint256 noted = idle;
                require(noted == idle);
                _burn(p, owner, shares);
                require(token.transfer(receiver, shares));
            }}
            function _burn(Position storage s, address account, uint256 amount) internal {{
                s.shares[account] -= amount;
            }}
        }}
        """
    )


def test_reverted_setup_and_zero_exit_are_not_evaluated() -> None:
    for source in (_share_vault("revert();"), _share_vault("s.shares[receiver] = 0;")):
        row = _one(
            _rows(source, "accounting.balance_as_deposit"),
            "deposit→donate→withdraw",
        )
        compared = _agree(row)
        assert verdict_class(str(compared["evm_verdict"])) == "not_evaluated"
        assert row["observed"].outcome is not Outcome.PROPERTY_HELD


def test_second_payout_distinguishes_a_repeat_release() -> None:
    safe = _agree(
        _one(
            _rows(_round(True), "conservation.round_trip_value"),
            "deposit→deposit→withdraw→withdraw",
        )
    )
    stolen = _agree(
        _one(
            _rows(_round(False), "conservation.round_trip_value"),
            "deposit→deposit→withdraw→withdraw",
        )
    )
    assert verdict_class(str(safe["evm_verdict"])) == "held"
    assert verdict_class(str(stolen["evm_verdict"])) == "violated"


def test_alternate_recipient_receives_the_exit_and_both_judges_agree() -> None:
    source = _share_vault("")
    row = _one(_rows(source, "accounting.balance_as_deposit"), "deposit→donate→withdraw")
    exit_call = next(call for call in row["calls"] if call[0] == "withdraw")  # type: ignore[index]
    assert ("receiver", "recipient") in exit_call[2]
    compared = _agree(row)
    assert verdict_class(str(compared["evm_verdict"])) == "held"
    observed = row["observed"]
    events = observed.result.events if observed.result is not None else ()
    recipient = {
        index: value for kind, index, value in events if kind == K_ACTOR and index in {2, 3}
    }
    assert recipient.get(3, 0) > recipient.get(2, 0)


def test_unsupported_oracles_are_not_called_agreement() -> None:
    opaque = _report("data.accounted = 1;")
    # A stored constant is not a report. The converted-share credit is an oracle
    # the builders refuse. Neither is an executed agreement between the judges.
    converted = _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Desk {{
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
    files = {"Desk.sol": converted}
    model = build_research_model(files)
    found = [
        item for item in run_suite(model).candidates if item.detector.startswith("accounting.")
    ]
    generated = generate(model, found, SequenceIdentity(campaign_id="units"), sources=files)
    unsupported = None
    for sequence in generated.sequences:
        candidate = next(
            item
            for item in found
            if sequence.derived_from.startswith(f"{item.detector}@{item.contract}.{item.function}")
        )
        spec = build_property(sequence, model, candidate)
        if spec.declaration is PropertyDeclaration.PROPERTY_UNSUPPORTED:
            unsupported = (sequence, spec, candidate)
            break
    assert unsupported is not None, [
        (item.template, build_property(item, model).declaration.value)
        for item in generated.sequences
    ]
    sequence, spec, _candidate = unsupported
    observed = StatefulExecutor().execute(
        stamp_source_identity(sequence, files), model, files, spec=spec
    )
    compared = compare_judges(observed, sequence, files)
    assert compared["supported"] is False
    assert "cannot express" in str(compared["reason"]) or "not built" in str(compared["reason"])
    assert observed.outcome is not Outcome.PROPERTY_VIOLATED
    hits = [
        item
        for item in run_suite(build_research_model({"Desk.sol": opaque})).candidates
        if item.detector == "accounting.reported_balance"
    ]
    assert hits == []


def test_identity_mismatch_blocks_a_candidate_the_judges_still_agree_on() -> None:
    row = _one(
        _rows(_report("data.accounted = live * 2;"), "accounting.reported_balance"), "donate→report"
    )
    compared = _agree(row)
    assert verdict_class(str(compared["evm_verdict"])) == "violated"
    observed = row["observed"]
    record = {
        "outcome": "property_violated",
        "declaration": "property_under_test",
        "verdict": "property_violated",
        "oracle_kind": observed.oracle_kind,
        "identity_status": "identity_mismatch",
        "stale": False,
        "token_fixture": "standard",
        "applicability": reconcile_identity(
            row["spec"].applicability, "identity_mismatch"
        ).as_dict(),
    }
    assert record["applicability"]["disposition"] != "target_applicable"
    assert is_strong(record) is False
    # The judges above agreed. They do not read campaign identity.
    assert verdict_class(str(compared["python_verdict"])) == "violated"
