"""Blinded campaigns distinguish an internal helper from its safe twin.

The runner receives source text only. Detector, property, sequence, and label
stay in this file.
"""

from __future__ import annotations

import inspect
import textwrap
from pathlib import Path

import pytest

import app.discovery.bounty.service as service_module
from app.core.config import get_settings
from app.discovery.bounty.e2e_benchmark import run_blind_campaign
from app.discovery.bounty.service import BountyCampaignService
from tests.test_phase52.phase52_support import requires_forge

_ERC = """
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
"""


def _src(text: str) -> str:
    return textwrap.dedent(text).strip() + "\n"


def _direct(full_credit: bool) -> str:
    credit = (
        "credit[receiver] += amount;"
        if full_credit
        else "credit[receiver] += amount - ((amount * 100) / 10000);"
    )
    return _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Pool {{
            struct Bag {{ uint256 n; }}
            Bag internal bag;
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount, address receiver) external {{
                _book(bag, receiver, amount);
            }}
            function _book(Bag storage b, address receiver, uint256 amount) internal {{
                b.n = amount;
                require(token.transferFrom(msg.sender, address(this), amount));
                {credit}
            }}
        }}
        """
    )


def _staged(full_credit: bool) -> str:
    credit = (
        "credit[receiver] += amount;"
        if full_credit
        else "credit[receiver] += amount - ((amount * 100) / 10000);"
    )
    return _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Shelf {{
            struct Bag {{ uint256 n; }}
            Bag internal bag;
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount, address receiver) external {{
                _stage(bag, receiver, amount);
            }}
            function _stage(Bag storage b, address receiver, uint256 amount) internal {{
                _book(b, receiver, amount);
            }}
            function _book(Bag storage b, address receiver, uint256 amount) internal {{
                require(token.transferFrom(msg.sender, address(this), amount));
                {credit}
            }}
        }}
        """
    )


def test_the_blind_runner_accepts_no_answer_arguments() -> None:
    params = set(inspect.signature(run_blind_campaign).parameters)
    assert params.isdisjoint(
        {"detector", "property", "sequence", "verdict", "label", "vulnerable", "family"}
    )


def _service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> BountyCampaignService:
    database = tmp_path / "campaigns.sqlite"
    monkeypatch.setattr(
        get_settings(),
        "bounty_campaign_database_url",
        f"sqlite:///{database}",
        raising=False,
    )
    monkeypatch.setattr(service_module, "_SERVICE", None, raising=False)
    return BountyCampaignService()


def _run(service: BountyCampaignService, root: Path, name: str, contract: str, source: str):
    root.mkdir(parents=True)
    (root / name).write_text(source, encoding="utf-8")
    return run_blind_campaign(
        service,
        repo_root=root,
        files=(name,),
        contract=contract,
        rounds=1,
    )


def _fee_rows(report: dict[str, object]) -> list[dict[str, object]]:
    execution = report["execution"]
    sequences = report["sequences"]
    assert isinstance(execution, dict)
    assert isinstance(sequences, dict)
    rows = []
    for item in execution["observations"]:
        assert isinstance(item, dict)
        meta = sequences.get(item["sequence_id"], {})
        assert isinstance(meta, dict)
        derived = str(meta.get("derived_from", ""))
        if not derived.startswith("accounting.fee_on_transfer_mismatch@"):
            continue
        rows.append(
            {"outcome": item["outcome"], "reason_code": item.get("reason_code", ""), **meta}
        )
    return rows


@requires_forge
@pytest.mark.parametrize(
    ("contract", "filename", "planted", "control"),
    [
        ("Pool", "pool.sol", _direct(True), _direct(False)),
        ("Shelf", "shelf.sol", _staged(True), _staged(False)),
    ],
)
def test_blind_campaign_distinguishes_an_internal_helper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    contract: str,
    filename: str,
    planted: str,
    control: str,
) -> None:
    service = _service(tmp_path, monkeypatch)
    planted_report = _run(service, tmp_path / "planted", filename, contract, planted)
    control_report = _run(service, tmp_path / "control", filename, contract, control)
    for report in (planted_report, control_report):
        rows = _fee_rows(report)
        assert rows, report["candidates"]
        for row in rows:
            calls = row["calls"]
            assert isinstance(calls, list)
            assert calls[0]["function"].startswith("deposit(")
            assert calls[0]["entrypoint_for"].startswith("_book(")
            assert calls[0]["contract"] == contract
            assert row["call_path"]
            assert row["outcome"] != "compile_failed"
    planted_rows = _fee_rows(planted_report)
    control_rows = _fee_rows(control_report)
    assert any(row["outcome"] == "property_violated" for row in planted_rows)
    assert any(row["outcome"] == "property_held" for row in control_rows)
    assert not any(row["outcome"] == "property_violated" for row in control_rows)
