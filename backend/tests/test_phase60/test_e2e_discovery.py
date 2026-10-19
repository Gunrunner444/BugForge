"""Blinded campaign benchmark. Labels stay in this file; the runner never receives them.

This is a local seeded-fixture result. It is not a real-world recall rate.
"""

from __future__ import annotations

import inspect
import json
import textwrap
from pathlib import Path

import pytest

import app.discovery.bounty.service as service_module
from app.core.config import get_settings
from app.discovery.bounty.e2e_benchmark import run_blind_campaign
from app.discovery.bounty.service import BountyCampaignService
from tests.test_phase52.phase52_support import requires_forge

_REPORT = Path("/tmp/bugforge-e2e-benchmark.json")
_BANNED = ("vulnerable", "exploit", "safe.sol", "bug.sol")


def _src(text: str) -> str:
    body = textwrap.dedent(text).strip() + "\n"
    lowered = body.lower()
    for word in _BANNED:
        assert word not in lowered, word
    return body


_ERC = """
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
"""


def _locker(repeatable: bool) -> str:
    guard = ""
    ready = ""
    if not repeatable:
        ready = "    bool public initialized;\n"
        guard = "        require(!initialized);\n        initialized = true;\n"
    return _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        contract Locker {{
            address public entryPoint;
            address public ownerKey;
        {ready}    function validateUserOp(
                bytes calldata,
                bytes32 userOpHash,
                uint256
            ) external returns (uint256) {{
                require(msg.sender == entryPoint);
                address signer = ecrecover(userOpHash, 27, bytes32(0), bytes32(0));
                require(signer == ownerKey);
                return 0;
            }}

            function initialize(address next) external {{
        {guard}        ownerKey = next;
            }}
        }}
        """
    )


def _desk(debits: bool) -> str:
    debit = "        claim[msg.sender] -= amount;\n" if debits else ""
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
        {debit}        require(token.transfer(msg.sender, amount));
            }}
        }}
        """
    )


def _book(measures: bool) -> str:
    body = (
        """
                uint256 beforeBal = asset.balanceOf(address(this));
                require(asset.transferFrom(msg.sender, address(this), amount));
                uint256 got = asset.balanceOf(address(this)) - beforeBal;
                note[msg.sender] += got;
        """
        if measures
        else """
                require(asset.transferFrom(msg.sender, address(this), amount));
                note[msg.sender] += amount;
        """
    )
    return _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Book {{
            IERC20 public immutable asset;
            mapping(address => uint256) public note;
            constructor(IERC20 asset_) {{ asset = asset_; }}
            function fund(uint256 amount) external {{
        {body}    }}
            function release(uint256 amount) external {{
                uint256 owed = note[msg.sender];
                require(owed >= amount);
                note[msg.sender] = owed - amount;
                require(asset.transfer(msg.sender, amount));
            }}
        }}
        """
    )


def _route(debits: bool) -> str:
    debit = "        book[msg.sender] -= amount;\n" if debits else ""
    return _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Route {{
            IERC20 public immutable token;
            mapping(address => uint256) public book;
            constructor(IERC20 token_) {{ token = token_; }}
            function fund(uint256 amount) external {{ _accept(amount); }}
            function release(uint256 amount) external {{ _settle(amount); }}
            function _accept(uint256 amount) internal {{
                uint256 beforeBal = token.balanceOf(address(this));
                require(token.transferFrom(msg.sender, address(this), amount));
                uint256 got = token.balanceOf(address(this)) - beforeBal;
                book[msg.sender] += got;
            }}
            function _settle(uint256 amount) internal {{
                require(book[msg.sender] >= amount);
        {debit}        require(token.transfer(msg.sender, amount));
            }}
        }}
        """
    )


def _position(scaled: bool) -> str:
    paid = "(amount * scale) / 1e18" if scaled else "amount"
    return _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Position {{
            struct Slot {{
                uint128 units;
                uint64 stamp;
                uint64 flags;
            }}
            IERC20 public immutable token;
            uint256 public scale;
            mapping(address => Slot) internal slots;
            constructor(IERC20 token_) {{ token = token_; }}
            function prepare() external {{
                if (scale != 0) revert();
                scale = 15e17;
            }}
            function quote(address account) public view returns (uint256) {{
                return (uint256(slots[account].units) * scale) / 1e18;
            }}
            function fund(uint256 amount) external {{
                Slot memory slot = slots[msg.sender];
                slot.units += uint128((amount * 1e18) / scale);
                slots[msg.sender] = slot;
                require(token.transferFrom(msg.sender, address(this), amount));
            }}
            function release(uint256 amount) external {{
                Slot memory slot = slots[msg.sender];
                uint128 burned = uint128((amount * 1e18) / scale);
                require(slot.units >= burned);
                slot.units -= burned;
                slots[msg.sender] = slot;
                require(token.transfer(msg.sender, {paid}));
            }}
        }}
        """
    )


def _pool(offset: bool) -> str:
    minted = (
        "(amount * (supply + 1000)) / (assets + 1000)" if offset else "(amount * supply) / assets"
    )
    out = (
        "(shareAmount * (assets + 1000)) / (totalUnits + 1000)"
        if offset
        else "(shareAmount * assets) / totalUnits"
    )
    first = "amount" if not offset else "amount"
    minted_expr = f"supply == 0 ? {first} : {minted}"
    return _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Pool {{
            IERC20 public asset;
            uint256 public totalUnits;
            mapping(address => uint256) public units;
            constructor(IERC20 asset_) {{ asset = asset_; }}
            function join(uint256 amount) external {{
                uint256 assets = asset.balanceOf(address(this));
                uint256 supply = totalUnits;
                uint256 minted = {minted_expr};
                require(asset.transferFrom(msg.sender, address(this), amount));
                units[msg.sender] += minted;
                totalUnits += minted;
            }}
            function leave(uint256 shareAmount) external {{
                uint256 assets = asset.balanceOf(address(this));
                uint256 out = {out};
                units[msg.sender] -= shareAmount;
                totalUnits -= shareAmount;
                require(asset.transfer(msg.sender, out));
            }}
        }}
        """
    )


def _binder() -> str:
    return _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Binder {{
            IERC20 public token;
            address public immutable owner;
            mapping(address => uint256) public claim;
            constructor() {{ owner = msg.sender; }}
            function setToken(IERC20 token_) external {{
                require(msg.sender == owner);
                token = token_;
            }}
            function fund(uint256 amount) external {{
                require(token.transferFrom(msg.sender, address(this), amount));
                claim[msg.sender] += amount;
            }}
            function release(uint256 amount) external {{
                require(claim[msg.sender] >= amount);
                require(token.transfer(msg.sender, amount));
            }}
        }}
        """
    )


# Evaluator-only. None of these fields are passed into run_blind_campaign.
_PAIRS = (
    {
        "pair_id": "seed-01",
        "economic_class": "unprotected initializer",
        "family": "initialization",
        "contract": "Locker",
        "filename": "locker.sol",
        "detector": "aa.unprotected_account_initializer",
        "planted": _locker(True),
        "control": _locker(False),
        "control_emits": False,
    },
    {
        "pair_id": "seed-02",
        "economic_class": "withdrawal omits a debit",
        "family": "solvency",
        "contract": "Desk",
        "filename": "desk.sol",
        "detector": "conservation.round_trip_value",
        "planted": _desk(False),
        "control": _desk(True),
        "control_emits": True,
    },
    {
        "pair_id": "seed-03",
        "economic_class": "credited amount exceeds tokens received",
        "family": "token_movement",
        "contract": "Book",
        "filename": "book.sol",
        "detector": "accounting.fee_on_transfer_mismatch",
        "planted": _book(False),
        "control": _book(True),
        "control_emits": False,
    },
    {
        "pair_id": "seed-04",
        "economic_class": "omitted debit through an internal helper",
        "family": "solvency",
        "contract": "Route",
        "filename": "route.sol",
        "detector": "conservation.round_trip_value",
        "planted": _route(False),
        "control": _route(True),
        "control_emits": True,
    },
    {
        "pair_id": "seed-05",
        "economic_class": "struct index scales the payout",
        "family": "solvency",
        "contract": "Position",
        "filename": "position.sol",
        "detector": "conservation.round_trip_value",
        "planted": _position(True),
        "control": _position(False),
        "control_emits": True,
    },
    {
        "pair_id": "seed-06",
        "economic_class": "donation moves the share price",
        "family": "solvency",
        "contract": "Pool",
        "filename": "pool.sol",
        "detector": "accounting.donation_share_price",
        "planted": _pool(False),
        "control": _pool(True),
        "control_emits": True,
    },
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


def _case(
    service: BountyCampaignService, root: Path, filename: str, contract: str, source: str
) -> dict[str, object]:
    root.mkdir(parents=True)
    (root / filename).write_text(source, encoding="utf-8")
    assert "vulnerable" not in filename and "safe" not in filename
    return run_blind_campaign(
        service,
        repo_root=root,
        files=(filename,),
        contract=contract,
        rounds=1,
    )


def _rows(report: dict[str, object]) -> list[dict[str, object]]:
    execution = report["execution"]
    assert isinstance(execution, dict)
    sequences = report["sequences"]
    assert isinstance(sequences, dict)
    rows = []
    for item in execution["observations"]:
        assert isinstance(item, dict)
        meta = sequences.get(item["sequence_id"], {})
        assert isinstance(meta, dict)
        rows.append(
            {
                "outcome": item["outcome"],
                "reason": item.get("reason", ""),
                "reason_code": item.get("reason_code", ""),
                "verdict": item.get("verdict", ""),
                "verified": item.get("verified"),
                "strong_candidate": item.get("strong_candidate"),
                "declaration": item.get("declaration", ""),
                "derived_from": meta.get("derived_from", ""),
                "template": meta.get("template", ""),
                "sequence_id": item["sequence_id"],
                "evaluation": item.get("evaluation"),
                "result": item.get("result"),
            }
        )
    return rows


def _detectors(report: dict[str, object]) -> set[str]:
    return {str(item["detector"]) for item in report["candidates"]}  # type: ignore[index]


def _of(rows: list[dict[str, object]], detector: str) -> list[dict[str, object]]:
    return [row for row in rows if str(row["derived_from"]).startswith(detector + "@")]


@requires_forge
def test_blind_campaigns_distinguish_seeded_pairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, monkeypatch)
    measured: list[dict[str, object]] = []
    gap_record: dict[str, object] | None = None
    try:
        for index, pair in enumerate(_PAIRS):
            planted = _case(
                service,
                tmp_path / f"planted-{index}",
                str(pair["filename"]),
                str(pair["contract"]),
                str(pair["planted"]),
            )
            control = _case(
                service,
                tmp_path / f"control-{index}",
                str(pair["filename"]),
                str(pair["contract"]),
                str(pair["control"]),
            )
            planted_rows = _rows(planted)
            control_rows = _rows(control)
            detector = str(pair["detector"])
            planted_hits = _of(planted_rows, detector)
            control_hits = _of(control_rows, detector)
            planted_violations = [
                row for row in planted_hits if row["outcome"] == "property_violated"
            ]
            control_violations = [
                row for row in control_rows if row["outcome"] == "property_violated"
            ]
            control_held = [row for row in control_hits if row["outcome"] == "property_held"]
            distinguished = bool(planted_violations) and not control_violations
            if pair["control_emits"]:
                distinguished = distinguished and bool(control_held)
            else:
                distinguished = distinguished and detector not in _detectors(control)
            measured.append(
                {
                    "pair_id": pair["pair_id"],
                    "economic_class": pair["economic_class"],
                    "family": pair["family"],
                    "detector_emitted_on_planted": detector in _detectors(planted),
                    "detector_emitted_on_control": detector in _detectors(control),
                    "planted_outcomes": sorted({str(row["outcome"]) for row in planted_hits}),
                    "control_outcomes": sorted({str(row["outcome"]) for row in control_hits}),
                    "control_any_violation": bool(control_violations),
                    "distinguished": distinguished,
                    "manual_assistance": False,
                    "planted_violation": planted_violations[0] if planted_violations else None,
                    "planted": _public(planted),
                    "control": _public(control),
                }
            )
        gap = _case(service, tmp_path / "gap", "binder.sol", "Binder", _binder())
        gap_rows = _rows(gap)
        gap_record = {
            "pair_id": "seed-07",
            "economic_class": "token bound after construction",
            "family": "solvency",
            "tracked_gap": True,
            "outcomes": sorted({str(row["outcome"]) for row in gap_rows}),
            "reason_codes": sorted({str(row["reason_code"]) for row in gap_rows}),
            "property_violated": any(row["outcome"] == "property_violated" for row in gap_rows),
            "manual_assistance": False,
            "report": _public(gap),
        }
    finally:
        if measured or gap_record is not None:
            _REPORT.write_text(
                json.dumps(
                    {
                        "local_seeded_fixture": True,
                        "pairs": measured,
                        "gap": gap_record,
                    },
                    indent=2,
                    default=str,
                ),
                encoding="utf-8",
            )
    distinguished = [item for item in measured if item["distinguished"]]
    families = {str(item["family"]) for item in distinguished}
    classes = {str(item["economic_class"]) for item in distinguished}
    assert len(distinguished) >= 5, [
        (item["pair_id"], item["planted_outcomes"], item["control_outcomes"]) for item in measured
    ]
    assert len(classes) >= 4
    assert {"initialization", "solvency", "token_movement"} <= families
    for item in measured:
        assert item["detector_emitted_on_planted"] is True
        assert item["manual_assistance"] is False
        assert item["distinguished"] is True, item["pair_id"]
        violation = item["planted_violation"]
        assert isinstance(violation, dict)
        assert violation["verified"] is False
        assert violation["strong_candidate"] is True
        assert violation["declaration"] == "property_under_test"
    assert gap_record["property_violated"] is False
    assert "unbound_token" in gap_record["reason_codes"]
    assert all(item["verified"] is False for item in gap_record["report"]["findings"])  # type: ignore[index]


def _public(report: dict[str, object]) -> dict[str, object]:
    """Drop nothing the evaluator needs; the campaign output is already unlabeled."""
    execution = report["execution"]
    assert isinstance(execution, dict)
    return {
        "source_hashes": report["source_hashes"],
        "compiler": report["compiler"],
        "compiler_fingerprint": report["compiler_fingerprint"],
        "candidate_budget": report["candidate_budget"],
        "candidates": report["candidates"],
        "sequences": report["sequences"],
        "sequence_skipped": report["sequence_skipped"],
        "outcomes": execution["outcomes"],
        "skipped": execution["skipped"],
        "forge_runs": execution["forge_runs"],
        "observations": execution["observations"],
        "minimized": execution["minimized"],
        "independent_checks": execution["independent_checks"],
        "feedback": execution["feedback"],
        "findings": [
            {
                "detector": item["detector"],
                "qualification": item["qualification"],
                "candidate_strength": item["candidate_strength"],
                "poc_status": item["poc_status"],
                "confirmed_severity": item["confirmed_severity"],
                "verified": item["verified"],
                "execution_status": item["execution_status"],
            }
            for item in report["findings"]  # type: ignore[union-attr]
        ],
        "verified": False,
    }
