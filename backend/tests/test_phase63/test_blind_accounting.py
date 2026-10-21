"""Blinded campaigns judge share accounting. The runner receives source text only."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

import app.discovery.bounty.service as service_module
from app.core.config import get_settings
from app.discovery.bounty.e2e_benchmark import run_blind_campaign
from app.discovery.bounty.service import BountyCampaignService
from tests.test_phase52.phase52_support import requires_forge


def _src(text: str) -> str:
    return textwrap.dedent(text).strip() + "\n"


def _vault(credit: str, *, exit_body: str = "") -> str:
    exit_fn = (
        exit_body
        or """
            function redeem(uint256 shares, address receiver, address owner) external {
                uint256 idle = token.balanceOf(address(this));
                uint256 noted = idle;
                require(noted == idle);
                _burn(p, owner, shares);
                require(token.transfer(receiver, shares));
            }
            function _burn(Position storage s, address account, uint256 amount) internal {
                s.shares[account] -= amount;
            }
        """
    )
    return _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        interface IERC20 {{
            function transfer(address to, uint256 amount) external returns (bool);
            function transferFrom(address from, address to, uint256 amount) external returns (bool);
            function balanceOf(address account) external view returns (uint256);
        }}
        contract Vault {{
            struct Position {{ mapping(address => uint256) shares; }}
            Position internal p;
            IERC20 public immutable token;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 assets, address receiver) external {{
                _pull(p, receiver, assets);
            }}
            function _pull(Position storage s, address receiver, uint256 assets) internal {{
                require(token.transferFrom(msg.sender, address(this), assets));
                {credit}
            }}
            function balanceOf(address account) external view returns (uint256) {{
                return _shares(p, account);
            }}
            function _shares(Position storage s, address account) internal view returns (uint256) {{
                return s.shares[account];
            }}
            {exit_fn}
        }}
        """
    )


def _service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> BountyCampaignService:
    monkeypatch.setattr(
        get_settings(),
        "bounty_campaign_database_url",
        f"sqlite:///{tmp_path / 'campaigns.sqlite'}",
        raising=False,
    )
    monkeypatch.setattr(service_module, "_SERVICE", None, raising=False)
    return BountyCampaignService()


def _run(service: BountyCampaignService, root: Path, source: str) -> dict[str, object]:
    root.mkdir(parents=True, exist_ok=True)
    (root / "Vault.sol").write_text(source, encoding="utf-8")
    report = run_blind_campaign(
        service,
        repo_root=root,
        files=("Vault.sol",),
        contract="Vault",
        rounds=1,
    )
    assert report["verified"] is False
    return report


def _rows(report: dict[str, object], prefix: str) -> list[dict[str, object]]:
    execution = report["execution"]
    sequences = report["sequences"]
    assert isinstance(execution, dict) and isinstance(sequences, dict)
    rows = []
    for item in execution["observations"]:
        assert isinstance(item, dict)
        meta = sequences.get(str(item["sequence_id"]), {})
        assert isinstance(meta, dict)
        if str(meta.get("derived_from", "")).startswith(prefix):
            rows.append({**item, "calls": meta.get("calls", []), "template": meta.get("template")})
    return rows


@requires_forge
def test_public_mapping_credit_is_judged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _src(
        """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        interface IERC20 {
            function transferFrom(address from, address to, uint256 amount) external returns (bool);
            function balanceOf(address account) external view returns (uint256);
        }
        contract MapVault {
            IERC20 public immutable token;
            mapping(address => uint256) public shares;
            constructor(IERC20 token_) { token = token_; }
            function deposit(uint256 amount) external {
                require(token.transferFrom(msg.sender, address(this), amount));
                shares[msg.sender] += amount - ((amount * 100) / 10000);
            }
        }
        """
    )
    root = tmp_path / "map"
    root.mkdir()
    (root / "MapVault.sol").write_text(source, encoding="utf-8")
    report = run_blind_campaign(
        _service(tmp_path, monkeypatch),
        repo_root=root,
        files=("MapVault.sol",),
        contract="MapVault",
        rounds=1,
    )
    rows = _rows(report, "accounting.fee_on_transfer_mismatch@")
    assert rows
    assert all(row["outcome"] != "compile_failed" for row in rows)
    assert any(row["verdict"] == "property_held" for row in rows)
    assert not any(row["outcome"] == "property_violated" for row in rows)


@requires_forge
def test_struct_reader_distinguishes_excess_shares_from_the_control(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, monkeypatch)
    planted = _vault("s.shares[receiver] += assets;")
    control = _vault("s.shares[receiver] += assets - ((assets * 100) / 10000);")
    # The exit is present so a position can be redeemed; the fee property is the deposit.
    planted_rows = _rows(
        _run(service, tmp_path / "planted", planted), "accounting.fee_on_transfer_mismatch@"
    )
    control_rows = _rows(
        _run(service, tmp_path / "control", control), "accounting.fee_on_transfer_mismatch@"
    )
    assert planted_rows and control_rows
    assert any(row["outcome"] == "property_violated" for row in planted_rows)
    assert any(row["verdict"] == "property_held" for row in control_rows)
    assert not any(row["outcome"] == "property_violated" for row in control_rows)


@requires_forge
def test_deposit_then_redeem_uses_the_share_balance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _vault("s.shares[receiver] += assets - ((assets * 100) / 10000);")
    report = _run(_service(tmp_path, monkeypatch), tmp_path / "round", source)
    rows = _rows(report, "accounting.balance_as_deposit@")
    assert rows, report["sequence_skipped"]
    assert any(row["template"] == "deposit→donate→withdraw" for row in rows)
    sized = False
    for row in rows:
        calls = row["calls"]
        assert isinstance(calls, list)
        exit_call = calls[-1]
        assert isinstance(exit_call, dict)
        arguments = exit_call["arguments"]
        assert isinstance(arguments, list)
        assert ["shares", "share_balance"] in arguments
        assert exit_call["function"].startswith("redeem(")
        sized = True
        assert row["outcome"] != "compile_failed"
    assert sized
    assert any(row["verdict"] == "property_held" for row in rows)
    assert not any(row["outcome"] == "property_violated" for row in rows)


@requires_forge
def test_failed_setup_is_not_a_held_property(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, monkeypatch)
    missing = _src(
        """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        interface IERC20 {
            function transferFrom(address from, address to, uint256 amount) external returns (bool);
        }
        contract Vault {
            IERC20 public immutable token;
            mapping(address => uint256) private shares;
            constructor(IERC20 token_) { token = token_; }
            function deposit(uint256 amount) external {
                require(token.transferFrom(msg.sender, address(this), amount));
                shares[msg.sender] += amount;
            }
        }
        """
    )
    wrong = _src(
        """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        interface IERC20 {
            function transferFrom(address from, address to, uint256 amount) external returns (bool);
            function balanceOf(address account) external view returns (uint256);
        }
        contract Vault {
            struct Position { mapping(address => uint256) shares; }
            Position internal p;
            IERC20 public immutable token;
            constructor(IERC20 token_) { token = token_; }
            function deposit(uint256 assets, address receiver) external {
                _pull(p, receiver, assets);
            }
            function _pull(Position storage s, address receiver, uint256 assets) internal {
                require(token.transferFrom(msg.sender, address(this), assets));
                s.shares[receiver] += assets;
            }
            function balanceOf(address account) external view returns (uint256) {
                return token.balanceOf(account);
            }
        }
        """
    )
    zero = _vault("s.shares[receiver] += assets - assets;")
    reverted = _vault(
        "s.shares[receiver] += assets;",
        exit_body="""
            function redeem(uint256 shares, address receiver, address owner) external {
                uint256 idle = token.balanceOf(address(this));
                uint256 noted = idle;
                require(noted == idle);
                require(false);
                _burn(p, owner, shares);
                require(token.transfer(receiver, shares));
            }
            function _burn(Position storage s, address account, uint256 amount) internal {
                s.shares[account] -= amount;
            }
        """,
    )
    for name, source, prefix in (
        ("missing", missing, "accounting.fee_on_transfer_mismatch@"),
        ("wrong", wrong, "accounting.fee_on_transfer_mismatch@"),
        ("zero", zero, "accounting.balance_as_deposit@"),
        ("reverted", reverted, "accounting.balance_as_deposit@"),
    ):
        report = _run(service, tmp_path / name, source)
        rows = _rows(report, prefix)
        assert rows, (name, report["sequence_skipped"], report["candidates"])
        assert not any(row["outcome"] == "property_violated" for row in rows)
        assert not any(row["verdict"] == "property_held" for row in rows), name
