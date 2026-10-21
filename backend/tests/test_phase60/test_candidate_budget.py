"""The suite budget must not discard a late high-value candidate before ranking."""

from __future__ import annotations

from pathlib import Path

from app.discovery.bounty.analysis import analyze_campaign
from app.discovery.bounty.source_selection import SourceSelection
from app.parsing.solidity_account_abstraction import account_abstraction_present
from app.parsing.solidity_modules import modules_present
from app.parsing.solidity_research_suite import FAMILIES, MAX_TOTAL_CANDIDATES
from tests.test_phase50.phase50_support import manifest

_DONATION = "accounting.donation_share_price"
_ERC20 = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""


def _sources() -> dict[str, str]:
    arithmetic = [
        "pragma solidity ^0.8.20;",
        "contract FillA {",
    ]
    for index in range(64):
        arithmetic.append(
            f"    function a{index}(uint256 x) external {{"
            f" uint128 y = uint128(x * 2); payable(msg.sender).transfer(y); }}"
        )
    arithmetic.append("}")
    eoa = ["pragma solidity ^0.8.20;", "contract FillB {"]
    for index in range(64):
        eoa.append(
            f'    function b{index}() external {{ require(msg.sender == tx.origin, "eoa"); }}'
        )
    eoa.append("}")
    message = [
        "pragma solidity ^0.8.20;",
        "interface IE {",
        "    function recover(bytes32 digest, bytes calldata sig) external pure returns (address);",
        "}",
        "contract FillC {",
        "    IE public keys;",
    ]
    for index in range(64):
        message.append(
            f"    function c{index}(address to, uint256 amount, bytes calldata sig) external {{"
            " bytes32 digest = keccak256(abi.encodePacked(amount));"
            ' require(keys.recover(digest, sig) == address(this), "sig");'
            " payable(to).transfer(amount); }"
        )
    message.append("}")
    custody = ["pragma solidity ^0.8.20;", _ERC20]
    for index in range(64):
        custody.append(
            f"""
contract C{index} {{
    IERC20 public immutable token;
    mapping(address => uint256) public credit;
    constructor(IERC20 token_) {{ token = token_; }}
    function deposit(uint256 amount) external {{
        uint256 beforeBal = token.balanceOf(address(this));
        require(token.transferFrom(msg.sender, address(this), amount));
        credit[msg.sender] += token.balanceOf(address(this)) - beforeBal;
    }}
    function withdraw(uint256 amount) external {{
        require(credit[msg.sender] >= amount);
        credit[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount));
    }}
}}
"""
        )
    pool = """
pragma solidity ^0.8.20;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
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
    return {
        "a_arith.sol": "\n".join(arithmetic),
        "b_eoa.sol": "\n".join(eoa),
        "c_message.sol": "\n".join(message),
        "m_custody.sol": "\n".join(custody),
        "zzz_pool.sol": pool,
    }


def _unbudgeted(model):  # type: ignore[no-untyped-def]
    found = []
    for name in sorted(FAMILIES):
        if name == "account_abstraction" and not account_abstraction_present(model):
            continue
        if name == "protocol_modules" and not modules_present(model):
            continue
        found.extend(FAMILIES[name](model))
    return found


def _analyze(tmp_path: Path):  # type: ignore[no-untyped-def]
    sources = _sources()
    for name, text in sources.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    files = tuple(sorted(sources))
    mani = manifest(
        in_scope=[{"kind": "contract", "identifier": "Pool"}],
        out_of_scope=[],
        known_issues=[],
        testing_mode="local_only",
    )
    identity = mani.to_campaign_identity(contract="Pool", source_file="zzz_pool.sol")
    return analyze_campaign(
        manifest=mani,
        identity=identity,
        repo_root=tmp_path,
        files=files,
        selection=SourceSelection.explicit(files),
        contract="Pool",
    )


def test_a_lexical_cap_would_drop_the_late_pool_and_the_budget_keeps_it(tmp_path: Path) -> None:
    analysis = _analyze(tmp_path)
    assert analysis.model is not None
    found = _unbudgeted(analysis.model)
    lexical = sorted(
        found, key=lambda c: (c.file, c.line, c.family, c.detector, c.contract, c.function)
    )
    assert len(lexical) > MAX_TOTAL_CANDIDATES
    assert not any(item.detector == _DONATION for item in lexical[:MAX_TOTAL_CANDIDATES])
    assert any(item.detector == _DONATION for item in analysis.candidates)
    budget = analysis.candidate_budget
    assert budget["candidates_found"] > MAX_TOTAL_CANDIDATES
    assert budget["candidates_kept"] <= MAX_TOTAL_CANDIDATES
    assert budget["truncated"] is True
    reasons = {item["reason"] for item in budget["dropped"]}
    assert "total_budget" in reasons
    assert all(item["count"] > 0 for item in budget["dropped"])
    assert analysis.truncated is True


def _key(item):  # type: ignore[no-untyped-def]
    return (item.detector, item.file, item.contract, item.function, item.line)


def test_the_budget_is_deterministic(tmp_path: Path) -> None:
    first = _analyze(tmp_path)
    second = _analyze(tmp_path)
    assert [_key(item) for item in first.candidates] == [_key(item) for item in second.candidates]
    assert first.candidate_budget == second.candidate_budget
