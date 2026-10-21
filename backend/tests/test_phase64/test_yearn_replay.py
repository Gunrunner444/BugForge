"""Pinned Yearn Tokenized Strategy 3.0.4 source replay.

The checkout is the published tag, not ``master``. IdleHost is the local harness
host already used for this replay. A missing pin fails the dedicated CI job and
skips elsewhere. Execution is the ordinary campaign service with a run cap.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

import pytest

from app.discovery.bounty.campaign import BountyManifest
from app.discovery.bounty.constructor_profile import sha256_text
from app.discovery.bounty.service import BountyCampaignService, CampaignSpec
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite

PIN = "82806289f967590c4efbf6bc3d237e4e7f0a0966"
OZ_PIN = "bd325d56b4c62c9c5c1aff048c37c6bb18ac0290"
LITERAL = "0xD377919FA87120584B21279a491F82D5265A139c"
HASHES = {
    "src/IdleHost.sol": "bf4f97bc424d5859f50d187e8ff3ecaf7d725527da468c32ac89ed17d2ce243a",
    "src/BaseStrategy.sol": "6f049ce40a56409cca0d50d5e134b096fbf5ec5e2c3b88b4fe7cadd4c177063a",
    "src/TokenizedStrategy.sol": "af2cce2ece0a80c52fa431fce193cf6557fa7533bce0486cf6c13d0f9d46a403",
    "src/test/mocks/MockFactory.sol": "a24b2cac185794feb3b951a1bbe194030e3c5625ddc6cc18fcd8e6b55173685c",
}
YEARN_FILES = (
    "src/BaseStrategy.sol",
    "src/TokenizedStrategy.sol",
    "src/interfaces/IBaseStrategy.sol",
    "src/interfaces/IFactory.sol",
    "src/interfaces/ITokenizedStrategy.sol",
    "src/interfaces/IEvents.sol",
    "src/interfaces/IStrategy.sol",
    "src/test/mocks/MockFactory.sol",
)
OZ_FILES = (
    "contracts/interfaces/IERC4626.sol",
    "contracts/token/ERC20/ERC20.sol",
    "contracts/token/ERC20/IERC20.sol",
    "contracts/token/ERC20/extensions/IERC20Metadata.sol",
    "contracts/token/ERC20/extensions/IERC20Permit.sol",
    "contracts/token/ERC20/utils/SafeERC20.sol",
    "contracts/utils/Address.sol",
    "contracts/utils/Context.sol",
    "contracts/utils/math/Math.sol",
)
IDLE = Path(__file__).resolve().parents[1] / "fixtures" / "yearn_replay" / "IdleHost.sol"


def _require(name: str) -> str:
    value = os.environ.get(name, "")
    if value:
        return value
    if os.environ.get("BUGFORGE_REQUIRE_YEARN") == "1":
        pytest.fail(f"{name} is not available and this job requires the pinned Yearn replay")
    pytest.skip(f"{name} is not set")
    return ""


def assemble(tmp_path: Path) -> dict[str, str]:
    """Copy the pinned sources into one tree and return the source map."""
    yearn = Path(_require("BUGFORGE_YEARN_ROOT"))
    oz = Path(_require("BUGFORGE_OZ_ROOT"))
    if not yearn.is_dir() or not oz.is_dir():
        if os.environ.get("BUGFORGE_REQUIRE_YEARN") == "1":
            pytest.fail("the pinned Yearn or OpenZeppelin checkout is not available")
        pytest.skip("the pinned Yearn checkout is not available")
    head = yearn / ".git"
    if head.exists():
        commit = (
            __import__("subprocess")
            .check_output(["git", "-C", str(yearn), "rev-parse", "HEAD"], text=True)
            .strip()
        )
        assert commit == PIN
        oz_commit = (
            __import__("subprocess")
            .check_output(["git", "-C", str(oz), "rev-parse", "HEAD"], text=True)
            .strip()
        )
        assert oz_commit == OZ_PIN
    root = tmp_path / "yearn-replay"
    root.mkdir()
    for relative in YEARN_FILES:
        source = yearn / relative
        assert source.is_file(), relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    shutil.copyfile(IDLE, root / "src" / "IdleHost.sol")
    for relative in OZ_FILES:
        source = oz / relative
        assert source.is_file(), relative
        destination = root / "lib" / "openzeppelin-contracts" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    files = {path.relative_to(root).as_posix(): path.read_text() for path in root.rglob("*.sol")}
    for path, digest in HASHES.items():
        assert hashlib.sha256(files[path].encode()).hexdigest() == digest
    return files


def _profile(files: dict[str, str]) -> dict[str, object]:
    bound = tuple(HASHES)
    return {
        "profile_id": "yearn-idle-host",
        "contract": "IdleHost",
        "source_file": "src/IdleHost.sol",
        "source_sha256": sha256_text(files["src/IdleHost.sol"]),
        "parameter": "asset_",
        "model_type": "address",
        "solidity_type": "address",
        "struct_file": "src/IdleHost.sol",
        "struct_name": "address",
        "value": {"kind": "fixture", "value": "asset"},
        "fixtures": [
            {"fixture_id": "asset", "kind": "harness_token", "decimals": 18},
            {
                "fixture_id": "factory",
                "kind": "source_contract",
                "contract": "MockFactory",
                "arguments": [
                    {"kind": "uint", "value": "0"},
                    {"kind": "role", "value": "governor"},
                ],
            },
            {
                "fixture_id": "implementation",
                "kind": "source_contract",
                "contract": "TokenizedStrategy",
                "depends_on": "factory",
                "place_at": LITERAL,
                "arguments": [{"kind": "fixture", "value": "factory"}],
            },
        ],
        "imports": ["src/TokenizedStrategy.sol", "src/test/mocks/MockFactory.sol"],
        "bound_files": [{"path": path, "sha256": sha256_text(files[path])} for path in bound],
        "assumptions": [
            "IdleHost is a local host whose callbacks leave funds idle",
            "TokenizedStrategy runtime is placed at the address literal in BaseStrategy",
            "MockFactory returns a zero protocol fee and is not the vault factory",
            "asset() must return the harness token before token accounting runs",
            "this run is a local source replay, not deployed-runtime equivalence",
        ],
        "property_function": "asset()",
        "property_statement": "asset() returns the harness token after the host initializes",
        "property_getter": "asset()",
        "property_template": "initialization-asset",
        "source_commit": PIN,
    }


def test_the_pinned_sources_expose_a_balance_backed_report(tmp_path: Path) -> None:
    files = assemble(tmp_path)
    model = build_research_model(files)
    found = [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance" and item.function == "report()"
    ]
    assert len(found) == 1
    assert found[0].contract == "TokenizedStrategy"
    assert found[0].fact("balance_backed") == "true"
    assert found[0].fact("stored_getter") == "totalAssets()"
    assert found[0].fact("role_getter") == "keeper()"
    assert found[0].fact("unlock_seconds") == "864000"
    assert found[0].fact("loss_ignored") == "false"
    assert found[0].fact("token_behavior") == "unknown"


def test_yearn_replay_executes_the_report_through_the_campaign_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.environ.get("BUGFORGE_YEARN_EXECUTE") != "1":
        if os.environ.get("BUGFORGE_REQUIRE_YEARN") == "1":
            pytest.fail("the Yearn job must execute the source replay")
        pytest.skip("BUGFORGE_YEARN_EXECUTE is not set")
    from tests.test_phase52.phase52_support import _has

    if not (_has("forge") and _has("solc")):
        pytest.fail("forge and solc are required to execute the Yearn replay")
    files = assemble(tmp_path)
    root = tmp_path / "campaign"
    root.mkdir()
    for path, text in files.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
    import app.discovery.bounty.service as service_module
    from app.core.config import get_settings

    monkeypatch.setattr(
        get_settings(),
        "bounty_campaign_database_url",
        f"sqlite:///{tmp_path / 'campaigns.sqlite'}",
        raising=False,
    )
    monkeypatch.setattr(service_module, "_SERVICE", None, raising=False)
    manifest = BountyManifest.from_dict(
        {
            "platform": "local",
            "program_id": "yearn-replay",
            "program_name": "Yearn source replay",
            "rules_version": "local",
            "in_scope": [{"kind": "contract", "identifier": "TokenizedStrategy"}],
            "out_of_scope": [],
            "known_issues": [],
            "poc_requirement": "required",
            "testing_mode": "local_only",
            "repository": "https://github.com/yearn/tokenized-strategy",
            "source_commit": PIN,
            "deployments": [],
            "chain_ids": ["1"],
            "compiler": {
                "version": "0.8.18",
                "optimizer": "enabled",
                "optimizer_runs": "200",
                "via_ir": "false",
                "evm_version": "paris",
            },
            "impact_categories": [
                {
                    "name": "Direct theft of user funds",
                    "severity": "critical",
                    "weight": 90,
                    "tags": ["custody", "vault_accounting"],
                }
            ],
        }
    )
    service = BountyCampaignService()
    campaign = service.create(
        CampaignSpec(
            manifest=manifest,
            repo_root=root,
            contract="TokenizedStrategy",
            source_file="src/TokenizedStrategy.sol",
            files=tuple(sorted(files)),
            constructor_profile=_profile(files),
            address=LITERAL,
            chain_id="1",
        )
    )
    result = service.stateful_execute(campaign.campaign_id, rounds=1, max_runs=30)
    assert result["available"] is True, result.get("blocker") or result.get("reason")
    assert result["forge_runs"] <= 30
    observations = result["observations"]
    assert isinstance(observations, list)
    analysis = service._analysis(campaign)
    report_ids = {
        item.sequence_id
        for item in analysis.sequences
        if item.derived_from.startswith("accounting.reported_balance@")
    }
    assert report_ids
    judged = [
        item
        for item in observations
        if item["sequence_id"] in report_ids
        and item["outcome"]
        in {
            "property_held",
            "property_violated",
            "inconclusive",
        }
    ]
    assert judged, [
        (item["sequence_id"], item["outcome"], item.get("reason")) for item in observations
    ]
    assert not any(item.get("verified") for item in observations)
    assert result["forge_runs"] >= 1
