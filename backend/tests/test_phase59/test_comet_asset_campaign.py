"""A non-empty asset list evaluated against the pinned Comet source.

The target file is the Compound contract. The factory and asset list are the
pinned sources too. Local token and price-feed fixtures supply decimals only.
This is not a deployed-bytecode result and not a vulnerability finding.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import app.discovery.bounty.service as service_module
from app.core.config import get_settings
from app.discovery.bounty.constructor_profile import (
    ASSET_SIGNATURE,
    ASSET_STATEMENT,
    COMET_CONTRACT,
    COMET_FILE,
    COMET_PIN,
    comet_asset_profile,
    prepare_profile,
)
from app.discovery.bounty.service import BountyCampaignService, CampaignSpec
from app.discovery.bounty.solc_resolve import resolve_solc
from tests.test_phase51.phase51_support import manifest
from tests.test_phase52.phase52_support import requires_forge
from tests.test_phase58.comet_support import CLOSURE, comet_root, comet_sources

ASSET_CLOSURE = (
    *CLOSURE,
    "contracts/AssetList.sol",
    "contracts/AssetListFactory.sol",
)


def _sources() -> dict[str, str]:
    root = comet_root()
    missing = [path for path in ASSET_CLOSURE if not (root / path).is_file()]
    if missing:
        pytest.fail(f"Comet asset closure is incomplete: {missing}")
    sources = comet_sources(root)
    sources.update({path: (root / path).read_text(encoding="utf-8") for path in ASSET_CLOSURE})
    return sources


def test_the_asset_profile_uses_the_pinned_factory_and_one_collateral() -> None:
    sources = _sources()
    profile = comet_asset_profile(sources)
    prepared = prepare_profile(profile, sources)
    rendered = prepared.expression + "\n" + "\n".join(prepared.deploy_lines)
    assert profile.source_commit == COMET_PIN
    assert profile.property_function == ASSET_SIGNATURE
    assert profile.property_template == "configured-asset"
    assert "new AssetList(" not in prepared.contracts
    assert "return address(this)" not in prepared.contracts
    assert "AssetListFactory bf_factory = new AssetListFactory();" in rendered
    assert "new CometConfiguration.AssetConfig[](1)" in rendered
    assert "borrowCollateralFactor: 500000000000000000" in rendered
    assert "address(bf_collateral)" in rendered
    assert profile.public_dict()["establishes_deployed_state"] is False
    changed = dict(sources)
    changed["contracts/AssetList.sol"] = sources["contracts/AssetList.sol"] + "\n"
    with pytest.raises(Exception, match="profile_source_mismatch"):
        prepare_profile(profile, changed)


@requires_forge
def test_comet_asset_campaign_preserves_the_configured_collateral(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if resolve_solc("0.8.15") is None:
        if os.environ.get("BUGFORGE_REQUIRE_FOUNDRY") == "1":
            pytest.fail("the Foundry job requires solc 0.8.15")
        pytest.skip("solc 0.8.15 is not installed")
    sources = _sources()
    repo = comet_root()
    monkeypatch.setattr(
        get_settings(),
        "bounty_campaign_database_url",
        f"sqlite:///{tmp_path / 'campaign.sqlite'}",
        raising=False,
    )
    monkeypatch.setattr(service_module, "_SERVICE", None, raising=False)
    profile = comet_asset_profile(sources)
    svc = BountyCampaignService()
    campaign = svc.create(
        CampaignSpec(
            manifest=manifest(
                compiler={
                    "version": "0.8.15",
                    "optimizer": "enabled",
                    "optimizer_runs": "1",
                    "via_ir": "true",
                    "evm_version": "cancun",
                },
                in_scope=[{"kind": "contract", "identifier": COMET_CONTRACT}],
                out_of_scope=[],
                known_issues=[],
                source_commit=COMET_PIN,
            ),
            repo_root=repo,
            contract=COMET_CONTRACT,
            source_file=COMET_FILE,
            files=ASSET_CLOSURE,
            constructor_profile=profile.to_dict(),
        )
    )
    result = svc.stateful_execute(campaign.campaign_id, rounds=1)
    if not result.get("available"):
        pytest.fail(result.get("reason", "stateful execution did not run"))
    summary = result["campaign_summary"]
    print(
        json.dumps(
            {
                "campaign_id": campaign.campaign_id,
                "sequences": summary.get("sequences"),
                "sequences_submitted": summary.get("sequences_submitted"),
                "sequences_excluded": summary.get("sequences_excluded"),
                "exclusion_reasons": summary.get("exclusion_reasons"),
                "sequences_skipped": summary.get("sequences_skipped"),
                "skipped_by_reason": summary.get("skipped_by_reason"),
                "forge_runs": summary.get("forge_runs"),
                "by_outcome": summary.get("by_outcome"),
                "reason_codes": summary.get("reason_codes"),
                "positive_controls": summary.get("positive_controls"),
                "property_evaluation_demonstrated": summary.get("property_evaluation_demonstrated"),
                "execution_stages": summary.get("execution_stages"),
                "verified": summary.get("verified"),
            },
            default=str,
        )
    )
    assert summary["constructor_profile"]["validation"] == "accepted"
    assert summary["constructor_profile"]["source_commit"] == COMET_PIN
    assert summary["constructor_profile"]["establishes_deployed_state"] is False
    assert summary["forge_runs"] >= 1
    assert summary["foundry_invoked"] is True
    assert summary["property_evaluation_demonstrated"] is True
    assert summary["verified"] is False
    held = [
        item
        for item in result["observations"]
        if item["outcome"] == "property_held" and item["oracle_kind"] == "configured_value"
    ]
    assert held, result["outcomes"]
    assert held[0]["strong_candidate"] is False
    assert held[0]["property_under_test"] == ASSET_STATEMENT
    assert "configured fixture address" in held[0]["reason"]
    assert held[0]["verified"] is False
    reclassified = [
        item for item in result["observations"] if item["reason_code"] == "constructor_not_a_call"
    ]
    assert reclassified, "the constructor sequence disappeared instead of being reclassified"
    assert reclassified[0]["outcome"] == "inconclusive"
    assert summary["by_outcome"].get("inconclusive", 0) >= 1
    skipped = result["skipped"]
    assert any(
        "getPrice" in item.get("reason", "") or "oracle" in item.get("reason_code", "")
        for item in skipped
    )
    assert all(item.get("forge_invoked") == "false" for item in skipped)
    props = [
        spec
        for spec in result["properties"].values()
        if spec["oracle"].get("probe_function") == ASSET_SIGNATURE
    ]
    assert props
    assert props[0]["oracle"]["kind"] == "configured_value"
    assert props[0]["oracle"]["word_index"] == 1
    assert props[0]["verified"] is False
    runs = BountyCampaignService().stateful_status(campaign.campaign_id)["runs"]
    tools = runs[-1]["tools"]
    assert str(tools["solc_selected_version"]).startswith("0.8.15")
    assert tools["evm_requested"] == "cancun"
    assert tools["evm_exact"] == "false"
    assert tools["evm_version"] == ""
    assert tools["optimizer"] == "true"
    assert tools["via_ir"] == "true"
    assert tools["optimizer_runs"] == "1"
    reloaded = BountyCampaignService().research_ledger(campaign.campaign_id)["campaign_summary"]
    assert reloaded["forge_runs"] == summary["forge_runs"]
    assert reloaded["by_outcome"] == summary["by_outcome"]
    assert reloaded["reason_codes"] == summary["reason_codes"]
    assert reloaded["property_evaluation_demonstrated"] is True
    assert reloaded["verified"] is False
    findings = BountyCampaignService().findings(campaign.campaign_id)["findings"]
    assert all(item["verified"] is False for item in findings)
    assert all(item["candidate_strength"] != "strong_candidate" for item in findings)
    held_findings = [item for item in findings if item.get("execution_status") == "property_held"]
    assert held_findings
    assert all(item["candidate_strength"] == "property_held" for item in held_findings)
    asset_findings = [
        item
        for item in held_findings
        if str(item.get("function", "")).startswith("getAssetInfo(")
        and item.get("detector") == "profile.configured_asset"
    ]
    assert asset_findings
