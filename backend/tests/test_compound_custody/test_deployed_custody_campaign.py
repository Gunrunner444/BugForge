"""The traced base-token round trip against the deployed cUSDCv3 source (Comet 059c1191).

Analysis traces supply and withdraw through their helpers, the custody profile
binds config.baseToken to the harness token, and Foundry runs the real external
entry points offline. A held result is the expected outcome: it is a regression
for one ordering, not evidence that the market is safe, and never a finding.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import app.discovery.bounty.service as service_module
from app.core.config import get_settings
from app.discovery.bounty.constructor_profile import comet_custody_profile
from app.discovery.bounty.service import BountyCampaignService, CampaignSpec
from app.discovery.bounty.solc_resolve import resolve_solc
from app.parsing.solidity_conservation import DETECTOR
from tests.test_compound_custody.deployed_support import (
    CLOSURE,
    CONTRACT,
    DEPLOYED_COMPILER,
    DEPLOYED_PIN,
    TARGET,
    deployed_root,
    deployed_sources,
)
from tests.test_phase51.phase51_support import manifest
from tests.test_phase52.phase52_support import requires_forge


@requires_forge
def test_the_traced_base_round_trip_executes_against_the_deployed_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if resolve_solc("0.8.15") is None:
        if os.environ.get("BUGFORGE_REQUIRE_FOUNDRY") == "1":
            pytest.fail("the Foundry job requires solc 0.8.15")
        pytest.skip("solc 0.8.15 is not installed")
    root = deployed_root()
    sources = deployed_sources(root)
    monkeypatch.setattr(
        get_settings(),
        "bounty_campaign_database_url",
        f"sqlite:///{tmp_path / 'campaign.sqlite'}",
        raising=False,
    )
    monkeypatch.setattr(service_module, "_SERVICE", None, raising=False)
    profile = comet_custody_profile(sources, source_commit=DEPLOYED_PIN)
    svc = BountyCampaignService()
    campaign = svc.create(
        CampaignSpec(
            manifest=manifest(
                compiler=dict(DEPLOYED_COMPILER),
                in_scope=[{"kind": "contract", "identifier": CONTRACT}],
                out_of_scope=[],
                known_issues=[],
                source_commit=DEPLOYED_PIN,
            ),
            repo_root=root,
            contract=CONTRACT,
            source_file=TARGET,
            files=CLOSURE,
            constructor_profile=profile.to_dict(),
        )
    )
    result = svc.stateful_execute(campaign.campaign_id, rounds=1)
    if not result.get("available"):
        pytest.fail(result.get("reason", "stateful execution did not run"))
    summary = result["campaign_summary"]
    recorded = summary["constructor_profile"]
    assert recorded["validation"] == "accepted"
    assert recorded["source_commit"] == DEPLOYED_PIN
    assert recorded["establishes_deployed_state"] is False
    assert recorded["custody_binding"] == {
        "candidate": f"{DETECTOR}@{CONTRACT}.supply(address,uint256)",
        "payout_function": "withdraw(address,uint256)",
        "token_binding": "state:baseToken",
        "token_source": "constructor struct field config.baseToken",
        "harness_token_field": "config.baseToken",
        "credit_getter": "balanceOf(address)",
    }

    custody = [
        item for item in result["observations"] if item["oracle_kind"] == "balance_not_increased"
    ]
    assert len(custody) == 1, result["outcomes"]
    observed = custody[0]
    print(json.dumps({k: v for k, v in observed.items() if k != "result"}, default=str))
    assert observed["outcome"] == "property_held", observed["reason"]
    assert observed["declaration"] == "property_under_test"
    assert observed["strong_candidate"] is False and observed["verified"] is False
    assert observed["result"]["call_results"] == [1, 1, 1, 1]
    assert observed["result"]["solc_version"] == "0.8.15"
    assert observed["identity"]["source_snapshot"] == DEPLOYED_PIN
    assert observed["identity"]["source_hashes"] == {
        path: sources_hash for path, sources_hash in sorted(_hashes(sources).items())
    }
    evidence = observed["evaluation"]["evidence"]
    deposit = "1000000000000000000"
    assert evidence["attacker_withdrawal_amount"] == deposit
    assert evidence["holdings_before"] == "0"
    assert evidence["holdings_after"] == deposit
    assert evidence["victim_credit_after"] == deposit
    assert evidence["attacker_credit_after"] == "0"
    assert "Victim loss" not in observed["reason"]
    assert "one ordering" in observed["reason"]

    spec = result["properties"][observed["sequence_id"]]
    oracle = spec["oracle"]
    assert oracle["probe_function"] == "withdraw(address,uint256)"
    assert oracle["precondition_roles"] == ["initialize", "deposit", "victim_deposit"]
    assert oracle["getter"] == "balanceOf(address)"
    assumptions = " ".join(spec["provenance"]["assumptions"])
    assert "state:baseToken" in assumptions and "config.baseToken" in assumptions
    assert "not assumed to be token units" in assumptions
    assert "a gain is not yield" in assumptions
    assert "initializeStorage() runs first" in assumptions
    assert spec["verified"] is False

    tools = BountyCampaignService().stateful_status(campaign.campaign_id)["runs"][-1]["tools"]
    assert str(tools["solc_selected_version"]).startswith("0.8.15")
    assert tools["evm_requested"] == "london"
    assert tools["evm_exact"] == "true"
    assert tools["via_ir"] == "true"
    assert tools["optimizer_runs"] == "1"
    assert all(item.get("forge_invoked") == "false" for item in result["skipped"]), (
        "a skipped sequence reached Foundry"
    )
    findings = BountyCampaignService().findings(campaign.campaign_id)["findings"]
    assert all(item["verified"] is False for item in findings)
    assert all(item["candidate_strength"] != "strong_candidate" for item in findings)


def _hashes(sources: dict[str, str]) -> dict[str, str]:
    import hashlib

    return {
        path: hashlib.sha256(text.encode("utf-8")).hexdigest() for path, text in sources.items()
    }
