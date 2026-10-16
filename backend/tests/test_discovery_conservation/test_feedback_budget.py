"""Feedback budget fairness and the campaign path end to end."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from app.discovery.bounty.service import BountyCampaignService, CampaignSpec
from app.discovery.bounty.vfcs import MAX_MUTATIONS, FeedbackSignal, generate, mutate
from app.parsing.solidity_conservation import DETECTOR
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite
from tests.test_phase51.phase51_support import manifest
from tests.test_phase52.phase52_support import requires_forge

HISTORY = Path(__file__).resolve().parents[1] / "fixtures" / "phase52_history"


def _sequence(name: str, detector: str):  # type: ignore[no-untyped-def]
    text = (HISTORY / name).read_text(encoding="utf-8")
    model = build_research_model({name: text})
    candidate = next(c for c in run_suite(model).candidates if c.detector == detector)
    return model, candidate, generate(model, [candidate], sources={name: text}).sequences[0]


def test_one_parent_cannot_spend_the_whole_mutation_budget() -> None:
    _, _, first = _sequence("roundtrip_missing_debit_safe.sol", DETECTOR)
    _, _, second = _sequence("roundtrip_index_rounding_vulnerable.sol", DETECTOR)
    signals = [
        FeedbackSignal("near_miss", first.sequence_id, 3, engine="foundry"),
        FeedbackSignal("near_miss", second.sequence_id, 3, engine="foundry"),
    ]
    children = mutate([first, second], signals, limit=MAX_MUTATIONS)
    assert len(children) == MAX_MUTATIONS == 4
    parents = [child.origin.rsplit(":", 1)[-1] for child in children]
    assert parents.count(first.sequence_id) == 2
    assert parents.count(second.sequence_id) == 2
    rest = mutate([first, second, *children], signals, limit=MAX_MUTATIONS)
    assert len(rest) == 2 and {c.sequence_id for c in rest}.isdisjoint(
        c.sequence_id for c in children
    )
    assert mutate([first, second, *children, *rest], signals) == ()


@pytest.fixture
def vaults(tmp_path: Path) -> Path:
    shutil.copy(HISTORY / "roundtrip_index_rounding_vulnerable.sol", tmp_path / "IndexVault.sol")
    shutil.copy(HISTORY / "roundtrip_missing_debit_safe.sol", tmp_path / "LeakyVault.sol")
    return tmp_path


@requires_forge
def test_the_campaign_finds_the_rounding_twin_and_keeps_the_safe_vault_held(
    vaults: Path,
) -> None:
    mani = manifest(
        in_scope=[
            {"kind": "contract", "identifier": "IndexVault"},
            {"kind": "contract", "identifier": "LeakyVault"},
        ],
        out_of_scope=[],
        known_issues=[],
    )
    svc = BountyCampaignService()
    campaign = svc.create(
        CampaignSpec(
            manifest=mani,
            repo_root=vaults,
            contract="IndexVault",
            files=("IndexVault.sol", "LeakyVault.sol"),
        )
    )
    result = svc.stateful_execute(campaign.campaign_id)
    assert result["persistence"]["status"] == "persisted"
    executions = BountyCampaignService().stateful_status(campaign.campaign_id)["executions"]
    ran = {
        (
            record["derived_from"],
            record["origin"].split(":")[2] if record["origin"].startswith("mutation:") else "",
        ): record["outcome"]
        for record in executions.values()
    }
    index = f"{DETECTOR}@IndexVault.supply(uint256)"
    leaky = f"{DETECTOR}@LeakyVault.deposit(uint256)"
    assert ran[(index, "")] == "property_held"
    assert ran[(index, "small_amount_two")] == "property_violated"
    assert {ran[(leaky, op)] for op in ("", "small_amount_one", "small_amount_two")} == {
        "property_held"
    }
    assert "inconclusive" not in ran.values()

    findings = {
        (f["detector"], f["contract"]): f for f in svc.findings(campaign.campaign_id)["findings"]
    }
    found = findings[(DETECTOR, "IndexVault")]
    assert found["candidate_strength"] in {"strong_candidate", "corroborated_candidate"}
    assert found["verified"] is False
    assert (DETECTOR, "LeakyVault") not in findings

    ledger = svc.research_ledger(campaign.campaign_id)
    coverage = ledger["RESEARCH_COVERAGE"]
    assert coverage["violations_found_by_variation"] == 1
    assert coverage["properties_held_after_variation"] >= 1
    kinds = {(g["kind"], g["subject"]) for g in ledger["RESEARCH_GAPS"]}
    assert ("deployment_replay", "IndexVault.supply(uint256)") in kinds
    assert not [k for k, _ in kinds if k == "held_untested_variation"]
    assert ledger["verified"] is False
