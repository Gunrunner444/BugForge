"""Run one local campaign the way an operator would, without a planted answer.

The caller supplies source files, the target contract, and ordinary scope and
compiler metadata. Detector names, property choices, call sequences, and
ground-truth labels are not arguments. Those stay with the evaluator.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.discovery.bounty.campaign import BountyManifest
from app.discovery.bounty.service import BountyCampaignService, CampaignSpec

LOCAL_COMPILER: dict[str, str] = {
    "version": "0.8.28",
    "optimizer": "disabled",
    "optimizer_runs": "200",
    "via_ir": "false",
    "evm_version": "cancun",
}


def run_blind_campaign(
    service: BountyCampaignService,
    *,
    repo_root: Path,
    files: tuple[str, ...],
    contract: str,
    rounds: int = 1,
    source_commit: str = "local-seed",
    compiler: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Create a campaign and execute the sequences analysis itself produced."""
    chosen = dict(LOCAL_COMPILER if compiler is None else compiler)
    manifest = BountyManifest.from_dict(
        {
            "platform": "local",
            "program_id": "local-seed",
            "program_name": "Local seed",
            "rules_version": "local",
            "in_scope": [{"kind": "contract", "identifier": contract}],
            "out_of_scope": [],
            "known_issues": [],
            "poc_requirement": "required",
            "testing_mode": "local_only",
            "repository": "local",
            "source_commit": source_commit,
            "deployments": [],
            "chain_ids": [],
            "compiler": chosen,
            "impact_categories": [
                {
                    "name": "Direct theft of funds",
                    "severity": "critical",
                    "weight": 90,
                    "tags": ["value_transfer", "custody", "token_approvals"],
                },
                {
                    "name": "Permission takeover",
                    "severity": "high",
                    "weight": 70,
                    "tags": ["privileged_operations", "permissions_roles"],
                },
            ],
        }
    )
    campaign = service.create(
        CampaignSpec(
            manifest=manifest,
            repo_root=repo_root,
            contract=contract,
            source_file=files[0] if files else "",
            files=files,
        )
    )
    analysis = service._analysis(campaign)
    executed = service.stateful_execute(campaign.campaign_id, rounds=rounds)
    findings = service.findings(campaign.campaign_id)
    sequences = {
        item.sequence_id: {
            "sequence_id": item.sequence_id,
            "template": item.template,
            "derived_from": item.derived_from,
            "property_under_test": item.property_under_test,
            "calls": [
                {
                    "contract": call.contract,
                    "function": call.function,
                    "role": call.role,
                    "actor": call.actor,
                    "arguments": [list(pair) for pair in call.arguments],
                    "primitive": call.primitive,
                }
                for call in item.calls
            ],
            "source_hashes": dict(item.identity.source_hashes),
            "compiler_configuration": item.identity.compiler_configuration,
        }
        for item in analysis.sequences
    }
    return {
        "campaign_id": campaign.campaign_id,
        "contract": contract,
        "files": list(files),
        "source_commit": source_commit,
        "compiler": chosen,
        "compiler_fingerprint": manifest.compiler.fingerprint(),
        "source_hashes": dict(analysis.source_hashes),
        "candidate_budget": analysis.candidate_budget,
        "candidates": [
            {
                "detector": item.detector,
                "family": item.family,
                "contract": item.contract,
                "function": item.function,
                "file": item.file,
                "line": item.line,
                "confidence": item.confidence,
            }
            for item in analysis.candidates
        ],
        "sequences": sequences,
        "sequence_skipped": dict(analysis.sequence_skipped),
        "execution": _execution_view(executed),
        "findings": findings["findings"],
        "verified": False,
    }


def _execution_view(result: dict[str, Any]) -> dict[str, Any]:
    """Keep the structured run and drop harness stdout, which is not the verdict."""
    observations = []
    for item in result.get("observations", []):
        body = dict(item)
        inner = body.get("result")
        if isinstance(inner, dict):
            trimmed = dict(inner)
            trimmed.pop("stdout_tail", None)
            trimmed.pop("stderr_tail", None)
            body["result"] = trimmed
        observations.append(body)
    return {
        "available": result.get("available"),
        "forge_runs": result.get("forge_runs", 0),
        "outcomes": result.get("outcomes", {}),
        "skipped": result.get("skipped", []),
        "observations": observations,
        "minimized": result.get("minimized", {}),
        "independent_checks": result.get("independent_checks", {}),
        "feedback": result.get("feedback", []),
        "mutated": result.get("mutated", []),
        "properties": result.get("properties", {}),
        "blocker": result.get("blocker", ""),
        "persistence": result.get("persistence", {}),
        "campaign_summary": result.get("campaign_summary", {}),
        "verified": False,
    }
