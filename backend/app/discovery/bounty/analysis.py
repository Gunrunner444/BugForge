"""Campaign analysis: the real bounty analysis path behind findings, VFCS, and reports.

Everything here derives from the campaign's *selected* sources (truncation-aware
:func:`select_sources`), never from the first files in alphabetical order:

* the primary pass reads the selected files;
* dropped high-priority files get a bounded follow-up pass (at most
  ``MAX_FOLLOWUP_BATCHES`` batches); what still was not read is listed, never
  implied safe;
* a contract name declared in several files is not bound to the first file:
  each additional declaring file is analysed on its own and its candidates stay
  bound to that file and flagged as name-ambiguous;
* the campaign's deployment identity (chain, address, contract, source commit,
  runtime digest, compiler, proxy/implementation/beacon/diamond/clone) is
  carried into findings, VFCS sequence identity, dedup keys, and the report.

Nothing here executes a transaction, compiles, or touches a network.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.discovery.bounty.campaign import BountyManifest
from app.discovery.bounty.deployment_identity import (
    DeploymentIdentity,
    deployment_identity,
)
from app.discovery.bounty.priority import prioritize
from app.discovery.bounty.source_selection import MAX_FILE_BYTES, SourceSelection
from app.discovery.bounty.vfcs import MAX_VFCS_CANDIDATES, SequenceIdentity, Vfcs, generate
from app.discovery.orchestration.model import CampaignIdentity
from app.parsing.solidity_research import (
    ResearchModel,
    SemanticCandidate,
    build_research_model,
)
from app.parsing.solidity_research_suite import run_suite

MAX_AMBIGUOUS_PASSES = 8
_DECLARATION = re.compile(r"\b(?:abstract\s+)?(?:contract|library|interface)\s+([A-Za-z_]\w*)")
MAX_TOTAL_SEQUENCES = 2 * MAX_VFCS_CANDIDATES


@dataclass
class CampaignAnalysis:
    sources: dict[str, str]
    model: ResearchModel | None
    candidates: tuple[SemanticCandidate, ...]
    sequences: tuple[Vfcs, ...]
    models: dict[str, ResearchModel]  # sequence_id -> the model it was built from
    deployment: DeploymentIdentity
    sequence_identity: SequenceIdentity
    ambiguous_contracts: frozenset[str]
    followup: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False
    _deployments: dict[str, DeploymentIdentity] = field(default_factory=dict)

    def deployment_for(self, contract: str) -> DeploymentIdentity | None:
        return self._deployments.get(contract)


def read_sources(repo_root: Path, files: tuple[str, ...]) -> dict[str, str]:
    root = repo_root.resolve()
    sources: dict[str, str] = {}
    for name in files:
        path = (root / name).resolve()
        if not path.is_file() or root not in path.parents or path.suffix != ".sol":
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            sources[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            continue
    return sources


def _ordered(
    model: ResearchModel, manifest: BountyManifest, candidates: tuple[SemanticCandidate, ...]
) -> list[SemanticCandidate]:
    ranked = prioritize(model, manifest=manifest, candidates=candidates)
    order = {entry.identity: index for index, entry in enumerate(ranked.ranked)}
    return sorted(
        candidates,
        key=lambda c: (order.get(f"{c.contract}.{c.function}", len(order)), c.detector, c.line),
    )


def analyze_campaign(
    *,
    manifest: BountyManifest,
    identity: CampaignIdentity,
    repo_root: Path,
    files: tuple[str, ...],
    selection: SourceSelection,
    contract: str = "",
    address: str = "",
    chain_id: str = "",
) -> CampaignAnalysis:
    sources = read_sources(repo_root, files)
    model = build_research_model(sources) if sources else None
    target = deployment_identity(
        manifest, contract=contract, address=address, chain_id=chain_id, model=model
    )
    seq_identity = SequenceIdentity(
        campaign_id=identity.campaign_id,
        source_snapshot=manifest.source_commit,
        compiler_configuration=manifest.compiler.fingerprint(),
        fork_reference=manifest.fork_reference(),
        program_context=manifest.identity_digest(),
        deployment=target.key if target.known else "",
    )
    candidates: list[SemanticCandidate] = []
    sequences: list[Vfcs] = []
    models: dict[str, ResearchModel] = {}
    ambiguous: set[str] = set()
    followup: dict[str, Any] = {
        "batches": [],
        "ambiguous_passes": [],
        "never_read": [],
    }

    def absorb(part: ResearchModel, found: tuple[SemanticCandidate, ...]) -> None:
        candidates.extend(found)
        room = MAX_TOTAL_SEQUENCES - len(sequences)
        if room <= 0:
            return
        built = generate(
            part,
            _ordered(part, manifest, found),
            seq_identity,
            limit=min(room, MAX_VFCS_CANDIDATES),
        )
        for item in built.sequences:
            if item.sequence_id not in models:
                sequences.append(item)
                models[item.sequence_id] = part

    if model is not None:
        absorb(model, run_suite(model).candidates)
        ambiguous |= set(model.ambiguous)

    # Bounded follow-up over dropped high-priority files.
    batches = selection.followup_batches()
    covered = set(sources)
    for batch in batches:
        batch_sources = read_sources(repo_root, tuple(p for p in batch if p not in covered))
        if not batch_sources:
            continue
        covered |= set(batch_sources)
        part = build_research_model(batch_sources)
        found = tuple(c for c in run_suite(part).candidates if c.file in batch_sources)
        absorb(part, found)
        ambiguous |= set(part.ambiguous)
        followup["batches"].append({"files": sorted(batch_sources), "candidates": len(found)})
    followed = {path for batch in batches for path in batch}
    followup["never_read"] = [p for p in selection.dropped_high_priority if p not in followed]

    # A contract name declared in several files: analyse each other declaring file
    # alone so its candidates are bound to that file instead of being dropped.
    declared: dict[str, list[str]] = {}
    for name, declaring in selection.ambiguous_contracts:
        declared[name] = list(declaring)
        ambiguous.add(name)
    for path, text in sources.items():
        for name in _DECLARATION.findall(text):
            if name in ambiguous and path not in declared.setdefault(name, []):
                declared[name].append(path)
    for name in sorted(ambiguous):
        extra_files = [
            path
            for path in declared.get(name, [])
            if model is None
            or model.contracts.get(name) is None
            or model.contracts[name].file != path
        ]
        for path in extra_files:
            if len(followup["ambiguous_passes"]) >= MAX_AMBIGUOUS_PASSES:
                break
            alone = read_sources(repo_root, (path,))
            if not alone:
                continue
            part = build_research_model(alone)
            found = tuple(c for c in run_suite(part).candidates if c.contract == name)
            absorb(part, found)
            followup["ambiguous_passes"].append(
                {"contract": name, "file": path, "candidates": len(found)}
            )

    unique: dict[tuple[str, str, str, str, int], SemanticCandidate] = {}
    for item in candidates:
        unique.setdefault((item.detector, item.file, item.contract, item.function, item.line), item)

    deployments: dict[str, DeploymentIdentity] = {}
    for item in unique.values():
        if item.contract in deployments:
            continue
        if contract and item.contract == contract:
            deployments[item.contract] = target
        else:
            deployments[item.contract] = deployment_identity(
                manifest, contract=item.contract, model=model
            )

    return CampaignAnalysis(
        sources=sources,
        model=model,
        candidates=tuple(
            sorted(unique.values(), key=lambda c: (c.file, c.line, c.contract, c.function))
        ),
        sequences=tuple(sequences),
        models=models,
        deployment=target,
        sequence_identity=seq_identity,
        ambiguous_contracts=frozenset(ambiguous),
        followup=followup,
        truncated=bool(selection.truncated or (model is not None and model.truncated)),
        _deployments=deployments,
    )


def sources_digest(sources: Mapping[str, str]) -> str:
    from app.discovery.orchestration.codec import digest

    return digest(sorted((path, len(text)) for path, text in sources.items()))


__all__ = ["CampaignAnalysis", "analyze_campaign", "read_sources", "sources_digest"]
