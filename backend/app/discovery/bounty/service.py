"""Operational bounty-campaign service (Phase 51).

This is the thin operational layer that makes the Phase 49 orchestrator and the
Phase 50 bounty engines reachable from the API and the Cursor MCP server. It
*reuses* the existing stack and introduces no parallel session, evidence store,
or authority model:

* identity is :class:`CampaignIdentity` derived from :class:`BountyManifest`;
* execution is the Phase 49 :class:`Orchestrator` over :class:`DiscoveryScheduler`;
* the gate is :class:`BountyGate` (which wraps the Phase 49 ``DefaultGate``);
* findings, VFCS plans, advisories, and the report pack are the Phase 50 modules.

The service never calls a model, never marks a finding verified, never raises a
budget, and never grants an approval to itself. Fork testing stays gated on an
operator-granted approval that only the human-only API path can set. Missing
optional tools (``solc``/``forge``) surface as UNAVAILABLE and are never faked.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.discovery.bounty.advisories import (
    advisory_dict,
    match_advisories,
    precondition_graphs,
)
from app.discovery.bounty.campaign import BountyManifest
from app.discovery.bounty.compiler_diff import NoCompilerBackend, run_differential
from app.discovery.bounty.engine import build_bounty_engines, load_sources
from app.discovery.bounty.findings import ResearchFinding, build_findings
from app.discovery.bounty.gate import BountyGate
from app.discovery.bounty.priority import prioritize
from app.discovery.bounty.report_pack import ReportPack, build_report_pack
from app.discovery.bounty.vfcs import MAX_VFCS_CANDIDATES, SequenceIdentity, Vfcs, generate
from app.discovery.builtin import BugforgeStaticEngine
from app.discovery.corpus import DiscoveryCorpus
from app.discovery.engine import AnalysisRequest, DiscoveryEngine
from app.discovery.orchestration import CampaignIdentity, MemoryStore, Orchestrator
from app.discovery.orchestration.model import EvidenceItem, ResearchState
from app.discovery.scheduler import DiscoveryScheduler
from app.parsing.solidity_research import SemanticCandidate, build_research_model
from app.parsing.solidity_research_suite import run_suite

MAX_CAMPAIGNS = 256
MAX_FILES_PER_REQUEST = 64
DEFAULT_MAX_ROUNDS = 16
DEFAULT_MAX_ENGINES = 16
# Only an operator may ever approve these. The AI and the MCP server cannot.
APPROVABLE_CAPABILITIES = frozenset({"fork_validation"})


class CampaignError(ValueError):
    """The campaign request is malformed or refers to something unavailable."""


class UnknownCampaignError(KeyError):
    """No campaign exists for the identifier."""


@dataclass(frozen=True)
class CampaignSpec:
    manifest: BountyManifest
    repo_root: Path
    target: str = ""
    contract: str = ""
    function: str = ""
    source_file: str = ""
    files: tuple[str, ...] = ()
    language: str = "solidity"
    max_rounds: int = DEFAULT_MAX_ROUNDS
    max_engines: int = DEFAULT_MAX_ENGINES


@dataclass
class BountyCampaign:
    """One live campaign. Holds the orchestrator plus the derived identity."""

    campaign_id: str
    spec: CampaignSpec
    identity: CampaignIdentity
    request: AnalysisRequest
    orchestrator: Orchestrator
    operator_identity: str = ""
    approvals: frozenset[str] = frozenset()
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def manifest(self) -> BountyManifest:
        return self.spec.manifest

    @property
    def state(self) -> ResearchState:
        return self.orchestrator.state


def _sanitize_files(files: tuple[str, ...]) -> tuple[str, ...]:
    chosen: list[str] = []
    for name in files:
        text = str(name).strip()
        if not text or ".." in text or text.startswith("/"):
            raise CampaignError(f"unsafe file reference: {name!r}")
        chosen.append(text)
        if len(chosen) >= MAX_FILES_PER_REQUEST:
            break
    return tuple(chosen)


class BountyCampaignService:
    """In-process registry of campaigns. One instance is shared by the API."""

    def __init__(self) -> None:
        self._campaigns: dict[str, BountyCampaign] = {}
        self._guard = threading.Lock()

    # ---- lifecycle ----------------------------------------------------------------------

    def create(self, spec: CampaignSpec, *, operator_identity: str = "") -> BountyCampaign:
        root = spec.repo_root.resolve()
        if not root.is_dir():
            raise CampaignError(f"repository root is not a directory: {root}")
        files = _sanitize_files(spec.files)
        identity = spec.manifest.to_campaign_identity(
            contract=spec.contract,
            function=spec.function,
            source_file=spec.source_file,
            repository_root=str(root),
        )
        extra = {"project_id": spec.manifest.program_id, **spec.manifest.request_extra()}
        request = AnalysisRequest(
            repo_root=root,
            language=spec.language,
            target=spec.target or spec.contract or spec.manifest.program_id,
            contract=spec.contract,
            function=spec.function,
            source_file=spec.source_file,
            files=files,
            campaign_id=identity.campaign_id,
            extra=extra,
        )
        scheduler = self._build_scheduler(spec)
        orchestrator = Orchestrator(
            scheduler,
            request,
            identity=identity,
            gate=BountyGate(spec.manifest, approvals=frozenset()),
            store=MemoryStore(),
            max_rounds=spec.max_rounds,
        )
        orchestrator.start()
        campaign = BountyCampaign(
            campaign_id=identity.campaign_id,
            spec=spec,
            identity=identity,
            request=request,
            orchestrator=orchestrator,
            operator_identity=operator_identity,
        )
        with self._guard:
            if (
                len(self._campaigns) >= MAX_CAMPAIGNS
                and identity.campaign_id not in self._campaigns
            ):
                raise CampaignError("the campaign registry is full")
            self._campaigns[identity.campaign_id] = campaign
        return campaign

    def _build_scheduler(self, spec: CampaignSpec) -> DiscoveryScheduler:
        engines: list[DiscoveryEngine] = [
            BugforgeStaticEngine(),
            *build_bounty_engines(spec.manifest),
        ]
        return DiscoveryScheduler(
            engines=tuple(engines),
            max_engines=spec.max_engines,
            max_rounds=spec.max_rounds,
            corpus=DiscoveryCorpus(),
        )

    def get(self, campaign_id: str) -> BountyCampaign:
        campaign = self._campaigns.get(campaign_id)
        if campaign is None:
            raise UnknownCampaignError(campaign_id)
        return campaign

    def list_ids(self) -> list[str]:
        return sorted(self._campaigns)

    # ---- advancing ----------------------------------------------------------------------

    def analyze(self, campaign_id: str) -> dict[str, Any]:
        campaign = self.get(campaign_id)
        with campaign.lock:
            campaign.orchestrator.run()
        return self.report(campaign_id)

    def step(self, campaign_id: str, *, capability: str = "", reason: str = "") -> dict[str, Any]:
        campaign = self.get(campaign_id)
        with campaign.lock:
            if capability:
                campaign.orchestrator.suggest(capability, reason=reason or "operator execute")
            progressed = campaign.orchestrator.step()
        result = self.report(campaign_id)
        result["progressed"] = progressed
        return result

    def suggest(
        self, campaign_id: str, capability: str, *, engine: str = "", reason: str = ""
    ) -> bool:
        """Queue a Cursor/operator suggestion. It is validated like any candidate.

        A suggestion is a hint only; it cannot widen scope, raise budget, or
        enable a gated capability.
        """
        campaign = self.get(campaign_id)
        with campaign.lock:
            return campaign.orchestrator.suggest(capability, engine=engine, reason=reason)

    def pause(self, campaign_id: str, *, reason: str = "operator") -> dict[str, Any]:
        # The orchestrator is bounded and deterministic; pausing simply records
        # that the operator stopped advancing it. No state transition is forced.
        self.get(campaign_id)
        state = self.report(campaign_id)
        state["paused"] = True
        state["pause_reason"] = reason
        return state

    def resume(self, campaign_id: str) -> dict[str, Any]:
        campaign = self.get(campaign_id)
        with campaign.lock:
            campaign.orchestrator.start(explicit_resume=True)
        return self.report(campaign_id)

    def stop(self, campaign_id: str, *, reason: str = "operator") -> dict[str, Any]:
        self.get(campaign_id)
        state = self.report(campaign_id)
        state["stopped_by_operator"] = True
        state["stop_requested_reason"] = reason
        return state

    # ---- operator approvals (human only) ------------------------------------------------

    def grant_approval(self, campaign_id: str, capability: str) -> frozenset[str]:
        """Record an operator approval for a gated capability.

        The caller must already have proven it is a human operator; this method
        makes no authority decision of its own beyond refusing capabilities that
        are not approvable at all.
        """
        if capability not in APPROVABLE_CAPABILITIES:
            raise CampaignError(f"capability is not approvable: {capability!r}")
        campaign = self.get(campaign_id)
        with campaign.lock:
            campaign.approvals = campaign.approvals | {capability}
            campaign.orchestrator.gate = BountyGate(campaign.manifest, approvals=campaign.approvals)
        return campaign.approvals

    # ---- reads --------------------------------------------------------------------------

    def report(self, campaign_id: str) -> dict[str, Any]:
        campaign = self.get(campaign_id)
        report = dict(campaign.orchestrator.report())
        report["program_context"] = campaign.manifest.identity_digest()
        report["scope_summary"] = self._scope_summary(campaign)
        report["manifest_gaps"] = list(campaign.manifest.gaps())
        report["approvals"] = sorted(campaign.approvals)
        report["verified"] = False
        report["submitted"] = False
        report["llm_invoked"] = False
        return report

    def next_action(self, campaign_id: str) -> dict[str, Any]:
        campaign = self.get(campaign_id)
        state = campaign.state
        return {
            "campaign_id": campaign_id,
            "state": state.state.value,
            "next_capability": state.next_capability,
            "uncertainties": list(state.uncertainties),
            "stop_reason": state.stop_reason,
            "recommend_verification_review": state.recommend_verification_review,
            "note": "a recommendation only; it verifies nothing and grants no approval",
        }

    def evidence(self, campaign_id: str) -> dict[str, Any]:
        campaign = self.get(campaign_id)
        return {
            "campaign_id": campaign_id,
            "verified": False,
            "evidence": [self._evidence_dict(item) for item in campaign.state.evidence],
            "contradictions": [
                {
                    "id": item.contradiction_id,
                    "kind": item.kind,
                    "identity": item.identity_key,
                    "status": item.status,
                }
                for item in campaign.state.contradictions
            ],
        }

    def findings(self, campaign_id: str) -> dict[str, Any]:
        campaign = self.get(campaign_id)
        candidates, sequences = self._candidates_and_sequences(campaign)
        findings = build_findings(
            candidates,
            manifest=campaign.manifest,
            identity=campaign.identity,
            state=campaign.state,
            sequences=sequences,
        )
        return {
            "campaign_id": campaign_id,
            "verified": False,
            "findings": [self._finding_dict(item) for item in findings],
        }

    def repro(self, campaign_id: str) -> dict[str, Any]:
        """Return the deterministic VFCS call-sequence plans.

        These are *plans* derived from static candidates; a plan is not an
        execution and nothing here runs against any network.
        """
        campaign = self.get(campaign_id)
        _candidates, sequences = self._candidates_and_sequences(campaign)
        return {
            "campaign_id": campaign_id,
            "note": "call-sequence plans from static candidates; plans are not executions",
            "verified": False,
            "sequences": [
                {
                    "sequence_id": seq.sequence_id,
                    "template": seq.template,
                    "derived_from": seq.derived_from,
                    "calls": [call.identity for call in seq.calls],
                }
                for seq in sequences
            ],
        }

    def report_pack(self, campaign_id: str) -> ReportPack:
        campaign = self.get(campaign_id)
        candidates, sequences = self._candidates_and_sequences(campaign)
        findings = build_findings(
            candidates,
            manifest=campaign.manifest,
            identity=campaign.identity,
            state=campaign.state,
            sequences=sequences,
        )
        sources = load_sources(campaign.request)
        advisories = match_advisories(campaign.manifest.compiler, sources)
        differential = run_differential(sources, backend=NoCompilerBackend())
        model = build_research_model(sources) if sources else None
        priority = (
            prioritize(model, manifest=campaign.manifest, candidates=candidates)
            if model is not None
            else None
        )
        return build_report_pack(
            manifest=campaign.manifest,
            identity=campaign.identity,
            findings=findings,
            sequences=sequences,
            state=campaign.state,
            advisories=advisories,
            differential=differential,
            priority=priority,
            tools=self._tool_availability(campaign),
        )

    def advisories(self, campaign_id: str) -> dict[str, Any]:
        campaign = self.get(campaign_id)
        sources = load_sources(campaign.request)
        report = advisory_dict(match_advisories(campaign.manifest.compiler, sources))
        report["precondition_graphs"] = [
            graph.as_dict() for graph in precondition_graphs(campaign.manifest.compiler, sources)
        ]
        return report

    # ---- helpers ------------------------------------------------------------------------

    def _candidates_and_sequences(
        self, campaign: BountyCampaign
    ) -> tuple[tuple[SemanticCandidate, ...], tuple[Vfcs, ...]]:
        sources = load_sources(campaign.request)
        if not sources:
            return (), ()
        model = build_research_model(sources)
        suite = run_suite(model)
        identity = SequenceIdentity(
            campaign_id=campaign.identity.campaign_id,
            source_snapshot=campaign.manifest.source_commit,
            compiler_configuration=campaign.manifest.compiler.fingerprint(),
            fork_reference=campaign.manifest.fork_reference(),
            program_context=campaign.manifest.identity_digest(),
        )
        built = generate(model, suite.candidates, identity, limit=MAX_VFCS_CANDIDATES)
        return suite.candidates, built.sequences

    def _tool_availability(self, campaign: BountyCampaign) -> dict[str, str]:
        diff_engine = next(
            (
                e
                for e in campaign.orchestrator.scheduler.engines
                if e.engine_id == "bugforge-compiler-diff"
            ),
            None,
        )
        solc = (
            "available"
            if diff_engine and diff_engine.availability().value == "available"
            else "unavailable"
        )
        return {
            "bugforge-research": "available",
            "bugforge-static": "available",
            "bugforge-compiler-diff": solc,
            "solc": solc,
            "forge": "unavailable",
        }

    def _scope_summary(self, campaign: BountyCampaign) -> dict[str, str]:
        scope = campaign.manifest.scope_of(
            contract=campaign.spec.contract, file=campaign.spec.source_file
        )
        return {"status": scope.status.value, "reason": scope.reason}

    @staticmethod
    def _evidence_dict(item: EvidenceItem) -> dict[str, Any]:
        return {
            "evidence_id": item.evidence_id,
            "kind": item.kind,
            "quality": item.quality.value,
            "engine": item.engine,
            "capability": item.capability,
            "identity_key": item.identity_key,
            "polarity": item.polarity,
            "verified": item.attrs.get("verified", "false"),
        }

    @staticmethod
    def _finding_dict(item: ResearchFinding) -> dict[str, Any]:
        return {
            "finding_id": item.finding_id,
            "title": item.title,
            "detector": item.detector,
            "family": item.family,
            "contract": item.contract,
            "function": item.function,
            "file": item.file,
            "line": item.line,
            "scope_status": item.scope_status,
            "severity_candidate": item.severity_candidate,
            "confirmed_severity": item.confirmed_severity,
            "poc_status": item.poc_status,
            "evidence_quality": item.evidence_quality,
            "sequence_ids": list(item.sequence_ids),
            "open_contradictions": list(item.open_contradictions),
            "known_issue": item.known_issue.issue_id if item.known_issue else "",
            "duplicate_of": item.duplicate_of,
            "qualification": item.qualification.status,
            "verified": item.verified,
            "submitted": item.submitted,
        }


_SERVICE: BountyCampaignService | None = None


def get_bounty_service() -> BountyCampaignService:
    """Return the process-wide campaign service (lazily created)."""
    global _SERVICE
    if _SERVICE is None:
        _SERVICE = BountyCampaignService()
    return _SERVICE
