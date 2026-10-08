"""Operational bounty-campaign service (Phase 51, hardened).

This is the operational layer that makes the Phase 49 orchestrator and the
Phase 50 bounty engines reachable from the API and the Cursor MCP server. It
*reuses* the existing stack and introduces no parallel session, evidence store,
or authority model:

* identity is :class:`CampaignIdentity` derived from :class:`BountyManifest`;
* execution is the Phase 49 :class:`Orchestrator` over :class:`DiscoveryScheduler`;
* state is persisted through the Phase 49 ``SqlStore`` (via
  :mod:`app.discovery.bounty.persistence`), so a campaign survives a restart;
* the gate is :class:`BountyGate` (which wraps the Phase 49 ``DefaultGate``);
* pause/stop are real Phase 49 state-machine stops (``operator_paused`` is
  resumable, ``operator_stopped`` is final) taken under the campaign lock, so a
  concurrent execute cannot run an engine past them;
* expensive work runs as a bounded background job on a worker thread;
* findings, VFCS plans, advisories, and the report pack are the Phase 50 modules.

The service never calls a model, never marks a finding verified, never raises a
budget, and never grants an approval to itself. Fork testing stays gated on an
operator-granted approval that only the human-only API path can set. Missing
optional tools surface as UNAVAILABLE and are never faked.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from app.discovery.bounty.campaign import BountyManifest, ManifestError

if TYPE_CHECKING:
    from app.discovery.bounty.analysis import CampaignAnalysis
    from app.discovery.bounty.compiler_diff import DifferentialResult
    from app.discovery.bounty.report_pack import ReportPack
from app.discovery.bounty.source_selection import (
    DEFAULT_LIMIT,
    SourceSelection,
    select_sources,
)
from app.discovery.engine import AnalysisRequest, DiscoveryEngine
from app.discovery.orchestration import CampaignIdentity, Orchestrator
from app.discovery.orchestration.model import (
    TERMINAL,
    OrchestratorState,
    PersistenceError,
    ResearchState,
    ResumeError,
    StopReason,
)
from app.discovery.scheduler import DiscoveryScheduler
from app.services.bounty_campaign_store import (
    CampaignConflictError,
    CampaignPersistenceError,
    CampaignRecord,
    CampaignRecordStore,
    RunnerSqlStore,
    SessionRunner,
    ensure_schema,
    runner_from_settings,
)

# The research engine and campaign records carry this version. Records written by
# earlier phases keep the version they were written with; nothing rewrites them.
ENGINE_VERSION = "phase51.1"
MAX_CAMPAIGNS = 256
MAX_FILES_PER_REQUEST = 64
DEFAULT_MAX_ROUNDS = 16
DEFAULT_MAX_ENGINES = 16
MAX_JOB_STEPS = 64
JOB_WORKERS = 2
# Only an operator may ever approve these. The AI and the MCP server cannot.
APPROVABLE_CAPABILITIES = frozenset({"fork_validation"})
CONTROL_ACTIVE = "active"
CONTROL_PAUSED = "paused"
CONTROL_STOPPED = "stopped"
JOB_IDLE = "idle"
JOB_ACTIVE = frozenset({"queued", "running"})


class CampaignError(ValueError):
    """The campaign request is malformed or refers to something unavailable."""


class UnknownCampaignError(KeyError):
    """No campaign exists for the identifier."""


class CampaignControlError(CampaignError):
    """The campaign's control state (paused, stopped, busy) refuses the action."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


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
    # Target deployment (Phase 51 hardening): the address and chain the operator
    # is researching. Never inferred from the source.
    address: str = ""
    chain_id: str = ""
    source_limit: int = DEFAULT_LIMIT

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_root": str(self.repo_root),
            "target": self.target,
            "contract": self.contract,
            "function": self.function,
            "source_file": self.source_file,
            "files": list(self.files),
            "language": self.language,
            "max_rounds": self.max_rounds,
            "max_engines": self.max_engines,
            "address": self.address,
            "chain_id": self.chain_id,
            "source_limit": self.source_limit,
        }

    @staticmethod
    def from_record(manifest: BountyManifest, data: dict[str, Any]) -> CampaignSpec:
        return CampaignSpec(
            manifest=manifest,
            repo_root=Path(str(data.get("repo_root", ""))),
            target=str(data.get("target", "")),
            contract=str(data.get("contract", "")),
            function=str(data.get("function", "")),
            source_file=str(data.get("source_file", "")),
            files=tuple(str(item) for item in data.get("files", [])),
            language=str(data.get("language", "solidity")),
            max_rounds=int(data.get("max_rounds", DEFAULT_MAX_ROUNDS)),
            max_engines=int(data.get("max_engines", DEFAULT_MAX_ENGINES)),
            address=str(data.get("address", "")),
            chain_id=str(data.get("chain_id", "")),
            source_limit=int(data.get("source_limit", DEFAULT_LIMIT)),
        )


@dataclass
class BountyCampaign:
    """One live campaign: the orchestrator, the derived identity, and its record."""

    campaign_id: str
    spec: CampaignSpec
    identity: CampaignIdentity
    request: AnalysisRequest
    orchestrator: Orchestrator
    record: CampaignRecord
    selection: SourceSelection
    lock: threading.RLock = field(default_factory=threading.RLock)
    cache: dict[str, Any] = field(default_factory=dict)

    @property
    def manifest(self) -> BountyManifest:
        return self.spec.manifest

    @property
    def state(self) -> ResearchState:
        return self.orchestrator.state

    @property
    def operator_identity(self) -> str:
        return self.record.operator_identity

    @property
    def approvals(self) -> frozenset[str]:
        return frozenset(str(item.get("capability", "")) for item in self.record.approvals)

    @property
    def control(self) -> str:
        return self.record.control


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


def _validate_target(spec: CampaignSpec) -> None:
    import re

    if spec.address and not re.fullmatch(r"0x[0-9a-fA-F]{40}", spec.address):
        raise CampaignError(f"target address {spec.address!r} is not an address")
    if spec.chain_id and not re.fullmatch(r"[0-9]{1,12}", spec.chain_id):
        raise CampaignError(f"chain id {spec.chain_id!r} is not a decimal chain id")
    if spec.chain_id and not spec.address:
        raise CampaignError("a chain id without an address names no deployment")


class BountyCampaignService:
    """Persistent registry of campaigns. One instance is shared by the API."""

    def __init__(
        self,
        runner: SessionRunner | None = None,
        *,
        engine_factory: Callable[[CampaignSpec], tuple[DiscoveryEngine, ...]] | None = None,
        job_workers: int = JOB_WORKERS,
    ) -> None:
        self._runner = runner or runner_from_settings()
        self._schema_ready = False
        self._store = RunnerSqlStore(self._runner)
        self._records = CampaignRecordStore(self._runner)
        self._campaigns: dict[str, BountyCampaign] = {}
        self._guard = threading.Lock()
        self._engine_factory = engine_factory
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, job_workers), thread_name_prefix="bounty-campaign"
        )
        self._jobs: dict[str, Future[None]] = {}
        self._halt: dict[str, StopReason] = {}

    # ---- persistence plumbing ---------------------------------------------------------

    def _ready(self) -> None:
        if not self._schema_ready:
            ensure_schema(self._runner)
            self._schema_ready = True

    @property
    def persistence(self) -> str:
        return self._runner.describe()

    def _save_record(self, campaign: BountyCampaign) -> None:
        try:
            campaign.record = self._records.update(campaign.record)
        except CampaignConflictError:
            self._evict(campaign.campaign_id)
            raise

    def _evict(self, campaign_id: str) -> None:
        with self._guard:
            self._campaigns.pop(campaign_id, None)
        self._store.forget(campaign_id)

    # ---- lifecycle ----------------------------------------------------------------------

    def create(self, spec: CampaignSpec, *, operator_identity: str = "") -> BountyCampaign:
        self._ready()
        root = spec.repo_root.resolve()
        if not root.is_dir():
            raise CampaignError(f"repository root is not a directory: {root}")
        _validate_target(spec)
        spec = CampaignSpec(**{**spec.__dict__, "repo_root": root})
        identity = self._identity(spec)
        existing = self._records.get(identity.campaign_id)
        if existing is not None:
            if existing.operator_identity and existing.operator_identity != operator_identity:
                raise CampaignConflictError("campaign exists and belongs to another operator")
            return self.get(identity.campaign_id)
        with self._guard:
            if len(self._campaigns) >= MAX_CAMPAIGNS:
                raise CampaignError("the campaign registry is full")
        campaign = self._build(spec, identity, record=None, operator_identity=operator_identity)
        with self._guard:
            self._campaigns[campaign.campaign_id] = campaign
        return campaign

    def _identity(self, spec: CampaignSpec) -> CampaignIdentity:
        identity = spec.manifest.to_campaign_identity(
            contract=spec.contract,
            function=spec.function,
            source_file=spec.source_file,
            repository_root=str(spec.repo_root),
        )
        if spec.address:
            deployment = f"{spec.chain_id}:{spec.address.lower()}"
            base = CampaignIdentity(**{**identity.__dict__, "campaign_id": ""})
            base = CampaignIdentity(**{**base.__dict__, "deployment": deployment})
            identity = CampaignIdentity(
                **{**base.__dict__, "campaign_id": f"cp_{base.target_digest()}"}
            )
        return identity

    def _selection(self, spec: CampaignSpec, files: tuple[str, ...]) -> SourceSelection:
        if files:
            return SourceSelection.explicit(files)
        return select_sources(
            spec.repo_root,
            manifest=spec.manifest,
            focus_contract=spec.contract,
            focus_file=spec.source_file,
            limit=max(1, min(spec.source_limit, MAX_FILES_PER_REQUEST)),
        )

    def _build(
        self,
        spec: CampaignSpec,
        identity: CampaignIdentity,
        *,
        record: CampaignRecord | None,
        operator_identity: str = "",
    ) -> BountyCampaign:
        files = _sanitize_files(spec.files)
        selection = self._selection(spec, files)
        chosen = files or selection.selected
        extra = {"project_id": spec.manifest.program_id, **spec.manifest.request_extra()}
        extra.update(selection.request_extra())
        if spec.address:
            extra["deployment_address"] = spec.address.lower()
            extra["deployment_chain_id"] = spec.chain_id
        request = AnalysisRequest(
            repo_root=spec.repo_root,
            language=spec.language,
            target=spec.target or spec.contract or spec.manifest.program_id,
            contract=spec.contract,
            function=spec.function,
            source_file=spec.source_file,
            files=chosen,
            campaign_id=identity.campaign_id,
            extra=extra,
        )
        approvals = (
            frozenset(str(a.get("capability", "")) for a in record.approvals)
            if record
            else frozenset()
        )
        from app.discovery.bounty.gate import BountyGate

        orchestrator = Orchestrator(
            self._build_scheduler(spec),
            request,
            identity=identity,
            gate=BountyGate(spec.manifest, approvals=approvals),
            store=self._store,
            max_rounds=spec.max_rounds,
        )
        try:
            orchestrator.start()
        except ResumeError as exc:
            raise CampaignError(f"stored campaign cannot be restored: {exc}") from exc
        if record is None:
            record = self._records.insert(
                CampaignRecord(
                    campaign_id=identity.campaign_id,
                    operator_identity=operator_identity,
                    engine_version=ENGINE_VERSION,
                    program_context=spec.manifest.identity_digest(),
                    manifest=spec.manifest.to_dict(),
                    spec=spec.to_dict(),
                    artifacts={"source_selection": selection.as_dict()},
                )
            )
        elif record.job.get("status") in JOB_ACTIVE and identity.campaign_id not in self._jobs:
            # A job that was running when the process stopped did not finish.
            record.job = {**record.job, "status": "interrupted", "finished_at": _now()}
            record = self._records.update(record)
        return BountyCampaign(
            campaign_id=identity.campaign_id,
            spec=spec,
            identity=identity,
            request=request,
            orchestrator=orchestrator,
            record=record,
            selection=selection,
        )

    def _build_scheduler(self, spec: CampaignSpec) -> DiscoveryScheduler:
        if self._engine_factory is not None:
            engines = self._engine_factory(spec)
        else:
            from app.discovery.bounty.engine import build_bounty_engines
            from app.discovery.builtin import BugforgeStaticEngine

            engines = (BugforgeStaticEngine(), *build_bounty_engines(spec.manifest))
        from app.discovery.corpus import DiscoveryCorpus

        return DiscoveryScheduler(
            engines=tuple(engines),
            max_engines=spec.max_engines,
            max_rounds=spec.max_rounds,
            corpus=DiscoveryCorpus(),
        )

    def get(self, campaign_id: str) -> BountyCampaign:
        with self._guard:
            cached = self._campaigns.get(campaign_id)
        if cached is not None:
            return cached
        self._ready()
        record = self._records.get(campaign_id)
        if record is None:
            raise UnknownCampaignError(campaign_id)
        try:
            manifest = BountyManifest.from_dict(record.manifest)
        except ManifestError as exc:
            raise CampaignError(f"stored manifest is invalid: {exc}") from exc
        spec = CampaignSpec.from_record(manifest, record.spec)
        identity = self._identity(spec)
        if identity.campaign_id != campaign_id:
            raise CampaignError("stored campaign no longer derives the same identity")
        campaign = self._build(spec, identity, record=record)
        with self._guard:
            existing = self._campaigns.setdefault(campaign_id, campaign)
        return existing

    def list_ids(self, operator_identity: str | None = None) -> list[str]:
        self._ready()
        return self._records.list_ids(operator_identity)

    def reload(self, campaign_id: str) -> BountyCampaign:
        """Drop the in-process copy and rebuild from storage (used after a conflict)."""
        self._evict(campaign_id)
        return self.get(campaign_id)

    # ---- advancing ----------------------------------------------------------------------

    def _check_runnable(self, campaign: BountyCampaign, *, from_job: bool = False) -> None:
        if campaign.control == CONTROL_STOPPED:
            raise CampaignControlError("campaign is stopped by the operator")
        if campaign.control == CONTROL_PAUSED:
            raise CampaignControlError("campaign is paused; resume it first")
        if not from_job and campaign.record.job.get("status") in JOB_ACTIVE:
            raise CampaignControlError("a background job is advancing this campaign")

    def _step_locked(self, campaign: BountyCampaign) -> bool:
        try:
            progressed = campaign.orchestrator.step()
        except CampaignConflictError:
            self._evict(campaign.campaign_id)
            raise
        campaign.cache.clear()
        return progressed

    def analyze(self, campaign_id: str, *, max_steps: int = MAX_JOB_STEPS) -> dict[str, Any]:
        """Run the bounded campaign synchronously (callers run this off the event loop)."""
        campaign = self.get(campaign_id)
        steps = 0
        while steps < max_steps:
            if self._halt.get(campaign_id) is not None:
                break
            with campaign.lock:
                self._check_runnable(campaign, from_job=True)
                if campaign.record.job.get("status") in JOB_ACTIVE and not self._is_job_thread(
                    campaign_id
                ):
                    raise CampaignControlError("a background job is advancing this campaign")
                progressed = self._step_locked(campaign)
            steps += 1
            if not progressed:
                break
        self._after_run(campaign)
        return self.report(campaign_id)

    def step(self, campaign_id: str, *, capability: str = "", reason: str = "") -> dict[str, Any]:
        campaign = self.get(campaign_id)
        with campaign.lock:
            self._check_runnable(campaign)
            if capability:
                campaign.orchestrator.suggest(capability, reason=reason or "operator execute")
            progressed = self._step_locked(campaign)
        self._after_run(campaign)
        result = self.report(campaign_id)
        result["progressed"] = progressed
        return result

    def _after_run(self, campaign: BountyCampaign) -> None:
        """Hook for post-orchestrator campaign work (VFCS stateful loop, artifacts)."""
        return None

    def suggest(
        self, campaign_id: str, capability: str, *, engine: str = "", reason: str = ""
    ) -> bool:
        """Queue a Cursor/operator suggestion. It is validated like any candidate.

        A suggestion is a hint only; it cannot widen scope, raise budget, or
        enable a gated capability.
        """
        campaign = self.get(campaign_id)
        with campaign.lock:
            if campaign.control != CONTROL_ACTIVE:
                return False
            return campaign.orchestrator.suggest(capability, engine=engine, reason=reason)

    # ---- control: pause / resume / stop ------------------------------------------------

    def pause(self, campaign_id: str, *, reason: str = "operator") -> dict[str, Any]:
        return self._halt_campaign(campaign_id, StopReason.OPERATOR_PAUSED, reason)

    def stop(self, campaign_id: str, *, reason: str = "operator") -> dict[str, Any]:
        return self._halt_campaign(campaign_id, StopReason.OPERATOR_STOPPED, reason)

    def _halt_campaign(self, campaign_id: str, reason: StopReason, detail: str) -> dict[str, Any]:
        campaign = self.get(campaign_id)
        if campaign.control == CONTROL_STOPPED:
            raise CampaignControlError("campaign is already stopped")
        # Signal a running job first so it halts at the next round boundary.
        self._halt[campaign_id] = reason
        try:
            with campaign.lock:  # waits for any in-flight round to finish
                changed = campaign.orchestrator.halt(reason, detail=detail[:200])
                campaign.record.control = (
                    CONTROL_PAUSED if reason is StopReason.OPERATOR_PAUSED else CONTROL_STOPPED
                )
                campaign.record.control_reason = detail[:200]
                self._save_record(campaign)
        finally:
            self._halt.pop(campaign_id, None)
        state = self.report(campaign_id)
        state["state_changed"] = changed
        return state

    def resume(self, campaign_id: str) -> dict[str, Any]:
        campaign = self.get(campaign_id)
        with campaign.lock:
            if campaign.control == CONTROL_STOPPED:
                raise CampaignControlError("a stopped campaign is final and cannot be resumed")
            if campaign.record.job.get("status") in JOB_ACTIVE:
                raise CampaignControlError("a background job is advancing this campaign")
            try:
                campaign.orchestrator.start(explicit_resume=True)
            except CampaignConflictError:
                self._evict(campaign_id)
                raise
            except ResumeError as exc:
                raise CampaignError(f"campaign cannot be resumed: {exc}") from exc
            campaign.record.control = CONTROL_ACTIVE
            campaign.record.control_reason = ""
            self._save_record(campaign)
            campaign.cache.clear()
        return self.report(campaign_id)

    # ---- background jobs -----------------------------------------------------------------

    def _is_job_thread(self, campaign_id: str) -> bool:
        return threading.current_thread().name.startswith("bounty-campaign") and bool(
            self._jobs.get(campaign_id)
        )

    def start_job(self, campaign_id: str, *, max_steps: int = MAX_JOB_STEPS) -> dict[str, Any]:
        """Queue the bounded campaign run on a worker thread and return immediately."""
        campaign = self.get(campaign_id)
        with campaign.lock:
            self._check_runnable(campaign)
            if campaign.state.state in TERMINAL:
                raise CampaignControlError(
                    f"campaign is {campaign.state.state.value}; nothing remains to run"
                )
            job_id = f"job_{uuid.uuid4().hex[:12]}"
            campaign.record.job = {
                "job_id": job_id,
                "status": "queued",
                "steps": 0,
                "max_steps": max(1, min(max_steps, MAX_JOB_STEPS)),
                "queued_at": _now(),
                "started_at": "",
                "finished_at": "",
                "error": "",
            }
            self._save_record(campaign)
            future = self._executor.submit(self._run_job, campaign_id, job_id)
            self._jobs[campaign_id] = future
        return self.progress(campaign_id)

    def _run_job(self, campaign_id: str, job_id: str) -> None:
        campaign = self.get(campaign_id)
        try:
            with campaign.lock:
                if campaign.record.job.get("job_id") != job_id:
                    return
                campaign.record.job.update({"status": "running", "started_at": _now()})
                self._save_record(campaign)
            limit = int(campaign.record.job.get("max_steps", MAX_JOB_STEPS))
            outcome = "completed"
            for _ in range(limit):
                if self._halt.get(campaign_id) is not None:
                    outcome = "halted"
                    break
                with campaign.lock:
                    if campaign.control != CONTROL_ACTIVE:
                        outcome = "halted"
                        break
                    progressed = self._step_locked(campaign)
                    campaign.record.job["steps"] = int(campaign.record.job.get("steps", 0)) + 1
                    campaign.record.job["round"] = campaign.state.round
                    campaign.record.job["state"] = campaign.state.state.value
                    self._save_record(campaign)
                if not progressed:
                    break
            if outcome == "completed":
                self._after_run(campaign)
            with campaign.lock:
                campaign.record.job.update({"status": outcome, "finished_at": _now()})
                self._save_record(campaign)
        except Exception as exc:  # recorded, never swallowed silently
            try:
                fresh = self.reload(campaign_id)
                with fresh.lock:
                    fresh.record.job.update(
                        {
                            "status": "failed",
                            "finished_at": _now(),
                            "error": f"{type(exc).__name__}: {exc}"[:300],
                        }
                    )
                    self._save_record(fresh)
            except Exception:
                pass
        finally:
            self._jobs.pop(campaign_id, None)

    def wait_for_job(self, campaign_id: str, timeout: float = 300.0) -> dict[str, Any]:
        future = self._jobs.get(campaign_id)
        if future is not None:
            future.result(timeout=timeout)
        return self.progress(campaign_id)

    def progress(self, campaign_id: str) -> dict[str, Any]:
        campaign = self.get(campaign_id)
        state = campaign.state
        job = dict(campaign.record.job) or {"status": JOB_IDLE}
        return {
            "campaign_id": campaign_id,
            "control": campaign.control,
            "control_reason": campaign.record.control_reason,
            "job": job,
            "state": state.state.value,
            "stop_reason": state.stop_reason,
            "round": state.round,
            "decisions": state.decision_number,
            "budget_remaining": {
                name: state.budget.remaining(name) for name in sorted(state.budget.limits)
            },
            "verified": False,
        }

    # ---- operator approvals (human only) ------------------------------------------------

    def grant_approval(
        self, campaign_id: str, capability: str, *, granted_by: str = ""
    ) -> frozenset[str]:
        """Record an operator approval for a gated capability.

        The caller must already have proven it is a human operator; this method
        makes no authority decision of its own beyond refusing capabilities that
        are not approvable at all. The approval is persisted with its grantor.
        """
        if capability not in APPROVABLE_CAPABILITIES:
            raise CampaignError(f"capability is not approvable: {capability!r}")
        campaign = self.get(campaign_id)
        with campaign.lock:
            if capability not in campaign.approvals:
                campaign.record.approvals.append(
                    {"capability": capability, "granted_by": granted_by, "granted_at": _now()}
                )
                self._save_record(campaign)
            from app.discovery.bounty.gate import BountyGate

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
        report["control"] = campaign.control
        report["control_reason"] = campaign.record.control_reason
        report["paused"] = campaign.control == CONTROL_PAUSED
        report["stopped_by_operator"] = campaign.control == CONTROL_STOPPED
        report["job"] = dict(campaign.record.job) or {"status": JOB_IDLE}
        report["engine_version"] = campaign.record.engine_version
        report["persistence"] = self.persistence
        report["source_selection"] = {
            "truncated": campaign.selection.truncated,
            "selected": len(campaign.selection.selected),
            "considered": campaign.selection.considered,
            "mode": campaign.selection.mode,
        }
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
            "control": campaign.control,
            "next_capability": state.next_capability,
            "uncertainties": list(state.uncertainties),
            "stop_reason": state.stop_reason,
            "recommend_verification_review": state.recommend_verification_review,
            "note": "a recommendation only; it verifies nothing and grants no approval",
        }

    def decisions(self, campaign_id: str) -> dict[str, Any]:
        campaign = self.get(campaign_id)
        records = self._store.decisions(campaign_id)
        return {
            "campaign_id": campaign_id,
            "decisions": [
                {
                    "sequence": item.sequence,
                    "round": item.round,
                    "source": item.source.value,
                    "phase": item.phase.value,
                    "selected_capability": item.selected_capability,
                    "selected_engine": item.selected_engine,
                    "stop_reason": item.stop_reason,
                    "rationale": item.rationale,
                    "record_hash": item.record_hash,
                }
                for item in records
            ],
            "count": len(records),
            "state": campaign.state.state.value,
        }

    def _scope_summary(self, campaign: BountyCampaign) -> dict[str, str]:
        scope = campaign.manifest.scope_of(
            contract=campaign.spec.contract,
            file=campaign.spec.source_file,
            address=campaign.spec.address,
            chain_id=campaign.spec.chain_id,
        )
        return {"status": scope.status.value, "reason": scope.reason}

    def source_selection(self, campaign_id: str) -> dict[str, Any]:
        """Truncation-aware ranking of the repo's sources. Dropped != safe."""
        campaign = self.get(campaign_id)
        return {"campaign_id": campaign_id, **campaign.selection.as_dict()}


    # ---- analysis-backed reads ----------------------------------------------------------

    def _analysis(self, campaign: BountyCampaign) -> CampaignAnalysis:
        from app.discovery.bounty.analysis import analyze_campaign

        cached = campaign.cache.get("analysis")
        if cached is not None:
            return cast("CampaignAnalysis", cached)
        analysis = analyze_campaign(
            manifest=campaign.manifest,
            identity=campaign.identity,
            repo_root=campaign.spec.repo_root,
            files=campaign.request.files,
            selection=campaign.selection,
            contract=campaign.spec.contract,
            address=campaign.spec.address,
            chain_id=campaign.spec.chain_id,
        )
        campaign.cache["analysis"] = analysis
        return analysis

    def findings(self, campaign_id: str) -> dict[str, Any]:
        from app.discovery.bounty.findings import build_findings

        campaign = self.get(campaign_id)
        analysis = self._analysis(campaign)
        findings = build_findings(
            analysis.candidates,
            manifest=campaign.manifest,
            identity=campaign.identity,
            state=campaign.state,
            sequences=analysis.sequences,
            deployment_for=analysis.deployment_for,
            ambiguous_contracts=analysis.ambiguous_contracts,
            target_address=campaign.spec.address,
            target_chain_id=campaign.spec.chain_id,
        )
        return {
            "campaign_id": campaign_id,
            "verified": False,
            "deployment": analysis.deployment.as_dict(),
            "findings": [_finding_dict(item) for item in findings],
        }

    def evidence(self, campaign_id: str) -> dict[str, Any]:
        campaign = self.get(campaign_id)
        state = campaign.state
        return {
            "campaign_id": campaign_id,
            "verified": False,
            "evidence": [_evidence_dict(item) for item in state.evidence],
            "contradictions": [
                {
                    "id": item.contradiction_id,
                    "kind": item.kind,
                    "identity": item.identity_key,
                    "status": item.status,
                }
                for item in state.contradictions
            ],
        }

    def repro(self, campaign_id: str) -> dict[str, Any]:
        from app.discovery.bounty.vfcs import instance_identities

        campaign = self.get(campaign_id)
        analysis = self._analysis(campaign)
        return {
            "campaign_id": campaign_id,
            "note": "call-sequence plans from static candidates; plans are not executions",
            "verified": False,
            "deployment": analysis.deployment.key,
            "sequences": [
                {
                    "sequence_id": seq.sequence_id,
                    "template": seq.template,
                    "derived_from": seq.derived_from,
                    "deployment": seq.identity.deployment,
                    "calls": [call.identity for call in seq.calls],
                    "instances": list(instance_identities(seq)),
                }
                for seq in analysis.sequences
            ],
        }

    def vfcs_feedback(self, campaign_id: str, signals: list[dict[str, Any]]) -> dict[str, Any]:
        from app.discovery.bounty.vfcs import FeedbackSignal, incorporate_feedback

        campaign = self.get(campaign_id)
        analysis = self._analysis(campaign)
        available = frozenset(
            engine.engine_id
            for engine in campaign.orchestrator.scheduler.engines
            if engine.availability().value == "available"
        )
        # fuzzers are discovery engines named foundry/echidna/medusa/ityfuzz
        fuzzers = frozenset(
            name
            for name in ("foundry", "echidna", "medusa", "ityfuzz")
            if any(e.engine_id == name and e.availability().value == "available"
                   for e in campaign.orchestrator.scheduler.engines)
        )
        parsed = [
            FeedbackSignal(
                kind=str(item.get("kind", "")),
                sequence_id=str(item.get("sequence_id", "")),
                call_index=int(item.get("call_index", -1)),
                values=tuple((str(k), str(v)) for k, v in dict(item.get("values", {})).items()),
                engine=str(item.get("engine", "")),
                call_instance=str(item.get("call_instance", "")),
            )
            for item in signals
        ]
        outcome = incorporate_feedback(
            analysis.sequences, parsed, available_engines=fuzzers or available
        )
        return {"campaign_id": campaign_id, **outcome.as_dict()}

    def advisories(self, campaign_id: str) -> dict[str, Any]:
        from app.discovery.bounty.advisories import (
            advisory_dict,
            match_advisories,
            precondition_graphs,
        )

        campaign = self.get(campaign_id)
        analysis = self._analysis(campaign)
        report = advisory_dict(match_advisories(campaign.manifest.compiler, analysis.sources))
        report["precondition_graphs"] = [
            graph.as_dict()
            for graph in precondition_graphs(campaign.manifest.compiler, analysis.sources)
        ]
        return report

    def scope_identity(self, campaign_id: str) -> dict[str, Any]:
        from app.discovery.bounty.deployment_identity import resolve_scope_identity

        campaign = self.get(campaign_id)
        analysis = self._analysis(campaign)
        decision = resolve_scope_identity(
            campaign.manifest,
            contract=campaign.spec.contract,
            file=campaign.spec.source_file,
            address=campaign.spec.address,
            chain_id=campaign.spec.chain_id,
            model=analysis.model,
        )
        result = {"campaign_id": campaign_id, **decision.as_dict()}
        result["deployment_identity"] = analysis.deployment.as_dict()
        result["followup"] = analysis.followup
        return result

    def tool_availability(self, campaign: BountyCampaign) -> dict[str, str]:
        from app.discovery.bounty.stateful import execution_enabled, tool_status

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
        tools = {
            "bugforge-research": "available",
            "bugforge-static": "available",
            "bugforge-compiler-diff": solc,
            "solc": solc,
        }
        fuzz = tool_status()
        tools["forge"] = fuzz.forge
        tools["stateful_execution"] = (
            "available" if (execution_enabled() and fuzz.available) else "unavailable"
        )
        for name in ("echidna", "medusa", "ityfuzz"):
            engine = next(
                (e for e in campaign.orchestrator.scheduler.engines if e.engine_id == name), None
            )
            tools[name] = (
                engine.availability().value if engine is not None else "unavailable"
            )
        return tools

    def report_pack(self, campaign_id: str) -> ReportPack:
        from app.discovery.bounty.advisories import match_advisories
        from app.discovery.bounty.findings import build_findings
        from app.discovery.bounty.priority import prioritize
        from app.discovery.bounty.report_pack import build_report_pack

        campaign = self.get(campaign_id)
        analysis = self._analysis(campaign)
        findings = build_findings(
            analysis.candidates,
            manifest=campaign.manifest,
            identity=campaign.identity,
            state=campaign.state,
            sequences=analysis.sequences,
            deployment_for=analysis.deployment_for,
            ambiguous_contracts=analysis.ambiguous_contracts,
            target_address=campaign.spec.address,
            target_chain_id=campaign.spec.chain_id,
        )
        advisories = match_advisories(campaign.manifest.compiler, analysis.sources)
        differential = self._differential(campaign, analysis.sources)
        model = analysis.model
        priority = (
            prioritize(model, manifest=campaign.manifest, candidates=analysis.candidates)
            if model is not None
            else None
        )
        return build_report_pack(
            manifest=campaign.manifest,
            identity=campaign.identity,
            findings=findings,
            sequences=analysis.sequences,
            state=campaign.state,
            advisories=advisories,
            differential=differential,
            priority=priority,
            tools=self.tool_availability(campaign),
        )

    def _differential(self, campaign: BountyCampaign, sources: dict[str, str]) -> DifferentialResult:
        """Real compiler differential when solc is installed and host compilation is on,
        else the stored prior result, else UNAVAILABLE. Never a hard-coded backend."""
        from app.discovery.bounty.compiler_diff import HostSolcBackend, run_differential

        backend = HostSolcBackend()
        if backend.available():
            result = run_differential(
                sources, backend=backend, expected=campaign.manifest.compiler
            )
            campaign.record.artifacts["compiler_differential"] = {
                "status": result.status,
                "reason": result.reason,
                "backend": result.backend,
                "compiler_version": result.compiler_version,
                "differences": len(result.differences),
            }
            try:
                self._save_record(campaign)
            except (CampaignConflictError, CampaignPersistenceError):
                pass
            return result
        return run_differential(sources, backend=backend)

    def stateful_execute(self, campaign_id: str, *, rounds: int = 3) -> dict[str, Any]:
        """Phase 52: the executable closed loop over the campaign's VFCS plans.

        Needs an in-scope or operator-acknowledged target and the installed forge.
        Honest: a missing tool or a non-executable plan is reported, never faked.
        """
        from app.discovery.bounty.stateful import (
            StatefulExecutor,
            execution_enabled,
            run_feedback_loop,
            tool_status,
        )

        campaign = self.get(campaign_id)
        analysis = self._analysis(campaign)
        tools = tool_status()
        if not execution_enabled():
            return {
                "campaign_id": campaign_id,
                "available": False,
                "reason": "local stateful execution is disabled",
                "tools": tools.as_dict(),
                "verified": False,
            }
        if not tools.available:
            return {
                "campaign_id": campaign_id,
                "available": False,
                "reason": "forge is not installed; stateful execution is unavailable",
                "tools": tools.as_dict(),
                "verified": False,
            }
        source_file = campaign.spec.source_file or (
            next(iter(analysis.sources), "") if analysis.sources else ""
        )
        import tempfile
        from pathlib import Path as _Path

        bundle_root = _Path(tempfile.mkdtemp(prefix="bugforge-bundle-"))
        executor = StatefulExecutor(bundle_dir=bundle_root)
        result = run_feedback_loop(
            executor,
            analysis.sequences,
            dict(analysis.models),
            analysis.sources,
            source_file=source_file,
            deployment=analysis.deployment.key,
            rounds=rounds,
        )
        campaign.record.artifacts["stateful"] = {
            "observations": len(result.observations),
            "violations": len(result.violations),
            "mutated": len(result.mutated),
            "bundle_dir": str(bundle_root),
        }
        try:
            self._save_record(campaign)
        except (CampaignConflictError, CampaignPersistenceError):
            pass
        return {
            "campaign_id": campaign_id,
            "available": True,
            "deployment": analysis.deployment.as_dict(),
            "bundle_dir": str(bundle_root),
            **result.as_dict(),
        }


def _evidence_dict(item: Any) -> dict[str, Any]:
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


def _finding_dict(item: Any) -> dict[str, Any]:
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
        "duplicate_basis": item.duplicate_basis,
        "root_cause_key": item.root_cause_key,
        "qualification": item.qualification.status,
        "deployment": dict(item.deployment),
        "verified": item.verified,
        "submitted": item.submitted,
    }


_SERVICE: BountyCampaignService | None = None
_SERVICE_LOCK = threading.Lock()


def get_bounty_service() -> BountyCampaignService:
    """Return the process-wide campaign service (lazily created from settings)."""
    global _SERVICE
    with _SERVICE_LOCK:
        if _SERVICE is None:
            _SERVICE = BountyCampaignService()
        return _SERVICE


__all__ = [
    "APPROVABLE_CAPABILITIES",
    "BountyCampaign",
    "BountyCampaignService",
    "CampaignConflictError",
    "CampaignControlError",
    "CampaignError",
    "CampaignPersistenceError",
    "CampaignSpec",
    "ENGINE_VERSION",
    "OrchestratorState",
    "PersistenceError",
    "UnknownCampaignError",
    "get_bounty_service",
]
