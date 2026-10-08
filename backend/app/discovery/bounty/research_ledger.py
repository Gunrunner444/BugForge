"""RESEARCH_COVERAGE and RESEARCH_GAPS: a deterministic research ledger (Phase 52, Slice C).

The ledger answers two questions from typed campaign state only (models, static
candidates, VFCS sequences, property specs, persisted executions and the engine
registry snapshot):

* **coverage** -- what was analyzed, what has an executable property, what ran,
  what each run concluded, and which engines judged it;
* **gaps** -- what is still missing, *why*, which evidence is missing, what closing
  the gap would cost, which engine/property would close it next, and a priority.

Every gap carries three estimates with their basis: ``reachability`` (an external
caller ranks above a privileged role, which ranks above internal-only code),
``impact`` (from the property family and the program's impact categories) and
``economic_feasibility`` (no capital / capital required / market dependent). The
cost-aware planner turns gaps into recommended actions against the Phase 49 budget
ledger and the local run budget. Nothing here runs an engine, grants an approval,
widens scope, raises a budget, or verifies anything.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from app.discovery.bounty.campaign import BountyManifest, ScopeStatus
from app.discovery.bounty.properties import PropertyDeclaration, PropertySpec, family_for
from app.discovery.bounty.vfcs import Vfcs
from app.discovery.orchestration.codec import digest
from app.parsing.solidity_research import ResearchModel, RFunction, SemanticCandidate

LEDGER_SCHEMA = "bugforge.research_ledger/1"
MAX_GAPS = 200
MAX_COVERAGE_FUNCTIONS = 400
MAX_ACTIONS = 25

_SENDER_GUARD = re.compile(r"\bmsg\.sender\s*(?:==|!=)|(?:==|!=)\s*msg\.sender\b")
_ROLE_GUARD = re.compile(r"\b(only\w+|hasRole|_checkRole|_checkOwner|requiresAuth|auth)\b")


class Reachability(StrEnum):
    EXTERNAL_CALLER = "external_caller"
    PRIVILEGED = "privileged"
    INTERNAL_ONLY = "internal_only"
    UNKNOWN = "unknown"


class Impact(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Economic(StrEnum):
    NO_CAPITAL = "no_capital"
    CAPITAL_REQUIRED = "capital_required"
    MARKET_DEPENDENT = "market_dependent"
    UNKNOWN = "unknown"


_REACH_WEIGHT = {
    Reachability.EXTERNAL_CALLER: 4,
    Reachability.UNKNOWN: 2,
    Reachability.PRIVILEGED: 1,
    Reachability.INTERNAL_ONLY: 1,
}
_IMPACT_WEIGHT = {Impact.HIGH: 3, Impact.MEDIUM: 2, Impact.LOW: 1}
_ECON_WEIGHT = {
    Economic.NO_CAPITAL: 3,
    Economic.UNKNOWN: 2,
    Economic.CAPITAL_REQUIRED: 2,
    Economic.MARKET_DEPENDENT: 1,
}
_HIGH_FAMILIES = frozenset(
    {
        "authorization",
        "initialization",
        "token_movement",
        "solvency",
        "upgrade_safety",
        "access_control_hierarchy",
        "erc4337",
        "eip7702",
        "bridge_message_binding",
        "nonce_replay",
    }
)
_MEDIUM_FAMILIES = frozenset({"accounting", "oracle_safety", "governance"})


@dataclass(frozen=True)
class Estimate:
    reachability: Reachability
    reachability_basis: str
    impact: Impact
    impact_basis: str
    economic: Economic
    economic_basis: str

    @property
    def score(self) -> int:
        return (
            _REACH_WEIGHT[self.reachability]
            * _IMPACT_WEIGHT[self.impact]
            * _ECON_WEIGHT[self.economic]
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "reachability": self.reachability.value,
            "reachability_basis": self.reachability_basis,
            "impact": self.impact.value,
            "impact_basis": self.impact_basis,
            "economic_feasibility": self.economic.value,
            "economic_basis": self.economic_basis,
            "score": self.score,
        }


def reachability_of(
    model: ResearchModel | None, function: RFunction | None
) -> tuple[Reachability, str]:
    if model is None or function is None:
        return Reachability.UNKNOWN, "the function is not in the model"
    if not function.exposed:
        return Reachability.INTERNAL_ONLY, f"{function.visibility or 'internal'} {function.kind}"
    for name in function.modifiers:
        modifier = model.modifier(function.contract, name)
        if modifier is None:
            if _ROLE_GUARD.fullmatch(name) or name.startswith("only"):
                return Reachability.PRIVILEGED, f"modifier {name} (unresolved) names a role"
            continue
        if _SENDER_GUARD.search(modifier.body) or _ROLE_GUARD.search(modifier.body):
            return Reachability.PRIVILEGED, f"modifier {name} restricts msg.sender"
    head = function.body[:400]
    if re.search(r"require\s*\([^;]*msg\.sender\s*==", head) or re.search(
        r"if\s*\([^;]*msg\.sender\s*!=", head
    ):
        return Reachability.PRIVILEGED, "the body checks msg.sender before acting"
    return Reachability.EXTERNAL_CALLER, f"{function.visibility} with no caller restriction"


def impact_of(
    family: str, candidate: SemanticCandidate | None, manifest: BountyManifest | None
) -> tuple[Impact, str]:
    tags = set(candidate.impact_tags) if candidate is not None else set()
    if manifest is not None:
        matched = sorted(
            (c for c in manifest.impact_categories if tags & set(c.tags)),
            key=lambda c: (-c.weight, c.name),
        )
        if matched:
            top = matched[0]
            severity = top.severity.lower()
            level = (
                Impact.HIGH
                if severity in {"critical", "high"}
                else Impact.MEDIUM
                if severity == "medium"
                else Impact.LOW
            )
            return level, f"program impact category {top.name} ({top.severity})"
    if family in _HIGH_FAMILIES:
        return Impact.HIGH, f"property family {family}"
    if family in _MEDIUM_FAMILIES:
        return Impact.MEDIUM, f"property family {family}"
    return Impact.LOW, f"property family {family or 'unknown'}"


def economic_of(family: str, sequence: Vfcs | None) -> tuple[Economic, str]:
    template = sequence.template if sequence is not None else ""
    if family == "oracle_safety" or "oracle update" in template:
        return Economic.MARKET_DEPENDENT, "needs a price move in a market or feed"
    if "donate" in template or family == "solvency":
        return Economic.CAPITAL_REQUIRED, "needs the attacker to commit tokens (donation/deposit)"
    if family in {"authorization", "initialization", "access_control_hierarchy", "erc4337"}:
        return Economic.NO_CAPITAL, "a call sequence alone; no capital"
    if family in {"token_movement", "accounting"}:
        return Economic.CAPITAL_REQUIRED, "moves the attacker's own tokens"
    return Economic.UNKNOWN, "no economic model for this family"


# ---- gaps -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Cost:
    local_runs: int = 0
    engine_runs: int = 0
    human: bool = False
    capability: str = ""  # Phase 49 capability the action maps to, when any

    @property
    def units(self) -> int:
        return self.local_runs + 2 * self.engine_runs + (10 if self.human else 0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "local_runs": self.local_runs,
            "engine_runs": self.engine_runs,
            "human": self.human,
            "capability": self.capability,
            "units": self.units,
        }


@dataclass(frozen=True)
class Gap:
    gap_id: str
    kind: str
    subject: str  # Contract.signature or sequence id
    sequence_id: str
    detector: str
    family: str
    importance: Impact
    reason: str
    missing_evidence: str
    cost: Cost
    next_engine: str
    next_property: str
    estimate: Estimate
    blocked_by: str = ""  # policy reason when the next step is not allowed here

    @property
    def priority(self) -> int:
        if self.blocked_by:
            return 0
        return (1000 * self.estimate.score) // (1 + self.cost.units)

    def as_dict(self) -> dict[str, Any]:
        return {
            "gap_id": self.gap_id,
            "kind": self.kind,
            "subject": self.subject,
            "sequence_id": self.sequence_id,
            "detector": self.detector,
            "family": self.family,
            "importance": self.importance.value,
            "reason": self.reason,
            "missing_evidence": self.missing_evidence,
            "cost": self.cost.as_dict(),
            "next_engine": self.next_engine,
            "next_property": self.next_property,
            "estimate": self.estimate.as_dict(),
            "blocked_by": self.blocked_by,
            "priority": self.priority,
        }


# reason_code -> (missing evidence, next engine/step, cost, blocked_by)
_INCONCLUSIVE_NEXT: dict[str, tuple[str, str, Cost, str]] = {
    "unknown_constructor_argument": (
        "constructor arguments of the deployed instance",
        "fixture:constructor_arguments (from the manifest or deployment identity)",
        Cost(local_runs=1, human=True),
        "",
    ),
    "ambiguous_dependency": (
        "which implementation the target is wired to",
        "fixture:dependency_binding",
        Cost(local_runs=1, human=True),
        "",
    ),
    "cyclic_dependency": (
        "a construction order for mutually dependent contracts",
        "fixture:deployment_script",
        Cost(local_runs=1, human=True),
        "",
    ),
    "dependency_bound_exceeded": (
        "a deployment of more contracts than the bounded harness allows",
        "fixture:deployment_script",
        Cost(local_runs=1, human=True),
        "",
    ),
    "unbound_token": (
        "a token the harness can bind to the target",
        "fixture:token_binding",
        Cost(local_runs=1, human=True),
        "",
    ),
    "unsupported_primitive": (
        "a local fixture for the environment step (market, oracle, signer)",
        "fixture:environment_primitive",
        Cost(local_runs=1, human=True),
        "",
    ),
    "proxy_requires_compatible_harness": (
        "a proxy-compatible harness (proxy + implementation + initializer)",
        "fixture:proxy_harness",
        Cost(local_runs=1, human=True),
        "",
    ),
    "budget_exhausted": (
        "an execution within budget",
        "foundry:stateful_execute",
        Cost(local_runs=1, capability="stateful_execution"),
        "",
    ),
    "compile_failed": (
        "a harness that compiles against the exact sources",
        "fixture:compile_environment (remappings/dependencies)",
        Cost(local_runs=1, human=True),
        "",
    ),
    "compiler_unavailable": (
        "a solc version inside the source pragma",
        "install:solc (pinned version)",
        Cost(local_runs=1, human=True),
        "",
    ),
    "tool_missing": (
        "an installed forge/solc",
        "install:foundry",
        Cost(local_runs=1, human=True),
        "",
    ),
    "param_not_expressible": (
        "an ABI encoding for a parameter (struct, nested array, fixed array)",
        "fixture:parameter_encoding",
        Cost(local_runs=1, human=True),
        "",
    ),
    "nested_unresolved": (
        "the callee a nested dispatch should reach",
        "vfcs:nested_target",
        Cost(local_runs=1, human=True),
        "",
    ),
    "call_outside_target": (
        "a harness that calls a second contract the relationship model justifies",
        "fixture:multi_contract_sequence",
        Cost(local_runs=1, human=True),
        "",
    ),
    "unknown_actor": (
        "a harness actor for the role the sequence names",
        "fixture:actor",
        Cost(local_runs=1, human=True),
        "",
    ),
    "not_deployable": (
        "a concrete, deployable target (abstract/interface/library)",
        "fixture:concrete_target",
        Cost(local_runs=1, human=True),
        "",
    ),
    "blocked_by_policy:cheatcode_in_source": (
        "an execution environment that may run code referencing cheatcodes",
        "review:untrusted_cheatcode_use",
        Cost(human=True),
        "blocked_by_policy: untrusted sources reference cheatcodes",
    ),
    "identity_mismatch": (
        "an execution bound to the analyzed snapshot",
        "re-analyze then foundry:stateful_execute",
        Cost(local_runs=1, capability="stateful_execution"),
        "",
    ),
}


def _gap_id(kind: str, subject: str, sequence_id: str) -> str:
    return "gap_" + digest({"kind": kind, "subject": subject, "sequence": sequence_id})[:16]


@dataclass
class _Builder:
    manifest: BountyManifest | None
    models: Sequence[ResearchModel]
    gaps: dict[str, Gap] = field(default_factory=dict)

    def function(
        self, contract: str, signature: str
    ) -> tuple[ResearchModel | None, RFunction | None]:
        for model in self.models:
            for item in model.functions_of(contract):
                if item.signature == signature:
                    return model, item
        return None, None

    def estimate(
        self,
        contract: str,
        signature: str,
        family: str,
        candidate: SemanticCandidate | None,
        sequence: Vfcs | None,
    ) -> Estimate:
        model, function = self.function(contract, signature)
        reach, reach_basis = reachability_of(model, function)
        impact, impact_basis = impact_of(family, candidate, self.manifest)
        econ, econ_basis = economic_of(family, sequence)
        return Estimate(reach, reach_basis, impact, impact_basis, econ, econ_basis)

    def add(self, gap: Gap) -> None:
        if gap.gap_id not in self.gaps and len(self.gaps) < MAX_GAPS:
            self.gaps[gap.gap_id] = gap


def _split(derived_from: str) -> tuple[str, str, str]:
    detector, _, site = derived_from.partition("@")
    contract, _, signature = site.partition(".")
    return detector, contract, signature


def _in_scope(manifest: BountyManifest | None, contract: str) -> bool:
    if manifest is None:
        return True
    return manifest.scope_of(contract=contract).status is not ScopeStatus.OUT_OF_SCOPE


def build_ledger(
    *,
    models: Sequence[ResearchModel],
    candidates: Iterable[SemanticCandidate],
    sequences: Iterable[Vfcs],
    specs: Mapping[str, PropertySpec],
    skipped: Mapping[str, str],
    executions: Mapping[str, Mapping[str, Any]],
    engines: Sequence[Mapping[str, Any]],
    manifest: BountyManifest | None = None,
) -> dict[str, Any]:
    """Deterministic coverage + gaps. Same inputs, same ledger (ids, order, priorities)."""
    builder = _Builder(manifest, models)
    candidates = tuple(candidates)
    sequences = tuple(sequences)
    by_key = {f"{c.detector}@{c.contract}.{c.function}": c for c in candidates}
    engine_status = {str(e.get("name")): str(e.get("status")) for e in engines}
    usable_engines = sorted(
        str(e.get("name"))
        for e in engines
        if e.get("role") == "property_engine" and e.get("status") == "usable"
    )

    # -- candidates without a sequence ------------------------------------------------------
    for key, reason in sorted(skipped.items()):
        detector, contract, signature = _split(key)
        if not _in_scope(manifest, contract):
            continue
        family = family_for(detector).value
        candidate = by_key.get(key)
        builder.add(
            Gap(
                _gap_id("no_sequence", key, ""),
                "no_sequence",
                f"{contract}.{signature}",
                "",
                detector,
                family,
                impact_of(family, candidate, manifest)[0],
                reason,
                "an executable call sequence for this candidate",
                Cost(human=True, capability="vfcs_generation"),
                "vfcs:new_template",
                "",
                builder.estimate(contract, signature, family, candidate, None),
            )
        )

    # -- sequences: property declaration and execution state --------------------------------
    by_outcome: dict[str, int] = {}
    by_declaration: dict[str, int] = {}
    by_family: dict[str, dict[str, int]] = {}
    executed_sequences = 0
    judged_by: dict[str, int] = {}
    for sequence in sorted(sequences, key=lambda s: s.sequence_id):
        detector, contract, signature = _split(sequence.derived_from)
        if not _in_scope(manifest, contract):
            continue
        spec = specs.get(sequence.sequence_id)
        family = spec.family.value if spec else family_for(detector).value
        candidate = by_key.get(sequence.derived_from)
        estimate = builder.estimate(contract, signature, family, candidate, sequence)
        importance = estimate.impact
        declaration = spec.declaration.value if spec else "unknown"
        by_declaration[declaration] = by_declaration.get(declaration, 0) + 1
        fam = by_family.setdefault(family, {"sequences": 0, "executable": 0, "violated": 0})
        fam["sequences"] += 1
        record = executions.get(sequence.sequence_id)
        subject = f"{contract}.{signature}"
        sid = sequence.sequence_id

        def gap(
            kind: str,
            reason: str,
            missing: str,
            cost: Cost,
            next_engine: str,
            next_property: str = "",
            blocked_by: str = "",
            *,
            _sid: str = sid,
            _subject: str = subject,
            _detector: str = detector,
            _family: str = family,
            _importance: Impact = importance,
            _estimate: Estimate = estimate,
        ) -> None:
            builder.add(
                Gap(
                    _gap_id(kind, _subject, _sid),
                    kind,
                    _subject,
                    _sid,
                    _detector,
                    _family,
                    _importance,
                    reason,
                    missing,
                    cost,
                    next_engine,
                    next_property,
                    _estimate,
                    blocked_by,
                )
            )

        if spec is not None and spec.declaration is PropertyDeclaration.PROPERTY_UNSUPPORTED:
            gap(
                "property_unsupported",
                spec.unsupported_reason or "the oracle cannot be expressed locally",
                "an executable oracle for this property",
                Cost(human=True),
                "fixture:oracle_support",
                spec.statement,
            )
        elif spec is not None and spec.declaration is PropertyDeclaration.NO_PROPERTY_AVAILABLE:
            gap(
                "no_property",
                spec.unsupported_reason or "nothing meaningful can be judged from execution",
                "a property that execution can judge",
                Cost(human=True),
                "property:define",
                sequence.property_under_test,
            )
        if spec is not None and spec.executable:
            fam["executable"] += 1
        if record is None:
            if spec is not None and spec.executable:
                gap(
                    "not_executed",
                    "an executable property exists but no persisted execution",
                    "a local execution of the sequence",
                    Cost(local_runs=1 + len(usable_engines), capability="stateful_execution"),
                    "foundry:stateful_execute",
                    spec.statement,
                )
            continue
        executed_sequences += 1
        outcome = str(record.get("outcome", ""))
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        code = str(record.get("reason_code", ""))
        for path in record.get("check_paths", []) or []:
            if path.get("verdict") in {"property_violated", "property_held"}:
                engine = str(path.get("engine", ""))
                judged_by[engine] = judged_by.get(engine, 0) + 1
        if record.get("stale"):
            gap(
                "stale_execution",
                "the persisted execution was for a different source set",
                "an execution against the current snapshot",
                Cost(local_runs=1, capability="stateful_execution"),
                "foundry:stateful_execute",
            )
            continue
        if outcome == "property_violated":
            fam["violated"] += 1
            corroboration = str(record.get("corroboration", ""))
            if corroboration == "disagreement":
                gap(
                    "contradiction",
                    "independent paths disagree about this property",
                    "a resolution of the disagreement (which path is wrong)",
                    Cost(human=True),
                    "review:contradiction",
                    spec.statement if spec else "",
                )
            elif corroboration != "corroborated_candidate":
                missing_engines = [
                    name for name in ("echidna", "medusa") if engine_status.get(name) != "usable"
                ]
                gap(
                    "needs_corroboration",
                    "only one materially independent path judged this violation",
                    "a materially independent check (alternate oracle or second engine)",
                    Cost(engine_runs=1, capability="property_testing"),
                    f"property_engine:{missing_engines[0]}"
                    if missing_engines
                    else "property:alternate_oracle",
                    spec.statement if spec else "",
                )
            # a local source replay never establishes deployed behavior
            gap(
                "deployment_replay",
                "local source replay does not establish the deployed instance's behavior",
                "replay against the deployed runtime and state (pinned fork)",
                Cost(local_runs=1, human=True, capability="fork_validation"),
                "pinned_fork_replay",
                spec.statement if spec else "",
                blocked_by=(
                    "blocked_by_policy: fork replay needs an approved pinned fork; "
                    "research tooling uses no RPC"
                    if engine_status.get("fork_replay", "blocked_by_policy") != "usable"
                    else ""
                ),
            )
        elif outcome == "sequence_executed_no_oracle":
            gap(
                "no_oracle",
                "the sequence ran but nothing judged a property",
                "an executable oracle",
                Cost(human=True),
                "property:define",
                sequence.property_under_test,
            )
        elif outcome in {"inconclusive", "compile_failed", "unavailable", "identity_mismatch"}:
            missing, next_engine, cost, blocked = _INCONCLUSIVE_NEXT.get(
                code,
                (
                    "a conclusive local execution",
                    "review:inconclusive",
                    Cost(local_runs=1, human=True),
                    "",
                ),
            )
            gap(
                f"{outcome}:{code or outcome}",
                str(record.get("reason", ""))[:200],
                missing,
                cost,
                next_engine,
                spec.statement if spec else "",
                blocked,
            )
        elif outcome in {"execution_failed", "timeout"}:
            gap(
                outcome,
                str(record.get("reason", ""))[:200],
                "a completed local execution",
                Cost(local_runs=1, capability="stateful_execution"),
                "foundry:stateful_execute",
            )
        elif outcome == "sequence_reverted":
            gap(
                "sequence_reverted",
                "a precondition reverted, so the property was not judged",
                "a sequence whose preconditions succeed",
                Cost(local_runs=2, capability="stateful_execution"),
                "vfcs:mutate (near_miss feedback)",
                spec.statement if spec else "",
            )

    # -- functions: coverage of the exposed, state-changing surface --------------------------
    covered_sites = {s.derived_from.split("@", 1)[-1] for s in sequences}
    candidate_sites = {f"{c.contract}.{c.function}" for c in candidates}
    functions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for model in models:
        for function in model.all_functions():
            if function.identity in seen or len(functions) >= MAX_COVERAGE_FUNCTIONS:
                continue
            owner = model.contracts.get(function.contract)
            if owner is None or owner.kind != "contract":
                continue
            if not function.exposed or function.mutability in {"view", "pure"}:
                continue
            if not _in_scope(manifest, function.contract):
                continue
            seen.add(function.identity)
            reach, basis = reachability_of(model, function)
            functions.append(
                {
                    "function": function.identity,
                    "file": function.file,
                    "line": function.line,
                    "reachability": reach.value,
                    "reachability_basis": basis,
                    "static_candidates": function.identity in candidate_sites,
                    "sequence": function.identity in covered_sites,
                }
            )
    functions.sort(key=lambda item: item["function"])
    unexamined = [
        f
        for f in functions
        if not f["static_candidates"] and f["reachability"] == "external_caller"
    ]

    gaps = sorted(builder.gaps.values(), key=lambda g: (-g.priority, g.gap_id))
    coverage = {
        "functions_state_changing": len(functions),
        "functions_with_candidates": sum(1 for f in functions if f["static_candidates"]),
        "functions_with_sequences": sum(1 for f in functions if f["sequence"]),
        "external_unrestricted_without_candidates": len(unexamined),
        "candidates": len(candidates),
        "sequences": len(sequences),
        "sequences_without_template": len(skipped),
        "executed_sequences": executed_sequences,
        "by_declaration": dict(sorted(by_declaration.items())),
        "by_outcome": dict(sorted(by_outcome.items())),
        "by_family": {k: by_family[k] for k in sorted(by_family)},
        "judged_by_engine": dict(sorted(judged_by.items())),
        "engines": {k: engine_status[k] for k in sorted(engine_status)},
        "functions": functions,
    }
    return {
        "schema": LEDGER_SCHEMA,
        "RESEARCH_COVERAGE": coverage,
        "RESEARCH_GAPS": [g.as_dict() for g in gaps],
        "gap_count": len(gaps),
        "truncated": len(builder.gaps) >= MAX_GAPS,
        "ledger_digest": digest(
            {"coverage": {k: v for k, v in coverage.items()}, "gaps": [g.gap_id for g in gaps]}
        ),
        "note": "deterministic estimates from typed state; nothing here is verified",
        "verified": False,
    }


# ---- cost-aware planner -----------------------------------------------------------------------


def plan_actions(
    ledger: Mapping[str, Any],
    *,
    budget_remaining: Mapping[str, int],
    local_runs_remaining: int,
    limit: int = MAX_ACTIONS,
) -> dict[str, Any]:
    """Recommended next research actions, highest priority per unit cost first.

    Extends the Phase 49 planner's cost model: an action that maps to a Phase 49
    capability must fit ``estimate_cost`` against the campaign's remaining budget;
    local stateful runs must fit the server-owned run budget. Blocked actions are
    listed with their policy reason and never planned. A recommendation only.
    """
    from app.discovery.orchestration.budget import estimate_cost

    planned: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    local_left = max(0, local_runs_remaining)
    remaining = dict(budget_remaining)
    for gap in ledger.get("RESEARCH_GAPS", []):
        cost = dict(gap.get("cost", {}))
        action = {
            "gap_id": gap["gap_id"],
            "kind": gap["kind"],
            "subject": gap["subject"],
            "next_engine": gap["next_engine"],
            "next_property": gap["next_property"],
            "priority": gap["priority"],
            "cost": cost,
        }
        if gap.get("blocked_by"):
            blocked.append({**action, "reason": gap["blocked_by"]})
            continue
        if cost.get("human"):
            deferred.append({**action, "reason": "needs a human-provided fixture or decision"})
            continue
        runs = int(cost.get("local_runs", 0)) + int(cost.get("engine_runs", 0))
        capability = str(cost.get("capability", ""))
        phase49 = (
            estimate_cost(capability)
            if capability and capability not in {"stateful_execution"}
            else {}
        )
        short = sorted(name for name, need in phase49.items() if remaining.get(name, 0) < need)
        if short:
            deferred.append({**action, "reason": f"budget: {', '.join(short)} exhausted"})
            continue
        if runs > local_left:
            deferred.append({**action, "reason": "local run budget exhausted"})
            continue
        if len(planned) >= limit:
            deferred.append({**action, "reason": "action limit reached"})
            continue
        local_left -= runs
        for name, need in phase49.items():
            remaining[name] = remaining.get(name, 0) - need
        planned.append({**action, "phase49_cost": phase49})
    return {
        "planned": planned,
        "deferred": deferred[:MAX_GAPS],
        "blocked": blocked[:MAX_GAPS],
        "local_runs_remaining_after": local_left,
        "note": "a recommendation only; it runs nothing, grants no approval and raises no budget",
        "verified": False,
    }
