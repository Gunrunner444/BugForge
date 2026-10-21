"""One entry point for the Phase 50 semantic analyzers.

Every analyzer reads the same bounded ``ResearchModel`` and returns static
``SemanticCandidate`` values. A family that does not apply to the target returns
nothing, and the suite reports which families ran so an empty result is never
mistaken for a clean bill of health.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from app.parsing.solidity_account_abstraction import (
    account_abstraction_present,
    analyze_account_abstraction,
)
from app.parsing.solidity_accounting import analyze_balance_delta
from app.parsing.solidity_arithmetic import analyze_arithmetic
from app.parsing.solidity_caller_context import analyze_caller_context
from app.parsing.solidity_conservation import analyze_conservation
from app.parsing.solidity_high_value import analyze_high_value
from app.parsing.solidity_message_binding import analyze_message_binding
from app.parsing.solidity_modules import analyze_protocol_modules, modules_present
from app.parsing.solidity_oracle_quality import analyze_oracle_quality
from app.parsing.solidity_research import ResearchModel, SemanticCandidate, build_research_model

Analyzer = Callable[[ResearchModel], list[SemanticCandidate]]

FAMILIES: dict[str, Analyzer] = {
    "caller_context": analyze_caller_context,
    "oracle_quality": analyze_oracle_quality,
    "message_binding": analyze_message_binding,
    "account_abstraction": analyze_account_abstraction,
    "balance_delta": analyze_balance_delta,
    "arithmetic": analyze_arithmetic,
    "high_value": analyze_high_value,
    "protocol_modules": analyze_protocol_modules,
    "conservation": analyze_conservation,
}
MAX_TOTAL_CANDIDATES = 256
# One family cannot consume the whole budget, and a rare family keeps a reserve
# so a crowd of common detectors cannot starve it. Neither bound is a lexical cut.
MAX_PER_FAMILY = 64
FAMILY_RESERVE = 16
_CONFIDENCE = {"high": 4, "medium": 2, "low": 0}
_TAG_WEIGHT = {
    "vault_accounting": 24,
    "custody": 8,
    "value_transfer": 8,
    "reserve_accounting": 6,
    "signature_authorization": 4,
}
# Families that emit testable hypotheses on safe and unsafe code alike. Their
# candidates feed execution planning only: they are not defect suspicions, not
# static observations, and not findings until execution shows a violation.
HYPOTHESIS_FAMILIES = frozenset({"conservation"})


def discovery_score(candidate: SemanticCandidate) -> int:
    """A selection rank. It is not a finding and not an exploitability claim."""
    tags = sum(_TAG_WEIGHT.get(tag, 1) for tag in candidate.impact_tags)
    return tags + _CONFIDENCE.get(candidate.confidence, 0)


def _mix(name: str) -> int:
    return int(hashlib.sha256(name.encode()).hexdigest()[:8], 16)


def _identity(candidate: SemanticCandidate) -> tuple[str, str, str, str, int]:
    return (
        candidate.detector,
        candidate.file,
        candidate.contract,
        candidate.function,
        candidate.line,
    )


def _rotate(group: list[SemanticCandidate]) -> list[SemanticCandidate]:
    """Highest score first, and files share each round instead of one path filling it.

    Equal scores rotate by a path hash, so an alphabetically late file is not
    systematically last. The path remains the final tie break, so the order is
    deterministic.
    """
    by_file: dict[str, list[SemanticCandidate]] = {}
    for item in group:
        by_file.setdefault(item.file, []).append(item)
    for bucket in by_file.values():
        bucket.sort(key=lambda c: (-discovery_score(c), c.line, c.detector, c.contract, c.function))

    def file_key(name: str) -> tuple[int, int, str]:
        best = max(discovery_score(item) for item in by_file[name])
        return (-best, _mix(name), name)

    files = sorted(by_file, key=file_key)
    picked: list[SemanticCandidate] = []
    while any(by_file.values()):
        for name in files:
            bucket = by_file[name]
            if bucket:
                picked.append(bucket.pop(0))
    return picked


def select_candidates(
    found: list[SemanticCandidate],
) -> tuple[tuple[SemanticCandidate, ...], tuple[tuple[str, str, int], ...], int]:
    """Keep a bounded, family-balanced set and record every drop.

    Returns ``(kept, dropped, found_count)``. ``dropped`` entries are
    ``(reason, family, count)`` with reason ``family_budget`` or ``total_budget``.
    """
    unique: dict[tuple[str, str, str, str, int], SemanticCandidate] = {}
    for item in found:
        unique.setdefault(_identity(item), item)
    items = list(unique.values())
    by_family: dict[str, list[SemanticCandidate]] = {}
    for item in items:
        by_family.setdefault(item.family, []).append(item)
    dropped: list[tuple[str, str, int]] = []
    ranked: dict[str, list[SemanticCandidate]] = {}
    for family in sorted(by_family):
        ordered = _rotate(by_family[family])
        if len(ordered) > MAX_PER_FAMILY:
            dropped.append(("family_budget", family, len(ordered) - MAX_PER_FAMILY))
        ranked[family] = ordered[:MAX_PER_FAMILY]
    families = sorted(ranked)
    if not families:
        return (), tuple(dropped), len(items)
    reserve = min(FAMILY_RESERVE, max(1, MAX_TOTAL_CANDIDATES // len(families)))
    selected: list[SemanticCandidate] = []
    selected_ids: set[tuple[str, str, str, str, int]] = set()
    leftovers: list[SemanticCandidate] = []
    for family in families:
        if len(selected) >= MAX_TOTAL_CANDIDATES:
            leftovers.extend(ranked[family])
            continue
        room = min(reserve, MAX_TOTAL_CANDIDATES - len(selected))
        take, rest = ranked[family][:room], ranked[family][room:]
        for item in take:
            selected.append(item)
            selected_ids.add(_identity(item))
        leftovers.extend(rest)
    leftovers.sort(
        key=lambda c: (
            -discovery_score(c),
            _mix(c.file),
            c.file,
            c.line,
            c.family,
            c.detector,
            c.contract,
            c.function,
        )
    )
    for item in leftovers:
        if len(selected) >= MAX_TOTAL_CANDIDATES:
            break
        selected.append(item)
        selected_ids.add(_identity(item))
    lost: dict[str, int] = {}
    for family, group in ranked.items():
        count = sum(1 for item in group if _identity(item) not in selected_ids)
        if count:
            lost[family] = count
    dropped.extend(("total_budget", family, lost[family]) for family in sorted(lost))
    kept = tuple(
        sorted(
            selected,
            key=lambda c: (c.file, c.line, c.family, c.detector, c.contract, c.function),
        )
    )
    return kept, tuple(dropped), len(items)


def is_hypothesis(candidate: SemanticCandidate) -> bool:
    return candidate.family in HYPOTHESIS_FAMILIES


@dataclass(frozen=True)
class SuiteResult:
    model: ResearchModel
    candidates: tuple[SemanticCandidate, ...]
    families_run: tuple[str, ...]
    families_skipped: tuple[str, ...]
    truncated: bool
    candidates_found: int = 0
    # (reason, family, count). Reasons: family_budget, total_budget, parser_limit.
    dropped: tuple[tuple[str, str, int], ...] = ()
    notes: tuple[str, ...] = ()

    def by_family(self, family: str) -> tuple[SemanticCandidate, ...]:
        return tuple(item for item in self.candidates if item.family == family)

    def budget(self) -> dict[str, object]:
        return {
            "candidates_found": self.candidates_found,
            "candidates_kept": len(self.candidates),
            "truncated": self.truncated,
            "dropped": [
                {"reason": reason, "family": family, "count": count}
                for reason, family, count in self.dropped
            ],
            "notes": list(self.notes),
        }


def run_suite(model: ResearchModel, families: tuple[str, ...] | None = None) -> SuiteResult:
    selected = tuple(sorted(FAMILIES)) if families is None else tuple(sorted(set(families)))
    run: list[str] = []
    skipped: list[str] = []
    found: list[SemanticCandidate] = []
    for name in selected:
        analyzer = FAMILIES.get(name)
        if analyzer is None:
            skipped.append(name)
            continue
        if name == "account_abstraction" and not account_abstraction_present(model):
            skipped.append(name)
            continue
        if name == "protocol_modules" and not modules_present(model):
            skipped.append(name)  # evidence-triggered: no hook/bridge evidence
            continue
        run.append(name)
        found.extend(analyzer(model))
    kept, dropped, seen = select_candidates(found)
    notes = model.notes if model.truncated else ()
    return SuiteResult(
        model=model,
        candidates=kept,
        families_run=tuple(run),
        families_skipped=tuple(skipped),
        truncated=model.truncated or bool(dropped),
        candidates_found=seen,
        dropped=dropped,
        notes=notes,
    )


def analyze_sources(
    sources: Mapping[str, str], families: tuple[str, ...] | None = None
) -> SuiteResult:
    return run_suite(build_research_model(sources), families)
