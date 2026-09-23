"""Bounded discovery scheduler. It selects complementary engines; it does not verify."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.discovery.capabilities import EngineAvailability, EngineCapability, ResultStatus
from app.discovery.corpus import DiscoveryCorpus, SeedSource
from app.discovery.engine import AnalysisRequest, DiscoveryEngine
from app.discovery.results import DynamicResult


@dataclass(frozen=True)
class ScheduleDecision:
    engine_id: str
    action: str
    reason: str
    capability: str = ""


@dataclass
class SchedulerFeedback:
    stagnating: bool = False
    difficult: bool = False
    new_coverage: bool = False
    crashes: int = 0
    assertion_failures: int = 0
    rounds: int = 0
    transitions: list[str] = field(default_factory=list)


# Preferred order. Later engines run only when budget and preconditions allow.
_SOLIDITY_ORDER = (
    "bugforge-static",
    "slither",
    "foundry",
    "echidna",
    "medusa",
    "halmos",
    "wake",
)
_LANGUAGE_ORDER: dict[str, tuple[str, ...]] = {
    "solidity": _SOLIDITY_ORDER,
    "c": ("bugforge-static", "native-fuzz", "sanitizer"),
    "cpp": ("bugforge-static", "native-fuzz", "sanitizer"),
    "go": ("bugforge-static", "go-test"),
    "rust": ("bugforge-static", "cargo-test"),
    "java": ("bugforge-static", "jazzer", "property"),
    "python": ("bugforge-static", "property", "pytest"),
}


@dataclass
class DiscoveryScheduler:
    engines: tuple[DiscoveryEngine, ...]
    max_engines: int = 3
    max_rounds: int = 2
    corpus: DiscoveryCorpus = field(default_factory=DiscoveryCorpus)
    feedback: SchedulerFeedback = field(default_factory=SchedulerFeedback)
    _coverage_seen: dict[str, float] = field(default_factory=dict)

    def select(self, request: AnalysisRequest) -> list[ScheduleDecision]:
        order = _LANGUAGE_ORDER.get(request.language, ("bugforge-static",))
        by_id = {engine.engine_id: engine for engine in self.engines}
        decisions: list[ScheduleDecision] = []
        selected = 0
        for engine_id in order:
            engine = by_id.get(engine_id)
            if engine is None:
                decisions.append(
                    ScheduleDecision(engine_id, "skip", "engine is not registered", "")
                )
                continue
            decision = self._decide(engine, request)
            if decision.action == "run" and selected >= self.max_engines:
                decision = ScheduleDecision(
                    engine.engine_id, "skip", "campaign budget exhausted", decision.capability
                )
            decisions.append(decision)
            if decision.action == "run":
                selected += 1
        return decisions

    def run_selected(self, request: AnalysisRequest) -> list[DynamicResult]:
        results: list[DynamicResult] = []
        by_id = {engine.engine_id: engine for engine in self.engines}
        for decision in self.select(request):
            if decision.action != "run":
                continue
            engine = by_id[decision.engine_id]
            if EngineCapability.STATIC_ANALYSIS in engine.capabilities():
                result = engine.analyze_target(request)
            else:
                result = engine.start_campaign(request)
            results.append(result)
            self.note_result(result, request)
        return results

    def note_result(self, result: DynamicResult, request: AnalysisRequest) -> None:
        self.feedback.rounds += 1
        increased = self._coverage_increased(result)
        if increased is True:
            self.feedback.new_coverage = True
            self.feedback.stagnating = False
            if result.minimized_input:
                self.corpus.add(
                    result.minimized_input,
                    source=SeedSource.COVERAGE,
                    reason="coverage-increasing input",
                    language=request.language,
                    target=request.target,
                )
        elif increased is False and result.executed:
            self.feedback.stagnating = True
        if result.crash:
            self.feedback.crashes += 1
            if result.minimized_input:
                self.corpus.add(
                    result.minimized_input,
                    source=SeedSource.CRASH,
                    reason="crashing input",
                    language=request.language,
                    target=request.target,
                )
        if result.assertion:
            self.feedback.assertion_failures += 1
        if result.minimized_input and result.metadata.get("seed_source") == "symbolic":
            self.corpus.add(
                result.minimized_input,
                source=SeedSource.SYMBOLIC_EXECUTION,
                reason="symbolic counterexample",
                language=request.language,
                target=request.target,
            )
        if (
            self.feedback.rounds >= self.max_rounds
            and self.feedback.stagnating
            and not self.feedback.new_coverage
        ):
            self.feedback.difficult = True

    def _coverage_increased(self, result: DynamicResult) -> bool | None:
        """True, false, or unknown. Unknown never counts as new coverage.

        An explicit tool comparison wins. Otherwise a percent is compared only
        with a percent this scheduler already observed for the same engine.
        """
        explicit = result.coverage.get("new_coverage", result.coverage.get("new", ""))
        if explicit in {"true", "false"}:
            return explicit == "true"
        raw = result.coverage.get("coverage_percent") or result.coverage.get("percent")
        if not raw or result.coverage.get("coverage_available") == "false":
            return None
        try:
            current = float(raw)
        except ValueError:
            return None
        previous = self._coverage_seen.get(result.engine)
        self._coverage_seen[result.engine] = current
        if previous is None:
            return None
        return current > previous

    def target_from_static(
        self,
        *,
        repo_root: AnalysisRequest,
        file_path: str,
        function: str,
        contract: str = "",
        rule_id: str = "",
    ) -> AnalysisRequest:
        """Turn a static location into the next research request."""
        difficult = self.feedback.stagnating or self.feedback.difficult
        return AnalysisRequest(
            repo_root=repo_root.repo_root,
            language=repo_root.language,
            target=function or contract or file_path,
            files=repo_root.files,
            contract=contract,
            function=function,
            source_file=file_path,
            difficult=difficult,
            framework=repo_root.framework,
            has_harness=repo_root.has_harness,
            campaign_id=rule_id,
            corpus=self.corpus,
            extra={"rule_id": rule_id, "source": "static_finding"},
        )

    def _decide(self, engine: DiscoveryEngine, request: AnalysisRequest) -> ScheduleDecision:
        if request.language not in engine.supported_languages and engine.supported_languages:
            return ScheduleDecision(
                engine.engine_id,
                "skip",
                f"does not support {request.language}",
                "",
            )
        if engine.engine_id == "wake" and request.extra.get("include_wake") != "true":
            return ScheduleDecision(
                engine.engine_id,
                "skip",
                "Wake stays optional unless this round asks for it",
                EngineCapability.STATIC_ANALYSIS.value,
            )
        if engine.engine_id in {"echidna", "medusa"} and not (
            request.function or request.contract or request.has_harness
        ):
            return ScheduleDecision(
                engine.engine_id,
                "skip",
                "property and coverage fuzzing wait for a contract or harness target",
                EngineCapability.PROPERTY_TESTING.value,
            )
        if engine.engine_id == "halmos" and not (request.difficult or self.feedback.difficult):
            return ScheduleDecision(
                engine.engine_id,
                "skip",
                "symbolic testing waits until a target is hard to reach",
                EngineCapability.SYMBOLIC_EXECUTION.value,
            )
        if (
            engine.engine_id == "foundry"
            and request.framework != "foundry"
            and not request.has_harness
        ):
            return ScheduleDecision(
                engine.engine_id,
                "skip",
                "no Foundry project or harness was detected",
                EngineCapability.TEST_EXECUTION.value,
            )
        if engine.availability() is not EngineAvailability.AVAILABLE:
            return ScheduleDecision(
                engine.engine_id,
                "skip",
                "not installed",
                "",
            )
        capability = next(iter(engine.capabilities()), EngineCapability.PLANNING_ONLY)
        return ScheduleDecision(engine.engine_id, "run", "selected", capability.value)

    def plan_followup(self, request: AnalysisRequest) -> list[ScheduleDecision]:
        """Choose the next complementary engine from what the last round learned."""
        by_id = {engine.engine_id: engine for engine in self.engines}
        decisions: list[ScheduleDecision] = []
        halmos_already = any(item.startswith("halmos:run") for item in self.feedback.transitions)
        if self.feedback.difficult and "halmos" in by_id and not halmos_already:
            decision = self._decide(by_id["halmos"], request)
            if decision.action == "skip" and self.feedback.difficult:
                decision = ScheduleDecision(
                    "halmos",
                    "run"
                    if by_id["halmos"].availability() is EngineAvailability.AVAILABLE
                    else "skip",
                    "coverage stalled, so symbolic execution is justified",
                    EngineCapability.SYMBOLIC_EXECUTION.value,
                )
            decisions.append(decision)
        if self.corpus.by_source(SeedSource.SYMBOLIC_EXECUTION) and "foundry" in by_id:
            decisions.append(
                ScheduleDecision(
                    "foundry",
                    "run"
                    if by_id["foundry"].availability() is EngineAvailability.AVAILABLE
                    else "skip",
                    "symbolic counterexample becomes a fuzz seed",
                    EngineCapability.FUZZING.value,
                )
            )
        elif self.feedback.stagnating and request.function and "medusa" in by_id:
            decisions.append(
                self._decide(
                    by_id["medusa"],
                    AnalysisRequest(
                        repo_root=request.repo_root,
                        language=request.language,
                        target=request.target,
                        files=request.files,
                        contract=request.contract,
                        function=request.function,
                        source_file=request.source_file,
                        difficult=request.difficult,
                        framework=request.framework,
                        has_harness=True,
                        corpus=self.corpus,
                        extra={**request.extra, "mode": "fuzz"},
                    ),
                )
            )
        for decision in decisions:
            self.feedback.transitions.append(
                f"{decision.engine_id}:{decision.action}:{decision.reason}"
            )
        return decisions

    def run_followup(self, request: AnalysisRequest) -> list[DynamicResult]:
        results: list[DynamicResult] = []
        by_id = {engine.engine_id: engine for engine in self.engines}
        for decision in self.plan_followup(request):
            if decision.action != "run":
                continue
            engine = by_id[decision.engine_id]
            extra = dict(request.extra)
            if decision.engine_id == "foundry" and self.corpus.by_source(
                SeedSource.SYMBOLIC_EXECUTION
            ):
                extra["mode"] = "fuzz"
            elif decision.engine_id == "medusa":
                extra["mode"] = "fuzz"
            targeted = AnalysisRequest(
                repo_root=request.repo_root,
                language=request.language,
                target=request.target,
                files=request.files,
                contract=request.contract,
                function=request.function,
                source_file=request.source_file,
                difficult=True if decision.engine_id == "halmos" else request.difficult,
                framework=request.framework,
                has_harness=request.has_harness,
                match_test=request.match_test or request.function,
                corpus=self.corpus,
                extra=extra,
            )
            if (
                EngineCapability.STATIC_ANALYSIS in engine.capabilities()
                and decision.engine_id != "halmos"
            ):
                result = engine.analyze_target(targeted)
            else:
                result = engine.start_campaign(targeted)
            results.append(result)
            self.note_result(result, targeted)
        return results


def campaign_stopped(results: list[DynamicResult], *, limit: int) -> bool:
    executed = [item for item in results if item.executed]
    return len(executed) >= limit or any(
        item.status is ResultStatus.FAILED for item in executed[-1:]
    )
