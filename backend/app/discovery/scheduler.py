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
    "c": ("bugforge-static", "coverage-fuzz", "sanitizer"),
    "cpp": ("bugforge-static", "coverage-fuzz", "sanitizer"),
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
        if result.coverage.get("new") == "true":
            self.feedback.new_coverage = True
            self.feedback.stagnating = False
        elif result.executed and not result.coverage.get("new"):
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
        if self.feedback.rounds >= self.max_rounds and not self.feedback.new_coverage:
            self.feedback.stagnating = True
            self.feedback.difficult = True

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


def campaign_stopped(results: list[DynamicResult], *, limit: int) -> bool:
    executed = [item for item in results if item.executed]
    return len(executed) >= limit or any(
        item.status is ResultStatus.FAILED for item in executed[-1:]
    )
