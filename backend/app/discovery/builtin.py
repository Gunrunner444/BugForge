"""In-process static engine. It reuses SecurityAnalysisEngine and does not verify."""

from __future__ import annotations

from pathlib import Path

from app.discovery.capabilities import EngineAvailability, EngineCapability, ResultStatus
from app.discovery.engine import AnalysisRequest, DiscoveryEngine
from app.discovery.results import DynamicFinding, DynamicResult


class BugforgeStaticEngine(DiscoveryEngine):
    @property
    def engine_id(self) -> str:
        return "bugforge-static"

    @property
    def display_name(self) -> str:
        return "BugForge static analysis"

    @property
    def supported_languages(self) -> frozenset[str]:
        return frozenset({"solidity", "python", "go", "java", "javascript", "typescript"})

    def capabilities(self) -> frozenset[EngineCapability]:
        return frozenset({EngineCapability.STATIC_ANALYSIS, EngineCapability.RESULTS_INGESTION})

    def availability(self) -> EngineAvailability:
        return EngineAvailability.AVAILABLE

    def version(self) -> str:
        return "phase27"

    def _analyze_target(self, request: AnalysisRequest) -> DynamicResult:
        from app.security.engine import SecurityAnalysisEngine

        files = [request.repo_root / path for path in request.files]
        files = [path for path in files if path.is_file()]
        if not files:
            files = list(request.repo_root.rglob("*.sol"))[:40]
        result = SecurityAnalysisEngine().analyze_repository(request.repo_root, files)
        findings = tuple(
            DynamicFinding(
                detector_id=item.rule_id,
                title=item.title,
                confidence=item.confidence,
                function=item.metadata.get("function", ""),
                contract=item.metadata.get("contract", ""),
                file_path=item.file_path,
                line=item.line,
                description=item.summary,
                status="potential",
            )
            for item in result.observations
            if not request.function or item.metadata.get("function") in {"", request.function}
        )
        return DynamicResult(
            engine=self.engine_id,
            engine_version=self.version(),
            language=request.language,
            target=request.target or str(request.repo_root),
            status=ResultStatus.INGESTED,
            executed=True,
            findings=findings,
            source_file=request.source_file,
            function=request.function,
            contract=request.contract,
            provenance="bugforge_static",
            metadata={"verified": "false", "files": str(result.files_analyzed)},
        )


def foundry_project(root: Path) -> bool:
    return (root / "foundry.toml").is_file()
