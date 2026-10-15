"""Static analysis stays on the target, stops on a deadline, and does not verify."""

from __future__ import annotations

import time
from pathlib import Path

from app.analyzers.framework_detector import FrameworkInfo
from app.discovery.bounty.research_ledger import campaign_coverage
from app.discovery.builtin import BugforgeStaticEngine
from app.discovery.capabilities import ResultStatus
from app.discovery.engine import AnalysisRequest
from app.discovery.orchestration.evidence import items_from_result
from app.discovery.orchestration.model import CampaignIdentity, ExecutionPhase
from app.domain.security import VulnerabilityClass
from app.parsing.model import SyntaxGraph
from app.security.engine import SecurityAnalysisEngine
from app.security.rules.base import RuleDocumentation, SecurityObservation, SecurityRule


class _SlowRule(SecurityRule):
    rule_id = "test.slow"
    vulnerability_class = VulnerabilityClass.INJECTION
    documentation = RuleDocumentation("test", "test", "test", "test")

    def __init__(self) -> None:
        self.calls: list[str] = []

    def check(
        self,
        graph: SyntaxGraph,
        *,
        frameworks: tuple[FrameworkInfo, ...] | list[FrameworkInfo] = (),
    ) -> list[SecurityObservation]:
        self.calls.append(graph.file_path)
        time.sleep(0.05)
        return [
            SecurityObservation(
                rule_id=self.rule_id,
                vulnerability_class=self.vulnerability_class,
                title="marker",
                summary="marker",
                file_path=graph.file_path,
                line=1,
                evidence_text="marker",
                confidence="low",
                language="solidity",
                documentation=self.documentation,
            )
        ]


def _write(root: Path, name: str, body: str) -> None:
    (root / name).write_text(
        f"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n{body}\n",
        encoding="utf-8",
    )


def test_rules_run_on_targets_and_not_on_dependencies(tmp_path: Path) -> None:
    _write(tmp_path, "Target.sol", "contract Target { function f() external {} }")
    _write(tmp_path, "Dep.sol", "contract Dep { function g() external {} }")
    rule = _SlowRule()
    result = SecurityAnalysisEngine([rule]).analyze_repository(
        tmp_path,
        [tmp_path / "Target.sol", tmp_path / "Dep.sol"],
        target_files={"Target.sol"},
        deadline_s=30,
    )
    assert result.status == "COMPLETED"
    assert rule.calls == ["Target.sol"]
    assert {item.file_path for item in result.observations} == {"Target.sol"}
    assert result.dependency_files == 1
    assert result.target_files == 1
    assert "parse" in result.timings_ms


def test_cancellation_stops_before_later_rules(tmp_path: Path) -> None:
    _write(tmp_path, "Target.sol", "contract Target { function f() external {} }")
    rule = _SlowRule()
    result = SecurityAnalysisEngine([rule]).analyze_repository(
        tmp_path,
        [tmp_path / "Target.sol"],
        deadline_s=30,
        cancel=lambda: True,
    )
    assert result.status == "PARTIAL"
    assert rule.calls == []
    assert result.observations == []
    assert any("cancelled" in item for item in result.limitations)


def test_a_deadline_is_reported_as_a_timeout(tmp_path: Path) -> None:
    _write(tmp_path, "Target.sol", "contract Target { function f() external {} }")
    rule = _SlowRule()
    result = SecurityAnalysisEngine([rule]).analyze_repository(
        tmp_path,
        [tmp_path / "Target.sol"],
        deadline_s=0,
    )
    assert result.status == "TIMED_OUT"
    assert rule.calls == []
    request = AnalysisRequest(
        tmp_path,
        "solidity",
        files=("Target.sol",),
        extra={"static_analysis_deadline_s": "0", "analysis_targets": "Target.sol"},
    )
    dynamic = BugforgeStaticEngine()._analyze_target(request)
    assert dynamic.status is ResultStatus.TIMEOUT
    assert dynamic.executed is False
    assert dynamic.metadata["verified"] == "false"
    assert dynamic.metadata["analysis_status"] == "TIMED_OUT"


def test_completed_static_evidence_keeps_stage_timings(tmp_path: Path) -> None:
    _write(tmp_path, "Target.sol", "contract Target { function f() external {} }")
    _write(tmp_path, "Dep.sol", "contract Dep { function g() external {} }")
    request = AnalysisRequest(
        tmp_path,
        "solidity",
        files=("Target.sol", "Dep.sol"),
        extra={"analysis_targets": "Target.sol"},
        contract="Target",
        function="f",
    )
    dynamic = BugforgeStaticEngine()._analyze_target(request)
    assert dynamic.status is ResultStatus.INGESTED
    assert dynamic.executed is True
    assert dynamic.metadata["verified"] == "false"
    assert dynamic.metadata["analysis_status"] == "COMPLETED"
    assert dynamic.metadata["target_files"] == "1"
    assert dynamic.metadata["dependency_files"] == "1"
    assert int(dynamic.metadata["timing_total_ms"]) >= 0
    items = items_from_result(
        dynamic,
        identity=CampaignIdentity(
            "c",
            source_snapshot="",
            compiler_configuration="",
            contract="Target",
            function="f",
        ),
        capability="static_analysis",
        execution_key="k",
        phase=ExecutionPhase.COMPLETED,
    )
    summary = next(item for item in items if item.kind != "finding")
    assert summary.attrs["analysis_status"] == "COMPLETED"
    assert summary.attrs["target_files"] == "1"
    assert summary.attrs["dependency_files"] == "1"
    assert "timing_total_ms" in summary.attrs
    assert summary.attrs["verified"] == "false"


def test_a_timed_out_campaign_cannot_be_marked_verified() -> None:
    summary = campaign_coverage(
        files_discovered=1,
        files_selected=1,
        files_read=1,
        dependency_status="traced",
        selection_mode="explicit",
        candidates=1,
        sequences=1,
        static_analysis_status="TIMED_OUT",
    )
    assert summary["verified"] is False
    assert summary["analysis_complete"] is False
    assert summary["static_analysis_status"] == "TIMED_OUT"
    assert "not verified" in summary["blocker"]
