"""Repair service — Phase 7 Automated Repair orchestration."""
from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any
from uuid import UUID

from app.testing.patch_planner import PatchPlan, PatchPlanner
from app.testing.patch_validator import validate_patch
from app.testing.repair_workspace import RepairWorkspace
from app.testing.test_validator import validate_test_code

logger = logging.getLogger(__name__)

_OUTPUT_LIMIT = 4_096
# Container path for the workspace repo during verification executions
_WORKSPACE_CONTAINER_PATH = "/bugforge-workspace"


class RepairService:
    """Orchestrates the full automated repair workflow for one session."""

    async def run_session(
        self,
        session_id: UUID,
        project_id: UUID,
        repository_path: str,
        hypothesis_id: UUID | None,
        reproduction_session_id: UUID | None,
        debugging_session_id: UUID | None,
        max_candidates: int = 1,
    ) -> None:
        from app.database import async_session_factory
        from app.repositories.repair_repo import RepairRepository

        logger.info("Starting repair session %s", session_id)

        async with async_session_factory() as db:
            repo = RepairRepository(db)
            await repo.update_status(session_id, "running")
            await db.commit()

        try:
            evidence = await self._load_evidence(
                project_id, hypothesis_id, reproduction_session_id, debugging_session_id
            )
            if not evidence.get("hypothesis_text"):
                await self._fail(session_id, "No hypothesis available for repair")
                return

            plans = await self._generate_candidates(evidence, repository_path, max_candidates)
            if not plans:
                await self._fail(session_id, "AI did not produce a usable patch plan")
                return

            candidate_ids: list[UUID] = []
            async with async_session_factory() as db:
                repo = RepairRepository(db)
                for rank, plan in enumerate(plans, start=1):
                    c = await repo.create_candidate(
                        session_id=session_id,
                        rank=rank,
                        patch_plan=plan.patch_plan,
                        patch_diff=plan.patch_diff,
                        changed_files=plan.changed_files,
                        provider=plan.provider,
                        model=plan.model,
                    )
                    candidate_ids.append(c.id)
                await db.commit()

            scores: list[tuple[UUID, float]] = []
            for candidate_id in candidate_ids:
                score = await self._evaluate_candidate(
                    candidate_id,
                    plans[candidate_ids.index(candidate_id)],
                    repository_path,
                    evidence,
                )
                scores.append((candidate_id, score))

            scores.sort(key=lambda x: x[1], reverse=True)
            best_id: UUID | None = None
            if scores and scores[0][1] > 0.0:
                best_id = scores[0][0]

            async with async_session_factory() as db:
                repo = RepairRepository(db)
                if best_id is not None:
                    await repo.update_candidate(
                        best_id, disposition="best"
                    )
                await repo.complete_session(session_id, len(plans), best_id)
                await db.commit()

            logger.info(
                "Repair session %s completed: %d candidates, best=%s (score=%.2f)",
                session_id,
                len(plans),
                best_id,
                scores[0][1] if scores else 0.0,
            )

        except Exception as exc:
            logger.exception("Repair session %s failed: %s", session_id, exc)
            await self._fail(session_id, str(exc))

    # ──────────────────────────────────────────────────────────────────
    # Evidence loading
    # ──────────────────────────────────────────────────────────────────

    async def _load_evidence(
        self,
        project_id: UUID,
        hypothesis_id: UUID | None,
        reproduction_session_id: UUID | None,
        debugging_session_id: UUID | None,
    ) -> dict[str, Any]:
        from app.database import async_session_factory

        async with async_session_factory() as db:
            return await self._collect_evidence(
                db, project_id, hypothesis_id, reproduction_session_id, debugging_session_id
            )

    async def _collect_evidence(
        self,
        db: Any,
        project_id: UUID,
        hypothesis_id: UUID | None,
        reproduction_session_id: UUID | None,
        debugging_session_id: UUID | None,
    ) -> dict[str, Any]:
        from sqlalchemy import select

        from app.models.analysis import Analysis
        from app.models.debugging import DebuggingHypothesis, DebuggingSession
        from app.models.finding import DBFinding
        from app.models.project import Project
        from app.models.reproduction import BugReproductionSession
        from app.models.test_run import TestResult

        evidence: dict[str, Any] = {
            "hypothesis_text": "",
            "affected_files": [],
            "reproduction_summary": "",
            "failing_tests": [],
            "static_findings": [],
            "repository_path": "",
        }

        project = await db.get(Project, project_id)
        if project:
            evidence["repository_path"] = project.repository_path

        if hypothesis_id:
            hyp = await db.get(DebuggingHypothesis, hypothesis_id)
            if hyp:
                evidence["hypothesis_text"] = hyp.root_cause
                evidence["affected_files"] = hyp.affected_files or []

        if not evidence["hypothesis_text"] and debugging_session_id:
            result = await db.execute(
                select(DebuggingHypothesis)
                .where(DebuggingHypothesis.session_id == debugging_session_id)
                .order_by(DebuggingHypothesis.confidence.desc())
                .limit(1)
            )
            hyp = result.scalar_one_or_none()
            if hyp:
                evidence["hypothesis_text"] = hyp.root_cause
                evidence["affected_files"] = hyp.affected_files or []

        if reproduction_session_id:
            repro = await db.get(BugReproductionSession, reproduction_session_id)
            if repro:
                parts: list[str] = []
                if repro.final_classification:
                    parts.append(f"Classification: {repro.final_classification}")
                if repro.target_behavior:
                    parts.append(f"Target: {repro.target_behavior}")
                if repro.expected_failure_pattern:
                    parts.append(f"Expected failure: {repro.expected_failure_pattern}")
                evidence["reproduction_summary"] = " | ".join(parts)
                evidence["reproducer_code"] = None
                if repro.attempts:
                    for attempt in repro.attempts:
                        if attempt.reproduced and attempt.reproducer_code:
                            evidence["reproducer_code"] = attempt.reproducer_code
                            break

        # Load failing tests from the debugging session's test run
        if debugging_session_id:
            ds = await db.get(DebuggingSession, debugging_session_id)
            if ds and ds.test_run_id:
                result = await db.execute(
                    select(TestResult)
                    .where(TestResult.test_run_id == ds.test_run_id)
                    .where(TestResult.status.in_(["failed", "error"]))
                    .limit(5)
                )
                evidence["failing_tests"] = [
                    {"node_id": r.node_id, "traceback": r.traceback or ""}
                    for r in result.scalars().all()
                ]

        # Load static findings
        latest_analysis = await db.execute(
            select(Analysis.id)
            .where(Analysis.project_id == project_id)
            .where(Analysis.status == "completed")
            .order_by(Analysis.created_at.desc())
            .limit(1)
        )
        analysis_id = latest_analysis.scalar_one_or_none()
        if analysis_id:
            result = await db.execute(
                select(DBFinding)
                .where(DBFinding.analysis_id == analysis_id)
                .order_by(DBFinding.severity.desc())
                .limit(5)
            )
            evidence["static_findings"] = [
                {
                    "category": r.category,
                    "severity": r.severity,
                    "file": r.file_path,
                    "line": r.line,
                    "message": r.message,
                }
                for r in result.scalars().all()
            ]

        return evidence

    # ──────────────────────────────────────────────────────────────────
    # Patch generation
    # ──────────────────────────────────────────────────────────────────

    async def _generate_candidates(
        self,
        evidence: dict[str, Any],
        repository_path: str,
        max_candidates: int,
    ) -> list[PatchPlan]:
        affected_files_content: dict[str, str] = {}
        for rel_path in (evidence.get("affected_files") or [])[:3]:
            full = Path(repository_path) / rel_path
            if full.is_file():
                try:
                    affected_files_content[rel_path] = full.read_text(
                        encoding="utf-8", errors="replace"
                    )[:4_000]
                except OSError:
                    pass

        plans: list[PatchPlan] = []
        planner = PatchPlanner()
        for _ in range(max_candidates):
            plan = await planner.plan(
                hypothesis_text=evidence["hypothesis_text"],
                reproduction_summary=evidence.get("reproduction_summary", ""),
                affected_files_content=affected_files_content,
                static_findings=evidence.get("static_findings", []),
                existing_test_failures=evidence.get("failing_tests", []),
            )
            if plan:
                plans.append(plan)

        return plans

    # ──────────────────────────────────────────────────────────────────
    # Candidate evaluation
    # ──────────────────────────────────────────────────────────────────

    async def _evaluate_candidate(
        self,
        candidate_id: UUID,
        plan: PatchPlan,
        repository_path: str,
        evidence: dict[str, Any],
    ) -> float:
        from app.database import async_session_factory
        from app.repositories.repair_repo import RepairRepository

        async with async_session_factory() as db:
            repo = RepairRepository(db)
            await repo.update_candidate(candidate_id, status="validating")
            await db.commit()

        # 1. Validate patch
        validation = validate_patch(plan.patch_diff, plan.changed_files)
        if not validation.valid:
            async with async_session_factory() as db:
                repo = RepairRepository(db)
                await repo.update_candidate(
                    candidate_id,
                    status="rejected",
                    validation_status="rejected",
                    validation_error=validation.error,
                    disposition="rejected",
                    score=0.0,
                )
                await db.commit()
            return 0.0

        async with async_session_factory() as db:
            repo = RepairRepository(db)
            await repo.update_candidate(
                candidate_id, status="applying", validation_status="valid"
            )
            await db.commit()

        # 2. Run inside disposable workspace
        try:
            workspace = RepairWorkspace.create(repository_path)
        except Exception as exc:
            async with async_session_factory() as db:
                repo = RepairRepository(db)
                await repo.update_candidate(
                    candidate_id,
                    status="rejected",
                    validation_error=f"Workspace creation failed: {exc}",
                    disposition="rejected",
                    score=0.0,
                )
                await db.commit()
            return 0.0

        try:
            result = await self._run_in_workspace(
                candidate_id, plan, workspace, repository_path, evidence
            )
        finally:
            workspace.destroy()

        return result

    async def _run_in_workspace(
        self,
        candidate_id: UUID,
        plan: PatchPlan,
        workspace: RepairWorkspace,
        repository_path: str,
        evidence: dict[str, Any],
    ) -> float:
        from app.database import async_session_factory
        from app.repositories.repair_repo import RepairRepository

        # ── Pre-patch baseline ─────────────────────────────────────────
        reproducer_code = evidence.get("reproducer_code")
        pre_reproduced: bool | None = None
        pre_stdout = ""

        if reproducer_code:
            pre_result = await self._run_reproducer(reproducer_code, workspace.repo_root)
            pre_reproduced = pre_result["exit_code"] == 1
            pre_stdout = pre_result.get("stdout", "")[:_OUTPUT_LIMIT]

        # ── Apply patch ────────────────────────────────────────────────
        async with async_session_factory() as db:
            repo = RepairRepository(db)
            await repo.update_candidate(candidate_id, status="applying")
            await db.commit()

        ok, apply_err = workspace.apply_patch(plan.patch_diff)
        if not ok:
            async with async_session_factory() as db:
                repo = RepairRepository(db)
                await repo.update_candidate(
                    candidate_id,
                    status="rejected",
                    validation_error=f"Patch application failed: {apply_err}",
                    disposition="rejected",
                    score=0.0,
                    pre_patch_reproduced=pre_reproduced,
                    pre_patch_stdout=pre_stdout,
                )
                await db.commit()
            return 0.0

        # ── Post-patch verification ────────────────────────────────────
        async with async_session_factory() as db:
            repo = RepairRepository(db)
            await repo.update_candidate(candidate_id, status="verifying")
            await db.commit()

        post_reproduced: bool | None = None
        post_stdout = ""
        bug_fixed: bool | None = None

        if reproducer_code:
            post_result = await self._run_reproducer(reproducer_code, workspace.repo_root)
            post_reproduced = post_result["exit_code"] == 1
            post_stdout = post_result.get("stdout", "")[:_OUTPUT_LIMIT]
            # Bug is fixed if it reproduced before and doesn't reproduce now
            if pre_reproduced is not None:
                bug_fixed = pre_reproduced and not post_reproduced

        # ── Existing test suite ────────────────────────────────────────
        tests_total, tests_passed, tests_failed, no_regressions, regression_count = (
            await self._run_existing_tests(workspace.repo_root)
        )

        # ── Score ──────────────────────────────────────────────────────
        score = self._compute_score(
            bug_fixed=bug_fixed,
            no_regressions=no_regressions,
            regression_count=regression_count,
        )
        disposition = "accepted" if score > 0.3 else "rejected"

        async with async_session_factory() as db:
            repo = RepairRepository(db)
            await repo.update_candidate(
                candidate_id,
                status="completed",
                pre_patch_reproduced=pre_reproduced,
                pre_patch_stdout=pre_stdout,
                post_patch_reproduced=post_reproduced,
                post_patch_stdout=post_stdout,
                bug_fixed=bug_fixed,
                existing_tests_total=tests_total,
                existing_tests_passed=tests_passed,
                existing_tests_failed=tests_failed,
                no_regressions=no_regressions,
                regression_count=regression_count,
                score=round(score, 3),
                disposition=disposition,
                completed_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            )
            await db.commit()

        return score

    async def _run_reproducer(self, code: str, workspace_repo: str) -> dict[str, Any]:
        from app.execution import ExecutorFactory
        from app.execution.base import ExecutionConfig

        try:
            with tempfile.TemporaryDirectory(prefix="bugforge_verify_") as tmpdir:
                test_file = Path(tmpdir) / "test_reproducer.py"
                test_file.write_text(code)

                # Validate before execution
                validation = validate_test_code(code)
                if not validation.valid:
                    return {"exit_code": -2, "stdout": "", "stderr": f"Validation failed: {validation.error}"}

                executor = ExecutorFactory.create()
                config = ExecutionConfig(
                    command=["python3", "-m", "pytest", "test_reproducer.py", "-v", "--tb=short", "-q"],
                    working_directory=tmpdir,
                    timeout_seconds=60,
                    output_dir=tmpdir,
                    environment={"PYTHONPATH": _WORKSPACE_CONTAINER_PATH},
                    read_only_volumes={workspace_repo: _WORKSPACE_CONTAINER_PATH},
                )
                result = await executor.execute(config)
                return {
                    "exit_code": result.exit_code,
                    "stdout": result.stdout[:_OUTPUT_LIMIT],
                    "stderr": result.stderr[:_OUTPUT_LIMIT],
                    "timed_out": result.timed_out,
                }
        except Exception as exc:
            return {"exit_code": -1, "stdout": "", "stderr": str(exc), "timed_out": False}

    async def _run_existing_tests(
        self, workspace_repo: str
    ) -> tuple[int, int, int, bool | None, int]:
        """Run the project's test suite and return (total, passed, failed, no_regressions, regression_count)."""
        from app.execution import ExecutorFactory
        from app.execution.base import ExecutionConfig

        try:
            with tempfile.TemporaryDirectory(prefix="bugforge_suite_") as tmpdir:
                executor = ExecutorFactory.create()
                config = ExecutionConfig(
                    command=[
                        "python3",
                        "-m",
                        "pytest",
                        "/bugforge-workspace",
                        "--tb=no",
                        "-q",
                        "--json-report",
                        "--json-report-file=/bugforge-output/report.json",
                    ],
                    working_directory=tmpdir,
                    timeout_seconds=120,
                    output_dir=tmpdir,
                    environment={"PYTHONPATH": _WORKSPACE_CONTAINER_PATH},
                    read_only_volumes={workspace_repo: _WORKSPACE_CONTAINER_PATH},
                )
                exec_result = await executor.execute(config)

                # Try to parse JSON report
                report_json = exec_result.artifact_contents.get("report.json", "")
                if report_json:
                    try:
                        report = json.loads(report_json)
                        summary = report.get("summary", {})
                        total = summary.get("total", 0)
                        passed = summary.get("passed", 0)
                        failed = summary.get("failed", 0) + summary.get("error", 0)
                        no_regressions = failed == 0
                        return total, passed, failed, no_regressions, failed
                    except (json.JSONDecodeError, KeyError):
                        pass

                # Fallback: infer from exit code
                if exec_result.exit_code == 0:
                    return 0, 0, 0, True, 0
                return 0, 0, 0, None, 0

        except Exception as exc:
            logger.warning("Existing test run failed: %s", exc)
            return 0, 0, 0, None, 0

    def _compute_score(
        self,
        bug_fixed: bool | None,
        no_regressions: bool | None,
        regression_count: int,
    ) -> float:
        """Composite score 0.0–1.0 based on verification evidence.

        Score components:
          - Bug fixed (pre reproduced, post not reproduced): +0.7
          - No regressions in existing tests: +0.3
          - Each regression: -0.1 (capped at -0.3)
        """
        score = 0.0

        if bug_fixed is True:
            score += 0.7
        elif bug_fixed is False:
            # Patch didn't fix the bug — score stays at 0 for this component
            pass
        # None means we couldn't verify (no reproducer available)

        if no_regressions is True:
            score += 0.3
        elif no_regressions is False:
            penalty = min(regression_count * 0.1, 0.3)
            score -= penalty

        return round(max(0.0, min(1.0, score)), 3)

    # ──────────────────────────────────────────────────────────────────
    # Error handling
    # ──────────────────────────────────────────────────────────────────

    async def _fail(self, session_id: UUID, message: str) -> None:
        from app.database import async_session_factory
        from app.repositories.repair_repo import RepairRepository

        async with async_session_factory() as db:
            repo = RepairRepository(db)
            await repo.update_status(session_id, "failed", error_message=message)
            await db.commit()
