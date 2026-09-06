"""Bug reproduction service — Phase 6 orchestration."""
from __future__ import annotations

import logging
import sys
import tempfile
from pathlib import Path
from typing import Any
from uuid import UUID

from app.testing.reproduction_planner import ReproductionPlanner
from app.testing.test_validator import validate_test_code

logger = logging.getLogger(__name__)

_OUTPUT_LIMIT = 4_096
_DEFAULT_ATTEMPTS = 3


class BugReproductionService:
    async def run_session(
        self,
        session_id: UUID,
        project_id: UUID,
        repository_path: str,
        hypothesis_id: UUID | None,
        generated_test_id: UUID | None,
        total_attempts: int = _DEFAULT_ATTEMPTS,
    ) -> None:
        from app.database import async_session_factory
        from app.repositories.reproduction_repo import ReproductionRepository

        logger.info("Starting reproduction session %s", session_id)

        async with async_session_factory() as db:
            repo = ReproductionRepository(db)
            await repo.update_status(session_id, "running")
            await db.commit()

        try:
            reproducer_code = await self._get_reproducer(
                repository_path, hypothesis_id, generated_test_id, project_id
            )
            if not reproducer_code:
                await self._fail(session_id, "No reproducer code available")
                return

            validation = validate_test_code(reproducer_code)
            if not validation.valid:
                await self._fail(session_id, f"Reproducer rejected: {validation.error}")
                return

            results = await self._run_attempts(
                reproducer_code, repository_path, total_attempts
            )
            await self._persist_results(session_id, reproducer_code, results)

        except Exception as exc:
            logger.exception("Reproduction session %s failed: %s", session_id, exc)
            await self._fail(session_id, str(exc))

    async def _get_reproducer(
        self,
        repository_path: str,
        hypothesis_id: UUID | None,
        generated_test_id: UUID | None,
        project_id: UUID,
    ) -> str | None:
        from app.database import async_session_factory

        # 1. Use existing generated test if provided
        if generated_test_id is not None:
            async with async_session_factory() as db:

                from app.models.test_generation import GeneratedTest

                row = await db.get(GeneratedTest, generated_test_id)
                if row and row.generated_code:
                    return row.generated_code

        # 2. Use AI planner to generate a reproducer from the hypothesis
        if hypothesis_id is not None:
            async with async_session_factory() as db:
                from app.models.debugging import DebuggingHypothesis

                hyp = await db.get(DebuggingHypothesis, hypothesis_id)
                if hyp:
                    failing_tests = await self._load_failing_tests(db, hyp.session_id)
                    findings = await self._load_findings_for_project(db, project_id)
                    planner = ReproductionPlanner()
                    plan = await planner.plan(
                        hypothesis_text=hyp.root_cause,
                        repository_path=repository_path,
                        failing_tests=failing_tests,
                        static_findings=findings,
                    )
                    if plan:
                        return plan.reproducer_code

        return None

    async def _load_failing_tests(self, db: Any, debugging_session_id: UUID) -> list[dict[str, Any]]:
        from sqlalchemy import select

        from app.models.debugging import DebuggingSession
        from app.models.test_run import TestResult

        session = await db.get(DebuggingSession, debugging_session_id)
        if session is None or session.test_run_id is None:
            return []
        result = await db.execute(
            select(TestResult)
            .where(TestResult.test_run_id == session.test_run_id)
            .where(TestResult.status.in_(["failed", "error"]))
            .limit(3)
        )
        rows = result.scalars().all()
        return [{"node_id": r.node_id, "traceback": r.traceback or ""} for r in rows]

    async def _load_findings_for_project(self, db: Any, project_id: UUID) -> list[dict[str, Any]]:
        from sqlalchemy import select

        from app.models.analysis import Analysis
        from app.models.finding import DBFinding

        latest_analysis_id = await db.execute(
            select(Analysis.id)
            .where(Analysis.project_id == project_id)
            .where(Analysis.status == "completed")
            .order_by(Analysis.created_at.desc())
            .limit(1)
        )
        analysis_id = latest_analysis_id.scalar_one_or_none()
        if not analysis_id:
            return []
        result = await db.execute(
            select(DBFinding)
            .where(DBFinding.analysis_id == analysis_id)
            .order_by(DBFinding.severity.desc())
            .limit(5)
        )
        rows = result.scalars().all()
        return [{"category": r.category, "severity": r.severity, "file": r.file_path, "line": r.line, "message": r.message} for r in rows]

    async def _run_attempts(
        self, code: str, repository_path: str, total: int
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for n in range(1, total + 1):
            result = await self._single_attempt(code, repository_path, n)
            results.append(result)
        return results

    async def _single_attempt(
        self, code: str, repository_path: str, attempt_number: int
    ) -> dict[str, Any]:
        from app.execution import ExecutorFactory
        from app.execution.base import ExecutionConfig

        try:
            with tempfile.TemporaryDirectory(prefix="bugforge_repro_") as tmpdir:
                test_file = Path(tmpdir) / "test_reproducer.py"
                test_file.write_text(code)
                executor = ExecutorFactory.create()
                config = ExecutionConfig(
                    command=[sys.executable, "-m", "pytest", "test_reproducer.py", "-v", "--tb=short", "-q"],
                    working_directory=tmpdir,
                    timeout_seconds=60,
                    output_dir=tmpdir,
                    environment={"PYTHONPATH": repository_path},
                )
                exec_result = await executor.execute(config)

                if exec_result.timed_out:
                    cls = "timeout"
                    reproduced = False
                elif exec_result.exit_code == 0:
                    # Test passed — bug NOT reproduced (test succeeded without triggering the issue)
                    cls = "failed"
                    reproduced = False
                elif exec_result.exit_code == 1:
                    # pytest exit_code 1 = tests ran and at least one FAILED — bug reproduced
                    cls = "reproduced"
                    reproduced = True
                elif exec_result.error_message:
                    cls = "environment_error"
                    reproduced = False
                else:
                    cls = "error"
                    reproduced = False

                return {
                    "attempt_number": attempt_number,
                    "exit_code": exec_result.exit_code,
                    "stdout": exec_result.stdout[:_OUTPUT_LIMIT],
                    "stderr": exec_result.stderr[:_OUTPUT_LIMIT],
                    "duration_seconds": exec_result.duration_seconds,
                    "timed_out": exec_result.timed_out,
                    "reproduced": reproduced,
                    "classification": cls,
                    "reproducer_code": code,
                    "command": " ".join(config.command),
                }
        except Exception as exc:
            return {
                "attempt_number": attempt_number,
                "exit_code": None,
                "stdout": "",
                "stderr": str(exc),
                "duration_seconds": 0.0,
                "timed_out": False,
                "reproduced": False,
                "classification": "error",
                "reproducer_code": code,
                "command": "",
            }

    async def _persist_results(
        self, session_id: UUID, reproducer_code: str, results: list[dict[str, Any]]
    ) -> None:
        from app.database import async_session_factory
        from app.repositories.reproduction_repo import ReproductionRepository

        successful = sum(1 for r in results if r["reproduced"])
        total = len(results)
        rate = successful / total if total > 0 else 0.0

        if successful == 0:
            cls = "not_reproduced"
        elif successful == total:
            cls = "consistently_reproduced"
        elif successful >= total * 0.5:
            cls = "intermittent"
        else:
            cls = "inconclusive"

        async with async_session_factory() as db:
            repo = ReproductionRepository(db)
            for r in results:
                await repo.add_attempt(session_id, r)
            await repo.complete(session_id, successful, total, rate, cls)
            await db.commit()

        logger.info(
            "Reproduction session %s: %d/%d reproduced → %s",
            session_id, successful, total, cls,
        )

    async def _fail(self, session_id: UUID, message: str) -> None:
        from app.database import async_session_factory
        from app.repositories.reproduction_repo import ReproductionRepository

        async with async_session_factory() as db:
            repo = ReproductionRepository(db)
            await repo.update_status(session_id, "failed", error_message=message)
            await db.commit()
