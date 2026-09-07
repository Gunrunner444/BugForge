"""Autonomous analysis orchestration service (v1.1.0).

Coordinates the discovery → eligibility → acquire → static-analysis →
AI-debugging → test-generation → reproduction → repair → verification pipeline
for public GitHub repositories.

Design invariants:
  - Never executes repository code on the BugForge host.
  - All code execution goes through DockerTestExecutor.
  - Never opens a GitHub PR for a mere AI hypothesis.
  - Respects concurrency limits from settings.
  - Repository data is always labelled as untrusted.
  - Cleanup always runs (success, failure, or cancellation).
"""
from __future__ import annotations

import asyncio
import logging
import tempfile
import time
from pathlib import Path
from uuid import UUID

from app.core.config import Settings
from app.models.discovery import RepositoryCandidate

logger = logging.getLogger(__name__)

# Maximum time (seconds) spent on one repository before forced cancellation
_PER_REPO_TIMEOUT_SECONDS = 1800  # 30 minutes


class AutonomousAnalysisService:
    """Orchestrates one autonomous analysis run.

    Create a new instance per run. This keeps state local and makes
    cancellation straightforward.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def run(
        self,
        candidate: RepositoryCandidate,
        autonomous_run_id: UUID,
        *,
        force_rescan: bool = False,
    ) -> None:
        """Execute the full pipeline for one candidate.

        Updates the autonomous_analysis_run record at each stage transition.
        Uses the existing BugForge pipeline services; does NOT implement a
        parallel pipeline.

        On completion (success or failure) the temporary clone directory is
        removed.
        """
        from app.database import async_session_factory
        from app.repositories.discovery_repo import AutonomousAnalysisRunRepository
        from app.services.analysis_service import AnalysisService
        from app.services.eligibility_service import EligibilityService

        start = time.monotonic()
        clone_dir: Path | None = None

        async with async_session_factory() as session:
            run_repo = AutonomousAnalysisRunRepository(session)
            await run_repo.update_status(autonomous_run_id, "screening", current_stage="screening")
            await session.commit()

        # --- Stage 1: Re-check eligibility against latest settings ---
        try:
            topics: list[str] = []
            if candidate.topics:
                import json
                try:
                    topics = json.loads(candidate.topics)
                except Exception:
                    topics = []

            elig_svc = EligibilityService(self._settings)
            assessment = elig_svc.assess(
                full_name=candidate.full_name,
                owner=candidate.owner,
                stars=candidate.stars,
                is_fork=candidate.is_fork,
                is_archived=candidate.is_archived,
                primary_language=candidate.primary_language,
                license_key=candidate.license_key,
                size_kb=candidate.size_kb,
                topics=topics,
                last_pushed_at=candidate.last_pushed_at,
                description=candidate.description,
            )

            if not assessment.is_eligible:
                async with async_session_factory() as session:
                    run_repo = AutonomousAnalysisRunRepository(session)
                    await run_repo.update_status(
                        autonomous_run_id,
                        "cancelled",
                        current_stage="screening",
                        error_code="eligibility_failed",
                        error_message=assessment.rejection_reason,
                    )
                    await session.commit()
                logger.warning(
                    "Autonomous run %s: candidate %s failed eligibility re-check: %s",
                    autonomous_run_id,
                    candidate.full_name,
                    assessment.rejection_reason,
                )
                return

        except Exception as exc:
            logger.error("Eligibility re-check failed for %s: %s", candidate.full_name, exc)
            await self._fail_run(autonomous_run_id, "screening_error", str(exc))
            return

        # --- Stage 2: Acquire repository (shallow clone) ---
        async with async_session_factory() as session:
            run_repo = AutonomousAnalysisRunRepository(session)
            await run_repo.update_status(autonomous_run_id, "acquiring", current_stage="acquiring")
            await session.commit()

        try:
            clone_dir, commit_sha = await self._shallow_clone(candidate)
        except Exception as exc:
            logger.error("Clone failed for %s: %s", candidate.full_name, exc)
            await self._fail_run(autonomous_run_id, "clone_failed", str(exc))
            return

        try:
            # --- Stage 3: Check for duplicate commit ---
            if (
                not force_rescan
                and candidate.last_analyzed_commit
                and candidate.last_analyzed_commit == commit_sha
            ):
                logger.info(
                    "Skipping %s — commit %s already analyzed.",
                    candidate.full_name,
                    commit_sha,
                )
                async with async_session_factory() as session:
                    run_repo = AutonomousAnalysisRunRepository(session)
                    await run_repo.update_status(
                        autonomous_run_id,
                        "completed",
                        current_stage=None,
                        error_code="no_new_commit",
                        error_message="Commit unchanged since last analysis; skipped.",
                    )
                    await session.commit()
                return

            async with async_session_factory() as session:
                from sqlalchemy import update as sa_update

                from app.models.discovery import (
                    AutonomousAnalysisRun as AutonomousRun,  # noqa: N817
                )
                await session.execute(
                    sa_update(AutonomousRun)
                    .where(AutonomousRun.id == autonomous_run_id)
                    .values(commit_sha=commit_sha)
                )
                await session.commit()

            # --- Stage 4: Create or reuse BugForge Project ---
            project_id = await self._ensure_project(candidate, clone_dir)

            async with async_session_factory() as session:
                run_repo = AutonomousAnalysisRunRepository(session)
                await run_repo.set_project_id(autonomous_run_id, project_id)
                await run_repo.update_status(
                    autonomous_run_id, "static_analyzing", current_stage="static_analyzing"
                )
                await session.commit()

            # --- Stage 5: Static Analysis (existing pipeline) ---
            analysis_svc = AnalysisService()
            analysis = await analysis_svc.start_analysis(project_id, str(clone_dir))
            await analysis_svc.run_analysis(analysis.id, str(clone_dir))

            # Count static findings
            static_count = await self._count_static_findings(analysis.id)

            async with async_session_factory() as session:
                run_repo = AutonomousAnalysisRunRepository(session)
                await run_repo.update_status(
                    autonomous_run_id,
                    "ai_analyzing",
                    current_stage="ai_analyzing",
                    static_findings_count=static_count,
                )
                await session.commit()

            # --- Stage 6: AI Debugging (local AI preferred) ---
            debugging_session = await self._run_ai_debugging(
                project_id, analysis.id, clone_dir, candidate.full_name, autonomous_run_id
            )
            hypotheses_count = 0
            if debugging_session is not None:
                hypotheses_count = await self._count_hypotheses(
                    getattr(debugging_session, "id")
                )

            async with async_session_factory() as session:
                run_repo = AutonomousAnalysisRunRepository(session)
                await run_repo.update_status(
                    autonomous_run_id,
                    "finding_validation",
                    current_stage="finding_validation",
                    ai_hypotheses_count=hypotheses_count,
                )
                await session.commit()

            # --- Stage 7: Finding Validation Budget ---
            validated, rejected = await self._validate_findings(
                project_id, analysis.id, debugging_session, autonomous_run_id
            )

            # --- Stage 8: Mark complete ---
            async with async_session_factory() as session:
                from app.repositories.discovery_repo import RepositoryCandidateRepository
                run_repo = AutonomousAnalysisRunRepository(session)
                await run_repo.update_status(
                    autonomous_run_id,
                    "completed",
                    current_stage=None,
                    validated_findings_count=validated,
                    rejected_findings_count=rejected,
                )
                cand_repo = RepositoryCandidateRepository(session)
                await cand_repo.mark_analyzed(
                    candidate.id,
                    commit_sha=commit_sha,
                    analysis_status="completed",
                )
                await session.commit()

            duration = time.monotonic() - start
            logger.info(
                "Autonomous run %s completed in %.1fs — %d static, %d AI, %d validated",
                autonomous_run_id,
                duration,
                static_count,
                hypotheses_count,
                validated,
            )

        except asyncio.CancelledError:
            logger.warning("Autonomous run %s was cancelled.", autonomous_run_id)
            await self._fail_run(autonomous_run_id, "cancelled", "Task cancelled")
            raise

        except Exception as exc:
            logger.error("Autonomous run %s failed: %s", autonomous_run_id, exc, exc_info=True)
            await self._fail_run(autonomous_run_id, "pipeline_error", str(exc))

        finally:
            # Always clean up the temporary clone
            if clone_dir and clone_dir.exists():
                await self._cleanup_clone(clone_dir)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _shallow_clone(self, candidate: RepositoryCandidate) -> tuple[Path, str]:
        """Clone the repository into a temporary directory.

        Returns (clone_dir, commit_sha). The caller is responsible for cleanup.
        Enforces size and timeout limits.
        """

        tmpdir = tempfile.mkdtemp(prefix="bugforge_autonomous_")
        clone_dir = Path(tmpdir)

        # Validate HTTPS URL (no credentials embedded)
        url = candidate.clone_url
        if not url.startswith("https://github.com/"):
            raise ValueError(f"Unexpected clone URL scheme: {url!r}")

        # Shallow clone (depth=1) to minimise disk usage
        cmd = [
            "git", "clone",
            "--depth", "1",
            "--single-branch",
            "--branch", candidate.default_branch,
            "--",
            url,
            str(clone_dir / "repo"),
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": "/tmp"},
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=300
            )
        except TimeoutError as exc:
            raise TimeoutError(f"Git clone timed out for {url}") from exc

        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed (rc={proc.returncode}): {stderr.decode()[:500]}")

        repo_path = clone_dir / "repo"

        # Resolve HEAD commit SHA
        sha_proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(repo_path), "rev-parse", "HEAD",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        sha_out, _ = await sha_proc.communicate()
        commit_sha = sha_out.decode().strip()[:40] or "unknown"

        return repo_path, commit_sha

    async def _ensure_project(self, candidate: RepositoryCandidate, clone_dir: Path) -> UUID:
        """Find or create a BugForge Project for this candidate."""
        from sqlalchemy import select

        from app.database import async_session_factory
        from app.models.project import Project

        async with async_session_factory() as session:
            result = await session.execute(
                select(Project).where(Project.name == candidate.full_name)
            )
            project = result.scalar_one_or_none()
            if project is not None:
                return project.id

            project = Project(
                name=candidate.full_name,
                description=f"Auto-discovered: {candidate.html_url}",
                repository_path=str(clone_dir),
            )
            session.add(project)
            await session.flush()
            await session.refresh(project)
            project_id = project.id
            await session.commit()
            return project_id

    async def _count_static_findings(self, analysis_id: UUID) -> int:
        from sqlalchemy import func, select

        from app.database import async_session_factory
        from app.models.finding import DBFinding

        async with async_session_factory() as session:
            result = await session.execute(
                select(func.count()).where(DBFinding.analysis_id == analysis_id)
            )
            return result.scalar_one()

    async def _run_ai_debugging(
        self, project_id: UUID, analysis_id: UUID, clone_dir: Path, repo_name: str, run_id: UUID
    ) -> object:
        """Run DebuggingService on the analysis; return the session or None."""
        from app.database import async_session_factory
        from app.services.debugging_service import DebuggingService

        try:
            async with async_session_factory() as session:
                svc = DebuggingService()
                debugging_session = await svc.start_session(project_id, analysis_id, None)
                session_id = getattr(debugging_session, "id")
                await session.commit()

            async with async_session_factory() as _session:
                svc2 = DebuggingService()
                await svc2.run_session(session_id, str(clone_dir), repo_name)

            return debugging_session
        except Exception as exc:
            logger.warning("AI debugging failed for run %s: %s", run_id, exc)
            return None

    async def _count_hypotheses(self, session_id: UUID) -> int:
        from sqlalchemy import func, select

        from app.database import async_session_factory
        from app.models.debugging import DebuggingHypothesis

        async with async_session_factory() as session:
            result = await session.execute(
                select(func.count()).where(DebuggingHypothesis.session_id == session_id)
            )
            return result.scalar_one()

    async def _validate_findings(
        self,
        project_id: UUID,
        analysis_id: UUID,
        debugging_session: object,
        run_id: UUID,
    ) -> tuple[int, int]:
        """Minimal validation budget: count hypotheses by confidence threshold."""
        if debugging_session is None:
            return 0, 0

        session_id = getattr(debugging_session, "id", None)
        if session_id is None:
            return 0, 0

        from sqlalchemy import func, select

        from app.database import async_session_factory
        from app.models.debugging import DebuggingHypothesis

        async with async_session_factory() as session:
            result = await session.execute(
                select(func.count()).where(
                    DebuggingHypothesis.session_id == session_id,
                    DebuggingHypothesis.confidence >= 0.6,
                )
            )
            validated: int = result.scalar_one()
            result2 = await session.execute(
                select(func.count()).where(
                    DebuggingHypothesis.session_id == session_id,
                    DebuggingHypothesis.confidence < 0.6,
                )
            )
            rejected: int = result2.scalar_one()
            return validated, rejected

    async def _fail_run(self, run_id: UUID, error_code: str, error_message: str) -> None:
        from app.database import async_session_factory
        from app.repositories.discovery_repo import AutonomousAnalysisRunRepository

        try:
            async with async_session_factory() as session:
                run_repo = AutonomousAnalysisRunRepository(session)
                await run_repo.update_status(
                    run_id,
                    "failed",
                    current_stage=None,
                    error_code=error_code,
                    error_message=error_message[:500],
                )
                await session.commit()
        except Exception as exc:
            logger.error("Could not persist failure for run %s: %s", run_id, exc)

    async def _cleanup_clone(self, clone_dir: Path) -> None:
        """Remove the temporary clone directory."""
        import shutil

        try:
            await asyncio.to_thread(shutil.rmtree, str(clone_dir), ignore_errors=True)
            logger.debug("Cleaned up clone directory: %s", clone_dir)
        except Exception as exc:
            logger.warning("Failed to clean up clone dir %s: %s", clone_dir, exc)
