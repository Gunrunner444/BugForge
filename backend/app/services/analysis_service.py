from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from uuid import UUID

from app.analyzers.repo_analyzer import AnalysisResult, RepoAnalyzer
from app.models.analysis import Analysis, CodeEntity, ImportRecord, RepositoryFile

logger = logging.getLogger(__name__)


class AnalysisNotFoundError(Exception):
    pass


class AnalysisService:
    """Orchestrates repository analysis and persists results."""

    def __init__(self) -> None:
        self._analyzer = RepoAnalyzer()

    async def start_analysis(self, project_id: UUID, repository_path: str) -> Analysis:
        """Creates the analysis record and returns it. The caller schedules run_analysis()."""
        from app.database import async_session_factory
        from app.repositories.analysis_repo import AnalysisRepository

        async with async_session_factory() as session:
            repo = AnalysisRepository(session)
            analysis = await repo.create(project_id=project_id, repository_path=repository_path)
            await session.commit()
            await session.refresh(analysis)
            return analysis

    async def run_analysis(self, analysis_id: UUID, repository_path: str) -> None:
        """Full analysis pipeline. Designed to run as a background task."""
        from app.database import async_session_factory
        from app.repositories.analysis_repo import AnalysisRepository

        logger.info("Starting analysis %s for %s", analysis_id, repository_path)

        async with async_session_factory() as session:
            repo = AnalysisRepository(session)
            await repo.update_status(analysis_id, "running")
            await session.commit()

        try:
            start_time = time.monotonic()
            analysis_result = await asyncio.to_thread(
                self._analyzer.analyze, Path(repository_path)
            )
            duration = time.monotonic() - start_time

            async with async_session_factory() as session:
                await self._persist_results(session, analysis_id, analysis_result, duration)
                await session.commit()

            logger.info(
                "Analysis %s completed in %.2fs — %d files",
                analysis_id,
                duration,
                analysis_result.total_files,
            )
        except Exception as exc:
            logger.exception("Analysis %s failed: %s", analysis_id, exc)
            async with async_session_factory() as session:
                repo = AnalysisRepository(session)
                await repo.update_status(analysis_id, "failed", error_message=str(exc))
                await session.commit()

    async def _persist_results(
        self,
        session,
        analysis_id: UUID,
        result: AnalysisResult,
        duration: float,
    ) -> None:
        from app.repositories.analysis_repo import AnalysisRepository

        total_entities = 0
        total_imports = 0

        for fr in result.file_results:
            file_record = RepositoryFile(
                analysis_id=analysis_id,
                relative_path=fr.relative_path,
                file_type=fr.file_type,
                language=fr.language,
                size_bytes=fr.size_bytes,
                line_count=fr.line_count,
                has_errors=fr.has_parse_errors,
            )
            session.add(file_record)
            await session.flush()  # obtain file_record.id

            if fr.parse_result:
                for entity in fr.parse_result.entities:
                    session.add(
                        CodeEntity(
                            file_id=file_record.id,
                            entity_type=entity.entity_type,
                            name=entity.name,
                            qualified_name=entity.qualified_name,
                            start_line=entity.start_line,
                            end_line=entity.end_line,
                            docstring=entity.docstring,
                            is_async="async" in entity.entity_type,
                            decorators=entity.decorators,
                            parameters=[
                                {
                                    "name": p.name,
                                    "annotation": p.annotation,
                                    "default": p.default,
                                    "kind": p.kind,
                                }
                                for p in entity.parameters
                            ],
                            return_annotation=entity.return_annotation,
                            parent_name=entity.parent,
                        )
                    )
                total_entities += len(fr.parse_result.entities)

                for imp in fr.parse_result.imports:
                    session.add(
                        ImportRecord(
                            file_id=file_record.id,
                            module_name=imp.module,
                            imported_name=imp.name,
                            alias=imp.alias,
                            import_type=imp.import_type,
                            line_number=imp.line_number,
                            is_from_import=imp.is_from_import,
                        )
                    )
                total_imports += len(fr.parse_result.imports)

        summary = {
            "total_files": result.total_files,
            "source_files": result.source_file_count,
            "test_files": result.test_file_count,
            "ignored_files": result.ignored_file_count,
            "total_entities": total_entities,
            "total_imports": total_imports,
            "languages": [
                {
                    "language": ls.language,
                    "file_count": ls.file_count,
                    "percentage": ls.percentage,
                }
                for ls in result.language_stats
            ],
            "frameworks": [
                {
                    "name": fw.name,
                    "language": fw.language,
                    "confidence": fw.confidence,
                    "evidence": fw.evidence,
                }
                for fw in result.framework_detections
            ],
            "analysis_duration_seconds": round(duration, 3),
        }

        repo = AnalysisRepository(session)
        await repo.complete_analysis(analysis_id, summary)
