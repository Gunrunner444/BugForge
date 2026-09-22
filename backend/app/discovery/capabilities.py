"""Explicit discovery-engine capabilities. Missing binaries stay unavailable."""

from __future__ import annotations

from enum import StrEnum


class EngineCapability(StrEnum):
    PLANNING_ONLY = "planning_only"
    STATIC_ANALYSIS = "static_analysis"
    FUZZING = "fuzzing"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    PROPERTY_TESTING = "property_testing"
    INVARIANT_TESTING = "invariant_testing"
    COVERAGE_FEEDBACK = "coverage_feedback"
    SANITIZER_AWARE = "sanitizer_aware"
    RESULTS_INGESTION = "results_ingestion"
    BUILD = "build"
    TEST_EXECUTION = "test_execution"


class EngineAvailability(StrEnum):
    UNAVAILABLE = "unavailable"
    AVAILABLE = "available"


class ResultStatus(StrEnum):
    """Execution truth. Planned is not executed, and unavailable is not a result."""

    PLANNED = "planned"
    UNAVAILABLE = "unavailable"
    NOT_IMPLEMENTED = "not_implemented"
    EXECUTED = "executed"
    INGESTED = "ingested"
    FAILED = "failed"
