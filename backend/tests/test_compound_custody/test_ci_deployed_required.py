"""The Compound job checks out and requires the deployed 059c1191 source."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_compound_custody.deployed_support import DEPLOYED_PIN, deployed_root

WORKFLOW = Path(__file__).resolve().parents[3] / ".github" / "workflows" / "backend.yml"


def test_the_compound_job_runs_the_deployed_source_tests() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    job = text.split("compound-integration:", 1)[1]
    assert job.count(DEPLOYED_PIN) >= 2  # checkout ref and the HEAD check
    assert "f766f51583c23acc33b2a7824654ef2029a96804" in job
    assert "BUGFORGE_COMET_DEPLOYED_ROOT" in job
    assert "BUGFORGE_REQUIRE_COMET" in job
    assert "tests/test_compound_custody" in job
    assert "continue-on-error" not in job


def test_a_missing_deployed_checkout_fails_when_required(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("BUGFORGE_COMET_DEPLOYED_ROOT", str(tmp_path / "missing"))
    monkeypatch.setenv("BUGFORGE_REQUIRE_COMET", "1")
    with pytest.raises(pytest.fail.Exception, match="is not available"):
        deployed_root()
    monkeypatch.setenv("BUGFORGE_REQUIRE_COMET", "0")
    with pytest.raises(pytest.skip.Exception):
        deployed_root()
