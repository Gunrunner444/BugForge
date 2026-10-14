"""The pinned Compound checkout is required for the dedicated integration job."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.test_phase58.comet_support import comet_root

WORKFLOW = Path(__file__).resolve().parents[3] / ".github" / "workflows" / "backend.yml"
PIN = "f766f51583c23acc33b2a7824654ef2029a96804"


def test_the_dedicated_job_requires_the_pinned_checkout() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "compound-integration:" in text
    job = text.split("compound-integration:", 1)[1]
    assert PIN in job
    assert "compound-finance/comet" in job
    assert "BUGFORGE_REQUIRE_COMET" in job
    assert "BUGFORGE_COMET_ROOT" in job
    assert "FOUNDRY_OFFLINE" in job
    assert "FOUNDRY_FFI" in job
    assert "test_comet_pause_campaign.py" in job
    assert "test_comet_asset_campaign.py" in job
    assert "continue-on-error" not in job
    pytest_job = text.split("  test:", 1)[1].split("  typecheck:", 1)[0]
    assert "BUGFORGE_REQUIRE_COMET" not in pytest_job


def test_a_missing_checkout_fails_instead_of_skipping(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("BUGFORGE_COMET_ROOT", str(tmp_path / "missing"))
    monkeypatch.setenv("BUGFORGE_REQUIRE_COMET", "1")
    with pytest.raises(pytest.fail.Exception, match="is not available"):
        comet_root()
    monkeypatch.setenv("BUGFORGE_REQUIRE_COMET", "0")
    with pytest.raises(pytest.skip.Exception):
        comet_root()


def test_require_foundry_does_not_require_the_comet_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("BUGFORGE_COMET_ROOT", str(tmp_path / "missing"))
    monkeypatch.setenv("BUGFORGE_REQUIRE_FOUNDRY", "1")
    monkeypatch.delenv("BUGFORGE_REQUIRE_COMET", raising=False)
    with pytest.raises(pytest.skip.Exception):
        comet_root()
    assert os.environ["BUGFORGE_REQUIRE_FOUNDRY"] == "1"
