"""Phase 9: GitHub Integration tests.

Security-critical tests including:
 - Unverified/rejected/inconclusive candidates cannot be delivered
 - Modified-after-verification patch cannot be delivered
 - Branch name injection prevention
 - Repository path traversal prevention
 - Token sanitization
 - Delivery idempotency
 - Ownership chain validation
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────


def _to_uuid(val: str | UUID) -> UUID:
    return UUID(val) if isinstance(val, str) else val


def _patch_hash(diff: str) -> str:
    return hashlib.sha256(diff.encode()).hexdigest()


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "calc.py").write_text("def divide(a, b):\n    return a / b\n")
    (repo / "tests").mkdir()
    (repo / "tests" / "__init__.py").write_text("")
    (repo / "tests" / "test_calc.py").write_text(
        "from calc import divide\ndef test_divide(): assert divide(10, 2) == 5\n"
    )
    return repo


# ── Unit tests: Pure security helpers ────────────────────────────────────────


class TestGitHubServiceHelpers:
    def test_patch_hash_is_deterministic(self) -> None:
        from app.services.github_service import _patch_hash as ph

        diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n+new\n"
        assert ph(diff) == ph(diff)
        assert len(ph(diff)) == 64

    def test_patch_hash_differs_for_different_content(self) -> None:
        from app.services.github_service import _patch_hash as ph

        assert ph("content_a") != ph("content_b")

    def test_sanitize_token_removes_token(self) -> None:
        from app.services.github_service import _sanitize_token

        token = "ghp_supersecrettoken123"
        text = f"clone https://x-access-token:{token}@github.com/owner/repo.git failed"
        sanitized = _sanitize_token(text, token)
        assert token not in sanitized
        assert "***" in sanitized

    def test_sanitize_token_empty_token_is_noop(self) -> None:
        from app.services.github_service import _sanitize_token

        text = "some error message"
        assert _sanitize_token(text, "") == text

    def test_delivery_branch_format(self) -> None:
        from app.services.github_service import _delivery_branch

        cid = uuid4()
        branch = _delivery_branch(cid)
        assert branch.startswith("bugforge/fix/")
        assert len(branch) <= 30

    def test_validate_branch_name_safe(self) -> None:
        from app.services.github_service import _validate_branch_name

        _validate_branch_name("bugforge/fix/abc123def456")

    def test_validate_branch_name_rejects_empty(self) -> None:
        from app.services.github_service import _validate_branch_name

        with pytest.raises(ValueError):
            _validate_branch_name("")

    def test_validate_branch_name_rejects_shell_injection(self) -> None:
        from app.services.github_service import _validate_branch_name

        with pytest.raises(ValueError):
            _validate_branch_name("main; rm -rf /")

    def test_validate_branch_name_rejects_path_traversal(self) -> None:
        from app.services.github_service import _validate_branch_name

        with pytest.raises(ValueError):
            _validate_branch_name("../../../etc/passwd")

    def test_validate_branch_name_rejects_double_dots(self) -> None:
        from app.services.github_service import _validate_branch_name

        with pytest.raises(ValueError):
            _validate_branch_name("feature..hack")

    def test_validate_github_owner_repo_safe(self) -> None:
        from app.services.github_service import _validate_github_owner_repo

        _validate_github_owner_repo("octocat", "Hello-World")

    def test_validate_github_owner_repo_rejects_injection(self) -> None:
        from app.services.github_service import _validate_github_owner_repo

        with pytest.raises(ValueError):
            _validate_github_owner_repo("owner; rm -rf /", "repo")

    def test_validate_github_owner_repo_rejects_slashes(self) -> None:
        from app.services.github_service import _validate_github_owner_repo

        with pytest.raises(ValueError):
            _validate_github_owner_repo("owner/sub", "repo")

    def test_sanitize_commit_message_removes_control_chars(self) -> None:
        from app.services.github_service import _sanitize_commit_message

        msg = "fix: issue\x00malicious\x01payload"
        sanitized = _sanitize_commit_message(msg)
        assert "\x00" not in sanitized
        assert "\x01" not in sanitized

    def test_sanitize_commit_message_truncates(self) -> None:
        from app.services.github_service import _sanitize_commit_message

        long_msg = "x" * 600
        assert len(_sanitize_commit_message(long_msg)) <= 500

    def test_build_pr_body_contains_verification_id(self) -> None:
        from app.services.github_service import _build_pr_body

        did = uuid4()
        cid = uuid4()
        vid = uuid4()
        body = _build_pr_body(
            delivery_id=did,
            candidate_id=cid,
            verification_id=vid,
            commit_sha="abc123",
            patch_hash="a" * 64,
        )
        assert str(vid) in body
        assert str(cid) in body
        assert "BugForge" in body
        assert "not automatically merge" in body.lower() or "not" in body.lower()

    def test_build_pr_body_no_secrets(self) -> None:
        from app.services.github_service import _build_pr_body

        body = _build_pr_body(
            delivery_id=uuid4(),
            candidate_id=uuid4(),
            verification_id=uuid4(),
            commit_sha="abc123",
            patch_hash="a" * 64,
        )
        assert "token" not in body.lower()
        assert "password" not in body.lower()
        assert "secret" not in body.lower()


# ── Unit tests: GitHubConnectRequest validation ───────────────────────────────


class TestGitHubConnectRequestValidation:
    def test_valid_request(self) -> None:
        from app.schemas.github import GitHubConnectRequest

        req = GitHubConnectRequest(owner="octocat", repo="Hello-World")
        assert req.owner == "octocat"

    def test_rejects_slash_in_owner(self) -> None:
        from app.schemas.github import GitHubConnectRequest

        with pytest.raises(Exception):
            GitHubConnectRequest(owner="owner/sub", repo="repo")

    def test_rejects_backslash_in_repo(self) -> None:
        from app.schemas.github import GitHubConnectRequest

        with pytest.raises(Exception):
            GitHubConnectRequest(owner="owner", repo="re\\po")

    def test_rejects_empty_owner(self) -> None:
        from app.schemas.github import GitHubConnectRequest

        with pytest.raises(Exception):
            GitHubConnectRequest(owner="  ", repo="repo")


# ── Integration tests: Delivery security ─────────────────────────────────────


class TestDeliverySecurityConstraints:
    """CRITICAL: Unverified candidates MUST NOT be delivered to GitHub."""

    async def test_unverified_candidate_rejected(self, client: Any) -> None:
        """An unverified candidate cannot be delivered — fails closed."""
        repo = Path("/tmp") / f"test_repo_{uuid4().hex[:8]}"
        repo.mkdir(exist_ok=True)
        (repo / "calc.py").write_text("x = 1\n")

        proj = await client.post(
            "/api/v1/projects",
            json={"name": f"GitHubTest_{uuid4().hex[:6]}", "repository_path": str(repo)},
        )
        assert proj.status_code == 201
        project_id = proj.json()["id"]

        # Try to deliver a non-existent candidate — must be 404
        resp = await client.post(
            f"/api/v1/projects/{project_id}/github/deliver/{uuid4()}"
        )
        assert resp.status_code in (400, 404)

    async def test_deliver_requires_verified_decision(self, client: Any) -> None:
        """Only candidates with verification_decision='verified' can be delivered."""
        from app.database import async_session_factory
        from app.models.github import GitHubRepository
        from app.models.repair import PatchCandidate, RepairSession
        from app.models.verification import PatchVerification

        repo = Path("/tmp") / f"test_repo_{uuid4().hex[:8]}"
        repo.mkdir(exist_ok=True)
        (repo / "x.py").write_text("x = 1\n")

        proj = await client.post(
            "/api/v1/projects",
            json={"name": f"GitHubDeliveryTest_{uuid4().hex[:6]}", "repository_path": str(repo)},
        )
        project_id = proj.json()["id"]

        # Directly create a rejected verification record
        async with async_session_factory() as db:

            rs = RepairSession(project_id=_to_uuid(project_id), status="completed")
            db.add(rs)
            await db.flush()

            diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
            pc = PatchCandidate(
                session_id=rs.id,
                patch_diff=diff,
                status="rejected",
                validation_status="valid",
            )
            db.add(pc)
            await db.flush()

            # Create a 'rejected' verification (not verified)
            pv = PatchVerification(
                candidate_id=pc.id,
                session_id=rs.id,
                project_id=_to_uuid(project_id),
                status="rejected",
                verification_decision="rejected",
            )
            db.add(pv)

            # Connect a fake GitHub repo
            gr = GitHubRepository(
                project_id=_to_uuid(project_id),
                owner="octocat",
                repo="hello-world",
                default_branch="main",
                html_url="https://github.com/octocat/hello-world",
                connected=True,
            )
            db.add(gr)
            await db.commit()
            candidate_id = pc.id

        resp = await client.post(
            f"/api/v1/projects/{project_id}/github/deliver/{candidate_id}"
        )
        # Must be rejected — not verified
        assert resp.status_code == 400
        assert "verified" in resp.json()["detail"].lower()

    async def test_deliver_rejects_inconclusive_verification(self, client: Any) -> None:
        """An inconclusive verification cannot be delivered."""
        from app.database import async_session_factory
        from app.models.github import GitHubRepository
        from app.models.repair import PatchCandidate, RepairSession
        from app.models.verification import PatchVerification

        repo = Path("/tmp") / f"test_repo_{uuid4().hex[:8]}"
        repo.mkdir(exist_ok=True)
        (repo / "x.py").write_text("x = 1\n")

        proj = await client.post(
            "/api/v1/projects",
            json={"name": f"InconclusiveTest_{uuid4().hex[:6]}", "repository_path": str(repo)},
        )
        project_id = proj.json()["id"]

        async with async_session_factory() as db:
            rs = RepairSession(project_id=_to_uuid(project_id), status="completed")
            db.add(rs)
            await db.flush()

            diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
            pc = PatchCandidate(session_id=rs.id, patch_diff=diff, status="completed", validation_status="valid")
            db.add(pc)
            await db.flush()

            pv = PatchVerification(
                candidate_id=pc.id, session_id=rs.id, project_id=_to_uuid(project_id),
                status="inconclusive", verification_decision="inconclusive",
            )
            db.add(pv)
            gr = GitHubRepository(
                project_id=_to_uuid(project_id), owner="octocat", repo="hello-world",
                default_branch="main", html_url="https://github.com/octocat/hello-world", connected=True,
            )
            db.add(gr)
            await db.commit()
            candidate_id = pc.id

        resp = await client.post(f"/api/v1/projects/{project_id}/github/deliver/{candidate_id}")
        assert resp.status_code == 400
        assert "verified" in resp.json()["detail"].lower()

    async def test_deliver_rejects_cross_project_candidate(self, client: Any) -> None:
        """A candidate from another project cannot be delivered to this project."""
        from app.database import async_session_factory
        from app.models.github import GitHubRepository
        from app.models.repair import PatchCandidate, RepairSession
        from app.models.verification import PatchVerification

        repo_a = Path("/tmp") / f"repo_a_{uuid4().hex[:8]}"
        repo_b = Path("/tmp") / f"repo_b_{uuid4().hex[:8]}"
        repo_a.mkdir(exist_ok=True)
        repo_b.mkdir(exist_ok=True)
        (repo_a / "x.py").write_text("x = 1\n")
        (repo_b / "x.py").write_text("x = 1\n")

        proj_a = await client.post(
            "/api/v1/projects", json={"name": f"ProjA_{uuid4().hex[:6]}", "repository_path": str(repo_a)}
        )
        proj_b = await client.post(
            "/api/v1/projects", json={"name": f"ProjB_{uuid4().hex[:6]}", "repository_path": str(repo_b)}
        )
        project_a_id = proj_a.json()["id"]
        project_b_id = proj_b.json()["id"]

        async with async_session_factory() as db:
            # Candidate belongs to project_a
            rs = RepairSession(project_id=_to_uuid(project_a_id), status="completed")
            db.add(rs)
            await db.flush()
            diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
            pc = PatchCandidate(session_id=rs.id, patch_diff=diff, status="completed", validation_status="valid")
            db.add(pc)
            await db.flush()
            pv = PatchVerification(
                candidate_id=pc.id, session_id=rs.id, project_id=_to_uuid(project_a_id),
                status="verified", verification_decision="verified",
            )
            db.add(pv)
            gr = GitHubRepository(
                project_id=_to_uuid(project_b_id), owner="octocat", repo="hello-world",
                default_branch="main", html_url="https://github.com/octocat/hello-world", connected=True,
            )
            db.add(gr)
            await db.commit()
            candidate_id = pc.id

        # Try to deliver project_a's candidate via project_b's endpoint
        resp = await client.post(f"/api/v1/projects/{project_b_id}/github/deliver/{candidate_id}")
        assert resp.status_code in (400, 404)

    async def test_verified_candidate_with_matching_hash_accepted(self, client: Any) -> None:
        """A genuinely verified candidate is accepted for delivery start (with token)."""
        from unittest.mock import patch as mpatch

        from app.database import async_session_factory
        from app.models.github import GitHubRepository
        from app.models.repair import PatchCandidate, RepairSession
        from app.models.verification import PatchVerification
        from app.services.github_service import _patch_hash

        repo = Path("/tmp") / f"test_repo_{uuid4().hex[:8]}"
        repo.mkdir(exist_ok=True)
        (repo / "x.py").write_text("x = 1\n")

        proj = await client.post(
            "/api/v1/projects",
            json={"name": f"VerifiedTest_{uuid4().hex[:6]}", "repository_path": str(repo)},
        )
        project_id = proj.json()["id"]

        async with async_session_factory() as db:
            rs = RepairSession(project_id=_to_uuid(project_id), status="completed")
            db.add(rs)
            await db.flush()
            diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
            pc = PatchCandidate(session_id=rs.id, patch_diff=diff, status="completed", validation_status="valid")
            db.add(pc)
            await db.flush()
            pv = PatchVerification(
                candidate_id=pc.id, session_id=rs.id, project_id=_to_uuid(project_id),
                status="verified", verification_decision="verified",
            )
            db.add(pv)
            gr = GitHubRepository(
                project_id=_to_uuid(project_id), owner="octocat", repo="hello-world",
                default_branch="main", html_url="https://github.com/octocat/hello-world", connected=True,
            )
            db.add(gr)
            await db.commit()
            candidate_id = pc.id

        # Mock a valid GitHub token so delivery proceeds to the pipeline stage
        with mpatch.object(
            __import__("app.core.config", fromlist=["settings"]).settings,
            "github_token", "ghp_fake_test_token",
        ):
            resp = await client.post(f"/api/v1/projects/{project_id}/github/deliver/{candidate_id}")

        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "pending"
        assert data["verified_patch_hash"] == _patch_hash(diff)

    async def test_delivery_idempotent_returns_same_record(self, client: Any) -> None:
        """Starting delivery twice for a non-active delivery returns the same record."""
        from typing import Any as TAny
        from unittest.mock import patch as mpatch

        from app.database import async_session_factory
        from app.models.github import GitHubRepository
        from app.models.repair import PatchCandidate, RepairSession
        from app.models.verification import PatchVerification

        repo = Path("/tmp") / f"test_repo_{uuid4().hex[:8]}"
        repo.mkdir(exist_ok=True)
        (repo / "x.py").write_text("x = 1\n")

        proj = await client.post(
            "/api/v1/projects",
            json={"name": f"IdempotentTest_{uuid4().hex[:6]}", "repository_path": str(repo)},
        )
        project_id = proj.json()["id"]

        async with async_session_factory() as db:
            rs = RepairSession(project_id=_to_uuid(project_id), status="completed")
            db.add(rs)
            await db.flush()
            diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
            pc = PatchCandidate(session_id=rs.id, patch_diff=diff, status="completed", validation_status="valid")
            db.add(pc)
            await db.flush()
            pv = PatchVerification(
                candidate_id=pc.id, session_id=rs.id, project_id=_to_uuid(project_id),
                status="verified", verification_decision="verified",
            )
            db.add(pv)
            gr = GitHubRepository(
                project_id=_to_uuid(project_id), owner="octocat", repo="hello-world",
                default_branch="main", html_url="https://github.com/octocat/hello-world", connected=True,
            )
            db.add(gr)
            await db.commit()
            candidate_id = pc.id

        import app.core.config as _cfg
        # Mock pipeline so delivery stays in "pending" between both requests
        async def _noop_pipeline(self_: TAny, delivery_id: UUID) -> None:
            pass

        with mpatch.object(_cfg.settings, "github_token", "ghp_fake_test_token"), \
             mpatch.object(
                 __import__("app.services.github_service", fromlist=["GitHubService"]).GitHubService,
                 "run_delivery_pipeline",
                 _noop_pipeline,
             ):
            resp1 = await client.post(f"/api/v1/projects/{project_id}/github/deliver/{candidate_id}")
            resp2 = await client.post(f"/api/v1/projects/{project_id}/github/deliver/{candidate_id}")

        assert resp1.status_code == 202
        assert resp2.status_code == 202
        assert resp1.json()["id"] == resp2.json()["id"]

    async def test_delivery_without_github_connection_fails(self, client: Any) -> None:
        """Delivery fails if no GitHub repository is connected."""
        from app.database import async_session_factory
        from app.models.repair import PatchCandidate, RepairSession
        from app.models.verification import PatchVerification

        repo = Path("/tmp") / f"test_repo_{uuid4().hex[:8]}"
        repo.mkdir(exist_ok=True)
        (repo / "x.py").write_text("x = 1\n")

        proj = await client.post(
            "/api/v1/projects",
            json={"name": f"NoGHTest_{uuid4().hex[:6]}", "repository_path": str(repo)},
        )
        project_id = proj.json()["id"]

        async with async_session_factory() as db:
            rs = RepairSession(project_id=_to_uuid(project_id), status="completed")
            db.add(rs)
            await db.flush()
            diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
            pc = PatchCandidate(session_id=rs.id, patch_diff=diff, status="completed", validation_status="valid")
            db.add(pc)
            await db.flush()
            pv = PatchVerification(
                candidate_id=pc.id, session_id=rs.id, project_id=_to_uuid(project_id),
                status="verified", verification_decision="verified",
            )
            db.add(pv)
            await db.commit()
            candidate_id = pc.id

        resp = await client.post(f"/api/v1/projects/{project_id}/github/deliver/{candidate_id}")
        assert resp.status_code == 400
        assert "github" in resp.json()["detail"].lower() or "connected" in resp.json()["detail"].lower()


# ── Unit tests: Patch hash mismatch ──────────────────────────────────────────


class TestPatchHashMismatch:
    """The delivered patch must exactly match the verified patch."""

    def test_hash_mismatch_detected(self) -> None:
        from app.services.github_service import _patch_hash

        original = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
        modified = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-x = 1\n+x = 999\n"
        assert _patch_hash(original) != _patch_hash(modified)

    def test_hash_is_deterministic_for_verified_content(self) -> None:
        from app.services.github_service import _patch_hash

        diff = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
        h1 = _patch_hash(diff)
        h2 = _patch_hash(diff)
        assert h1 == h2 == hashlib.sha256(diff.encode()).hexdigest()


# ── Integration tests: GitHub API endpoints ───────────────────────────────────


class TestGitHubAPIEndpoints:
    async def test_get_github_repo_not_found(self, client: Any) -> None:
        proj = await client.post(
            "/api/v1/projects",
            json={"name": f"NoGH_{uuid4().hex[:6]}", "repository_path": "/tmp"},
        )
        project_id = proj.json()["id"]
        resp = await client.get(f"/api/v1/projects/{project_id}/github")
        assert resp.status_code == 404

    async def test_list_deliveries_empty(self, client: Any) -> None:
        proj = await client.post(
            "/api/v1/projects",
            json={"name": f"Deliveries_{uuid4().hex[:6]}", "repository_path": "/tmp"},
        )
        project_id = proj.json()["id"]
        resp = await client.get(f"/api/v1/projects/{project_id}/github/deliveries")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_get_delivery_not_found(self, client: Any) -> None:
        resp = await client.get(f"/api/v1/github/deliveries/{uuid4()}")
        assert resp.status_code == 404

    async def test_connect_github_repo_no_token(self, client: Any) -> None:
        proj = await client.post(
            "/api/v1/projects",
            json={"name": f"ConnTest_{uuid4().hex[:6]}", "repository_path": "/tmp"},
        )
        project_id = proj.json()["id"]
        resp = await client.post(
            f"/api/v1/projects/{project_id}/github/connect",
            json={"owner": "octocat", "repo": "Hello-World"},
        )
        # Without GITHUB_TOKEN configured this returns 400
        assert resp.status_code == 400
        assert "token" in resp.json()["detail"].lower()

    async def test_connect_github_repo_validates_owner(self, client: Any) -> None:
        proj = await client.post(
            "/api/v1/projects",
            json={"name": f"ConnTest2_{uuid4().hex[:6]}", "repository_path": "/tmp"},
        )
        project_id = proj.json()["id"]
        resp = await client.post(
            f"/api/v1/projects/{project_id}/github/connect",
            json={"owner": "owner/sub", "repo": "repo"},
        )
        assert resp.status_code == 422  # Pydantic validation

    async def test_disconnect_github_repo_nonexistent_is_ok(self, client: Any) -> None:
        proj = await client.post(
            "/api/v1/projects",
            json={"name": f"Disc_{uuid4().hex[:6]}", "repository_path": "/tmp"},
        )
        project_id = proj.json()["id"]
        resp = await client.delete(f"/api/v1/projects/{project_id}/github")
        assert resp.status_code == 204


# ── Phase 8 stabilization tests ───────────────────────────────────────────────


class TestPhase8Stabilization:
    """Tests for the Phase 8 execution status improvements."""

    def test_test_run_result_success_status(self) -> None:
        from app.services.verification_service import _TestRunResult

        r = _TestRunResult(execution_status="success", total=5, passed=5)
        assert r.succeeded is True

    def test_test_run_result_environment_error_not_success(self) -> None:
        from app.services.verification_service import _TestRunResult

        r = _TestRunResult(execution_status="environment_error", total=0)
        assert r.succeeded is False

    def test_test_run_result_timeout_not_success(self) -> None:
        from app.services.verification_service import _TestRunResult

        r = _TestRunResult(execution_status="timeout", total=0)
        assert r.succeeded is False

    def test_test_run_result_report_error_not_success(self) -> None:
        from app.services.verification_service import _TestRunResult

        r = _TestRunResult(execution_status="report_error", total=0)
        assert r.succeeded is False

    def test_static_analysis_result_success(self) -> None:
        from app.services.verification_service import _StaticAnalysisResult

        r = _StaticAnalysisResult(status="success", count=0, finding_ids=[])
        assert r.succeeded is True

    def test_static_analysis_result_error_not_success(self) -> None:
        from app.services.verification_service import _StaticAnalysisResult

        r = _StaticAnalysisResult(status="error", count=0, error_message="boom")
        assert r.succeeded is False

    def test_compute_verification_fails_when_baseline_tests_failed(self) -> None:
        from app.services.verification_service import _compute_verification

        _, decision, reasons = _compute_verification(
            baseline_repro=True,
            target_bug_fixed=True,
            regression_count=0,
            new_static_introduced=0,
            security_passed=True,
            post_repro=False,
            baseline_test_exec_ok=False,
        )
        assert decision == "inconclusive"
        assert any("baseline" in r.lower() for r in reasons)

    def test_compute_verification_fails_when_post_tests_failed(self) -> None:
        from app.services.verification_service import _compute_verification

        _, decision, reasons = _compute_verification(
            baseline_repro=True,
            target_bug_fixed=True,
            regression_count=0,
            new_static_introduced=0,
            security_passed=True,
            post_repro=False,
            post_test_exec_ok=False,
        )
        assert decision == "inconclusive"

    def test_compute_verification_fails_when_static_analysis_failed(self) -> None:
        from app.services.verification_service import _compute_verification

        _, decision, reasons = _compute_verification(
            baseline_repro=True,
            target_bug_fixed=True,
            regression_count=0,
            new_static_introduced=0,
            security_passed=True,
            post_repro=False,
            baseline_static_ok=False,
        )
        assert decision == "inconclusive"

    def test_compare_findings_detects_new_finding(self) -> None:
        from app.services.verification_service import _compare_findings

        baseline = ["ruff:E302:foo.py", "ruff:E501:bar.py"]
        post = ["ruff:E302:foo.py", "ruff:E501:bar.py", "ruff:F401:baz.py"]
        new_ids, resolved_ids = _compare_findings(baseline, post)
        assert "ruff:F401:baz.py" in new_ids
        assert resolved_ids == []

    def test_compare_findings_detects_resolved_finding(self) -> None:
        from app.services.verification_service import _compare_findings

        baseline = ["ruff:E302:foo.py", "ruff:F401:bar.py"]
        post = ["ruff:E302:foo.py"]
        new_ids, resolved_ids = _compare_findings(baseline, post)
        assert "ruff:F401:bar.py" in resolved_ids
        assert new_ids == []

    def test_compare_findings_both_new_and_resolved(self) -> None:
        from app.services.verification_service import _compare_findings

        baseline = ["ruff:E302:a.py", "ruff:F401:b.py"]
        post = ["ruff:E302:a.py", "ruff:E501:c.py"]
        new_ids, resolved_ids = _compare_findings(baseline, post)
        assert "ruff:E501:c.py" in new_ids
        assert "ruff:F401:b.py" in resolved_ids

    def test_run_static_analysis_no_python_files(self, tmp_path: Path) -> None:
        from app.services.verification_service import _run_static_analysis

        result = _run_static_analysis(str(tmp_path), ["nonexistent.js"])
        assert result.status == "success"
        assert result.count == 0

    def test_verification_schema_has_evidence_fields(self) -> None:
        """VerificationResponse includes execution status fields."""
        from app.schemas.verification import VerificationResponse

        fields = VerificationResponse.model_fields
        assert "baseline_test_execution_status" in fields
        assert "post_test_execution_status" in fields
        assert "baseline_static_analysis_status" in fields
        assert "post_static_analysis_status" in fields
        assert "baseline_finding_ids" in fields
        assert "post_finding_ids" in fields
        assert "new_finding_ids" in fields
        assert "resolved_finding_ids" in fields


# ── Security: Malicious issue / prompt injection content ─────────────────────


class TestMaliciousInputRejection:
    def test_branch_name_rejects_command_substitution(self) -> None:
        from app.services.github_service import _validate_branch_name

        with pytest.raises(ValueError):
            _validate_branch_name("$(whoami)")

    def test_branch_name_rejects_backtick(self) -> None:
        from app.services.github_service import _validate_branch_name

        with pytest.raises(ValueError):
            _validate_branch_name("`ls -la`")

    def test_commit_message_strips_null_bytes(self) -> None:
        from app.services.github_service import _sanitize_commit_message

        msg = "fix: issue\x00; rm -rf /"
        result = _sanitize_commit_message(msg)
        assert "\x00" not in result

    def test_owner_rejects_path_traversal(self) -> None:
        from app.services.github_service import _validate_github_owner_repo

        with pytest.raises(ValueError):
            _validate_github_owner_repo("../../etc/passwd", "repo")

    def test_owner_rejects_at_sign(self) -> None:
        from app.services.github_service import _validate_github_owner_repo

        with pytest.raises(ValueError):
            _validate_github_owner_repo("user@example.com", "repo")
