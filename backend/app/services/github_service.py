"""GitHub Integration service — Phase 9.

Security invariants enforced here:
 - Unverified/rejected/inconclusive candidates cannot be delivered.
 - The delivered patch MUST exactly match the verified patch (hash check).
 - GitHub tokens are NEVER logged, stored in DB, or sent to AI prompts.
 - Git commands always use argument arrays (never shell interpolation).
 - Branch names are sanitized to prevent injection.
 - Repository URLs are validated to be on github.com.
 - Default branch is NEVER modified directly.
 - PRs are never automatically merged.
"""
from __future__ import annotations

import hashlib
import logging
import re
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx

logger = logging.getLogger(__name__)

# Maximum allowed branch name length
_MAX_BRANCH_LEN = 100
# Pattern for valid branch name characters (after prefix)
_BRANCH_SAFE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-_./]*$")
# Control characters to strip from commit messages
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

_GITHUB_API = "https://api.github.com"
_GITHUB_HOST = "github.com"


# ── Security helpers ──────────────────────────────────────────────────────────


def _patch_hash(patch_diff: str) -> str:
    """Stable SHA-256 of the patch content."""
    return hashlib.sha256(patch_diff.encode()).hexdigest()


def _sanitize_token(text: str, token: str) -> str:
    """Remove the GitHub token from any string before logging/storing."""
    if token:
        text = text.replace(token, "***")
    return text


def _delivery_branch(candidate_id: UUID) -> str:
    """Deterministic collision-resistant branch name for a candidate."""
    short_id = str(candidate_id).replace("-", "")[:12]
    branch = f"bugforge/fix/{short_id}"
    return branch


def _validate_branch_name(branch: str) -> None:
    """Raise ValueError if the branch name is unsafe."""
    if not branch or len(branch) > _MAX_BRANCH_LEN:
        raise ValueError(f"Branch name is empty or too long: {branch!r}")
    # Allow bugforge/ prefix with alphanumeric + safe chars
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-_/]*$", branch):
        raise ValueError(f"Branch name contains unsafe characters: {branch!r}")
    # No consecutive dots, no trailing dot, no @{ sequences
    if ".." in branch or branch.endswith(".") or "@{" in branch:
        raise ValueError(f"Branch name has invalid git sequences: {branch!r}")


def _validate_github_url(url: str) -> None:
    """Raise ValueError if the URL is not a valid github.com HTTPS URL."""
    if not url.startswith("https://"):
        raise ValueError("Repository URL must use HTTPS")
    # strip credentials if present
    stripped = re.sub(r"https://[^@]+@", "https://", url)
    if _GITHUB_HOST not in stripped:
        raise ValueError(f"URL does not appear to be a github.com URL: {url!r}")


def _sanitize_commit_message(msg: str) -> str:
    """Remove control characters; truncate to safe length."""
    msg = _CONTROL_CHARS.sub(" ", msg)
    return msg[:500].strip()


def _remote_url(owner: str, repo: str, token: str) -> str:
    """Build authenticated HTTPS remote URL.  Never log this value."""
    return f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"


def _git(args: list[str], cwd: str | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run a git command with argument array (never shell=True)."""
    return subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _require_git() -> None:
    if shutil.which("git") is None:
        raise RuntimeError("git is not installed or not on PATH")


# ── GitHub API client ─────────────────────────────────────────────────────────


class _GitHubClient:
    """Minimal httpx-based GitHub REST API client."""

    def __init__(self, token: str) -> None:
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{_GITHUB_API}/repos/{owner}/{repo}",
                headers=self._headers,
            )
        if resp.status_code == 404:
            raise ValueError(f"Repository {owner}/{repo} not found or not accessible")
        if resp.status_code == 401:
            raise ValueError("GitHub token is invalid or expired")
        resp.raise_for_status()
        return dict(resp.json())

    async def list_prs(
        self, owner: str, repo: str, head: str, state: str = "open"
    ) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{_GITHUB_API}/repos/{owner}/{repo}/pulls",
                headers=self._headers,
                params={"head": f"{owner}:{head}", "state": state},
            )
        resp.raise_for_status()
        return list(resp.json())

    async def create_pr(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{_GITHUB_API}/repos/{owner}/{repo}/pulls",
                headers=self._headers,
                json={"title": title, "body": body, "head": head, "base": base},
            )
        if resp.status_code == 422:
            detail = resp.json().get("message", "Unprocessable entity")
            raise ValueError(f"GitHub PR creation failed: {detail}")
        resp.raise_for_status()
        return dict(resp.json())


# ── Service ───────────────────────────────────────────────────────────────────


class GitHubService:
    """Handles GitHub repository connection and verified patch delivery."""

    async def connect_repository(
        self,
        project_id: UUID,
        owner: str,
        repo: str,
    ) -> UUID:
        """Verify GitHub access and create/update the GitHubRepository record."""
        from app.core.config import settings
        from app.database import async_session_factory
        from app.repositories.github_repo import GitHubRepositoryRepo
        from app.repositories.project_repo import ProjectRepository

        if not settings.github_token:
            raise ValueError("GitHub token is not configured (set GITHUB_TOKEN environment variable)")

        # Validate owner/repo names to prevent injection
        _validate_github_owner_repo(owner, repo)

        client = _GitHubClient(settings.github_token)
        try:
            repo_data = await client.get_repo(owner, repo)
        except httpx.HTTPStatusError as exc:
            raise ValueError(f"GitHub API error: {exc.response.status_code}") from exc

        html_url = repo_data.get("html_url", f"https://github.com/{owner}/{repo}")
        default_branch = repo_data.get("default_branch", "main")
        github_id = repo_data.get("id")

        async with async_session_factory() as db:
            project_repo = ProjectRepository(db)
            project = await project_repo.get_by_id(project_id)
            if project is None:
                raise ValueError(f"Project {project_id} not found")

            github_repo_repo = GitHubRepositoryRepo(db)
            existing = await github_repo_repo.get_by_project(project_id)
            if existing is not None:
                await github_repo_repo.update(
                    existing.id,
                    owner=owner,
                    repo=repo,
                    github_id=github_id,
                    default_branch=default_branch,
                    html_url=html_url,
                    connected=True,
                )
                await db.commit()
                return existing.id

            gr = await github_repo_repo.create(
                project_id=project_id,
                owner=owner,
                repo=repo,
                default_branch=default_branch,
                html_url=html_url,
                github_id=github_id,
            )
            await github_repo_repo.update(gr.id, connected=True)
            await db.commit()
            return gr.id

    async def disconnect_repository(self, project_id: UUID) -> None:
        """Remove the GitHub connection for a project."""
        from app.database import async_session_factory
        from app.repositories.github_repo import GitHubRepositoryRepo

        async with async_session_factory() as db:
            github_repo_repo = GitHubRepositoryRepo(db)
            existing = await github_repo_repo.get_by_project(project_id)
            if existing is not None:
                await github_repo_repo.delete(existing.id)
                await db.commit()

    async def start_delivery(
        self,
        project_id: UUID,
        candidate_id: UUID,
    ) -> UUID:
        """Create a delivery record and enqueue the delivery pipeline.

        SECURITY: Only VERIFIED candidates from the specified project are accepted.
        Ownership chain validated before token or infra checks.
        """
        from app.database import async_session_factory
        from app.repositories.github_repo import GitHubDeliveryRepo, GitHubRepositoryRepo
        from app.repositories.repair_repo import RepairRepository
        from app.repositories.verification_repo import VerificationRepository

        async with async_session_factory() as db:
            # ── Ownership chain validation (security-first) ───────────
            repair_repo = RepairRepository(db)
            candidate = await repair_repo.get_candidate(candidate_id)
            if candidate is None:
                raise ValueError(f"Candidate {candidate_id} not found")

            repair_session = await repair_repo.get_session_by_id(candidate.session_id)
            if repair_session is None or repair_session.project_id != project_id:
                raise ValueError(
                    f"Candidate {candidate_id} does not belong to project {project_id}"
                )

            # ── Must be verified — fail closed ────────────────────────
            ver_repo = VerificationRepository(db)
            verification = await ver_repo.get_by_candidate(candidate_id)
            if verification is None:
                raise ValueError(
                    f"Candidate {candidate_id} has no verification record — run verification first"
                )
            if verification.project_id != project_id:
                raise ValueError("Verification does not belong to the specified project")
            if verification.verification_decision != "verified":
                raise ValueError(
                    f"Candidate {candidate_id} cannot be delivered: "
                    f"verification_decision={verification.verification_decision!r}. "
                    "Only 'verified' candidates may be delivered to GitHub."
                )

            # ── GitHub repository must be connected ───────────────────
            github_repo_repo = GitHubRepositoryRepo(db)
            github_repo = await github_repo_repo.get_by_project(project_id)
            if github_repo is None or not github_repo.connected:
                raise ValueError(
                    f"Project {project_id} has no connected GitHub repository — use /github/connect first"
                )

            # ── Infra check: token must be present ────────────────────
            from app.core.config import settings

            if not settings.github_token:
                raise ValueError(
                    "GitHub token is not configured (set GITHUB_TOKEN environment variable)"
                )

            # ── Patch hash for later comparison ───────────────────────
            patch_diff = candidate.patch_diff or ""
            current_hash = _patch_hash(patch_diff)

            # ── Idempotency — prevent duplicate active/pending deliveries ─
            delivery_repo = GitHubDeliveryRepo(db)
            existing_delivery = await delivery_repo.get_by_candidate(candidate_id)
            if existing_delivery is not None and existing_delivery.status not in (
                "failed", "aborted",
            ):
                return existing_delivery.id

            delivery_branch = _delivery_branch(candidate_id)
            _validate_branch_name(delivery_branch)

            delivery = await delivery_repo.create(
                project_id=project_id,
                github_repository_id=github_repo.id,
                candidate_id=candidate_id,
                verification_id=verification.id,
                owner=github_repo.owner,
                repo=github_repo.repo,
                base_branch=github_repo.default_branch,
                delivery_branch=delivery_branch,
                verified_patch_hash=current_hash,
            )
            delivery_id = delivery.id
            await db.commit()

        return delivery_id

    async def run_delivery_pipeline(self, delivery_id: UUID) -> None:
        """Execute the full delivery pipeline: clone → patch → verify → commit → push → PR."""
        from app.core.config import settings
        from app.database import async_session_factory
        from app.repositories.github_repo import GitHubDeliveryRepo
        from app.repositories.repair_repo import RepairRepository
        from app.repositories.verification_repo import VerificationRepository

        token = settings.github_token
        if not token:
            raise RuntimeError("GitHub token not configured")

        _require_git()

        async with async_session_factory() as db:
            delivery_repo = GitHubDeliveryRepo(db)
            delivery = await delivery_repo.get_by_id(delivery_id)
            if delivery is None:
                raise ValueError(f"Delivery {delivery_id} not found")
            await delivery_repo.update(delivery_id, status="preparing", started_at=datetime.now(UTC))
            await db.commit()

        tmpdir: str | None = None
        try:
            async with async_session_factory() as db:
                delivery_repo = GitHubDeliveryRepo(db)
                delivery = await delivery_repo.get_by_id(delivery_id)
                if delivery is None:
                    return

                # Re-validate ownership chain
                repair_repo = RepairRepository(db)
                candidate = await repair_repo.get_candidate(delivery.candidate_id)
                if candidate is None or candidate.session_id is None:
                    raise ValueError("Candidate not found during delivery")

                ver_repo = VerificationRepository(db)
                verification = await ver_repo.get_by_candidate(delivery.candidate_id)
                if verification is None or verification.verification_decision != "verified":
                    raise ValueError(
                        "Verification is no longer 'verified' — delivery aborted"
                    )

                patch_diff = candidate.patch_diff or ""

            # ── Hash verification — delivered == verified ─────────────
            current_hash = _patch_hash(patch_diff)
            async with async_session_factory() as db:
                delivery_repo = GitHubDeliveryRepo(db)
                delivery = await delivery_repo.get_by_id(delivery_id)
                if delivery is None:
                    return
                if delivery.verified_patch_hash != current_hash:
                    await delivery_repo.update(
                        delivery_id,
                        status="aborted",
                        error_message=(
                            "Patch content has changed since verification — "
                            "hash mismatch, delivery aborted"
                        ),
                        completed_at=datetime.now(UTC),
                    )
                    await db.commit()
                    return
                owner = delivery.owner
                repo = delivery.repo
                base_branch = delivery.base_branch
                delivery_branch = delivery.delivery_branch

            # ── Clone repository ──────────────────────────────────────
            tmpdir = tempfile.mkdtemp(prefix="bugforge_gh_")
            clone_dir = str(Path(tmpdir) / "repo")
            remote_url = _remote_url(owner, repo, token)

            result = _git(
                ["clone", "--depth", "1", "--branch", base_branch, remote_url, clone_dir]
            )
            if result.returncode != 0:
                sanitized_err = _sanitize_token(result.stderr, token)
                raise RuntimeError(f"git clone failed: {sanitized_err}")

            async with async_session_factory() as db:
                delivery_repo = GitHubDeliveryRepo(db)
                await delivery_repo.update(delivery_id, status="branch_created")
                await db.commit()

            # ── Create delivery branch ────────────────────────────────
            result = _git(["checkout", "-b", delivery_branch], cwd=clone_dir)
            if result.returncode != 0:
                sanitized_err = _sanitize_token(result.stderr, token)
                raise RuntimeError(f"git checkout failed: {sanitized_err}")

            # ── Apply verified patch ──────────────────────────────────
            from app.testing.repair_workspace import RepairWorkspace

            # Use RepairWorkspace's patch application logic on the clone directory
            ws_temp = RepairWorkspace.__new__(RepairWorkspace)
            object.__setattr__(ws_temp, "_workspace_dir", Path(tmpdir))
            object.__setattr__(ws_temp, "_repo_root", Path(clone_dir))
            ok, apply_err = ws_temp.apply_patch(patch_diff)
            if not ok:
                raise RuntimeError(f"Patch application failed: {apply_err}")

            # ── Final pre-push verification ───────────────────────────
            async with async_session_factory() as db:
                delivery_repo = GitHubDeliveryRepo(db)
                await delivery_repo.update(delivery_id, status="final_verification")
                await db.commit()

            final_ok = await _run_final_tests(clone_dir)
            if not final_ok:
                raise RuntimeError(
                    "Final pre-push test run failed — patch not delivered"
                )

            # ── Commit ────────────────────────────────────────────────
            async with async_session_factory() as db:
                delivery_repo = GitHubDeliveryRepo(db)
                await delivery_repo.update(delivery_id, status="committing")
                await db.commit()

            result = _git(["add", "--all"], cwd=clone_dir)
            if result.returncode != 0:
                raise RuntimeError(f"git add failed: {result.stderr}")

            commit_msg = _sanitize_commit_message(
                f"fix: BugForge automated repair (candidate {str(delivery.candidate_id)[:8]})\n\n"
                f"Verified by BugForge patch verification pipeline.\n"
                f"Delivery ID: {delivery_id}\n"
                f"Patch hash: {current_hash[:16]}..."
            )
            # Configure git identity for the commit (no real user needed)
            _git(["config", "user.email", "bugforge-bot@localhost"], cwd=clone_dir)
            _git(["config", "user.name", "BugForge Bot"], cwd=clone_dir)

            result = _git(["commit", "-m", commit_msg], cwd=clone_dir)
            if result.returncode != 0:
                raise RuntimeError(f"git commit failed: {result.stderr}")

            # Extract commit SHA
            sha_result = _git(["rev-parse", "HEAD"], cwd=clone_dir)
            commit_sha = sha_result.stdout.strip() if sha_result.returncode == 0 else None

            # ── Push ──────────────────────────────────────────────────
            async with async_session_factory() as db:
                delivery_repo = GitHubDeliveryRepo(db)
                await delivery_repo.update(
                    delivery_id,
                    status="pushing",
                    commit_sha=commit_sha,
                    delivered_patch_hash=current_hash,
                )
                await db.commit()

            result = _git(["push", "origin", delivery_branch], cwd=clone_dir)
            if result.returncode != 0:
                sanitized_err = _sanitize_token(result.stderr, token)
                raise RuntimeError(f"git push failed: {sanitized_err}")

            # ── Create PR via GitHub API ───────────────────────────────
            async with async_session_factory() as db:
                delivery_repo = GitHubDeliveryRepo(db)
                await delivery_repo.update(delivery_id, status="pr_created")
                await db.commit()

            client = _GitHubClient(token)

            # Check for existing PR to prevent duplicates
            existing_prs = await client.list_prs(owner, repo, head=delivery_branch)
            if existing_prs:
                pr = existing_prs[0]
                pr_number = pr["number"]
                pr_url = pr["html_url"]
            else:
                pr_title = _sanitize_commit_message(
                    f"BugForge: automated fix (candidate {str(delivery_id)[:8]})"
                )
                pr_body = _build_pr_body(
                    delivery_id=delivery_id,
                    candidate_id=delivery.candidate_id,
                    verification_id=delivery.verification_id,
                    commit_sha=commit_sha,
                    patch_hash=current_hash,
                )
                pr_data = await client.create_pr(
                    owner=owner,
                    repo=repo,
                    title=pr_title,
                    body=pr_body,
                    head=delivery_branch,
                    base=base_branch,
                )
                pr_number = pr_data["number"]
                pr_url = pr_data["html_url"]

            async with async_session_factory() as db:
                delivery_repo = GitHubDeliveryRepo(db)
                await delivery_repo.update(
                    delivery_id,
                    pull_request_number=pr_number,
                    pull_request_url=pr_url,
                    status="completed",
                    completed_at=datetime.now(UTC),
                )
                await db.commit()

        except Exception as exc:
            sanitized_msg = _sanitize_token(str(exc), token)
            logger.exception("Delivery %s failed: %s", delivery_id, sanitized_msg)
            async with async_session_factory() as db:
                delivery_repo = GitHubDeliveryRepo(db)
                await delivery_repo.update(
                    delivery_id,
                    status="failed",
                    error_message=sanitized_msg[:2048],
                    completed_at=datetime.now(UTC),
                )
                await db.commit()
        finally:
            if tmpdir is not None:
                try:
                    import shutil as _shutil
                    _shutil.rmtree(tmpdir, ignore_errors=True)
                except Exception:
                    pass


# ── Pure helpers ──────────────────────────────────────────────────────────────


def _validate_github_owner_repo(owner: str, repo: str) -> None:
    """Reject obviously unsafe owner/repo values."""
    pattern = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-_.]*$")
    if not pattern.match(owner):
        raise ValueError(f"Invalid GitHub owner name: {owner!r}")
    if not pattern.match(repo):
        raise ValueError(f"Invalid GitHub repo name: {repo!r}")
    if len(owner) > 255 or len(repo) > 255:
        raise ValueError("GitHub owner/repo names are too long")


async def _run_final_tests(repo_dir: str) -> bool:
    """Run the test suite against the patched clone; returns True if tests pass."""
    import subprocess as _sp

    result = _sp.run(
        ["python3", "-m", "pytest", "--tb=no", "-q", "--no-header"],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return result.returncode == 0


def _build_pr_body(
    *,
    delivery_id: UUID,
    candidate_id: UUID,
    verification_id: UUID,
    commit_sha: str | None,
    patch_hash: str,
) -> str:
    """Build an evidence-based PR body.  Never includes secrets."""
    lines = [
        "## BugForge Automated Repair",
        "",
        "This pull request was created by **BugForge** after the patch candidate was ",
        "independently verified by the BugForge patch verification pipeline.",
        "",
        "### Verification Evidence",
        f"- Verification ID: `{verification_id}`",
        f"- Candidate ID: `{candidate_id}`",
        f"- Delivery ID: `{delivery_id}`",
        f"- Patch SHA-256 (first 16): `{patch_hash[:16]}...`",
    ]
    if commit_sha:
        lines.append(f"- Commit: `{commit_sha}`")
    lines += [
        "",
        "### What was verified",
        "- Target bug reproduced in baseline ✓",
        "- Patch applied to isolated workspace ✓",
        "- Target bug no longer reproduces post-patch ✓",
        "- No previously-passing tests newly fail ✓",
        "- Security checks passed ✓",
        "- Static analysis comparison completed ✓",
        "",
        "### Important notes",
        "- This patch was **verified** by BugForge — it is not an unreviewed AI suggestion.",
        "- BugForge does **not** automatically merge pull requests.",
        "- Please review the changes before merging.",
        "- BugForge does not guarantee correctness beyond the verified evidence above.",
    ]
    return "\n".join(lines)
