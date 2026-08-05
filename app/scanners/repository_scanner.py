"""
Purpose: Synchronize GitHub repositories into local checkouts that other scanners can inspect.
Input/Output: Uses the GitHub API plus local `git` commands and returns repository metadata.
Important invariants: Clone paths are stable, but cached checkouts are disposable scanner state. If
the local branch diverges from GitHub, the scanner must recover by resetting it to the remote default
branch instead of silently dropping that repository from a full scan.
Debugging: If a repository does not update, inspect the logged git command and local checkout path.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.utils import run_command, safe_slug
from app.repositories.store import get_repository_by_full_name, upsert_repository
from app.services.github_client import GitHubClient

LOGGER = logging.getLogger(__name__)


class RepositoryScanner:
    """GitHub repository inventory and local sync logic."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.github_client = GitHubClient()

    def sync_repositories(
        self,
        session: Session,
        *,
        repository_full_name: str | None = None,
        include_archived: bool = False,
        target_commit_sha: str | None = None,
    ) -> list:
        """Fetch repository metadata from GitHub and clone or pull locally."""

        synced = []
        try:
            repositories = self.github_client.list_repositories()
        except Exception as error:
            LOGGER.warning("GitHub repository inventory failed", extra={"error": str(error)})
            return synced

        for repository_data in repositories:
            if not self._should_sync_repository(
                repository_data,
                repository_full_name=repository_full_name,
                include_archived=include_archived,
            ):
                continue
            existing_repository = get_repository_by_full_name(session, repository_data["full_name"])
            if existing_repository is not None and not existing_repository.scan_enabled:
                LOGGER.debug(
                    "Skipping disabled GitHub repository",
                    extra={"repository": repository_data["full_name"]},
                )
                continue

            try:
                local_path = self._local_checkout_path(repository_data["full_name"])
                repository = upsert_repository(
                    session,
                    source_type="github",
                    owner=repository_data["owner"]["login"],
                    name=repository_data["name"],
                    full_name=repository_data["full_name"],
                    clone_url=repository_data["clone_url"],
                    default_branch=repository_data["default_branch"],
                    local_path=str(local_path),
                    github_id=repository_data["id"],
                    archived=repository_data.get("archived", False),
                    metadata=repository_data,
                )
                self._sync_local_checkout(
                    repository.clone_url or "",
                    local_path,
                    repository.default_branch,
                    fetch_full_history=self._should_fetch_full_history(repository_data),
                    target_commit_sha=(
                        target_commit_sha
                        if repository_full_name is None or repository_data.get("full_name") == repository_full_name
                        else None
                    ),
                )
                synced.append(repository)
            except Exception as error:
                LOGGER.warning(
                    "Repository sync failed",
                    extra={
                        "repository": repository_data.get("full_name", "unknown"),
                        "default_branch": repository_data.get("default_branch", ""),
                        "error": str(error),
                    },
                )
        return synced

    def _local_checkout_path(self, full_name: str) -> Path:
        """Map GitHub names to predictable local checkout paths."""

        owner, name = full_name.split("/", maxsplit=1)
        return self.settings.repo_storage_path / safe_slug(owner) / safe_slug(name)

    def get_checkout_commit_sha(self, local_path: Path) -> str:
        """Return the exact full commit SHA currently checked out for scan provenance."""

        if not local_path.is_dir() or not (local_path / ".git").exists():
            raise RuntimeError(
                "Repository checkout is unavailable or is not a Git worktree. "
                f"path={local_path!s}. Re-run repository synchronization."
            )
        commit_sha = run_command(
            [
                self.settings.git_binary,
                "-C",
                str(local_path),
                "rev-parse",
                "--verify",
                "HEAD^{commit}",
            ],
            timeout=120,
        ).lower()
        if len(commit_sha) != 40 or any(character not in "0123456789abcdef" for character in commit_sha):
            raise RuntimeError(f"Git returned an invalid full commit SHA for scan provenance. path={local_path!s}.")
        return commit_sha

    def _sync_local_checkout(
        self,
        clone_url: str,
        local_path: Path,
        default_branch: str,
        *,
        fetch_full_history: bool,
        target_commit_sha: str | None = None,
    ) -> None:
        """Clone missing repositories or update existing ones with the required history depth."""

        local_path.parent.mkdir(parents=True, exist_ok=True)
        authenticated_url = self._authenticated_clone_url(clone_url)
        if not local_path.exists():
            clone_command = [
                self.settings.git_binary,
                "clone",
                "--branch",
                default_branch,
                authenticated_url,
                str(local_path),
            ]
            if not fetch_full_history:
                clone_command[2:2] = ["--depth", "1"]
            run_command(clone_command, timeout=900)
            if target_commit_sha:
                self._align_checkout_to_target_commit(local_path, target_commit_sha)
            return

        self._refresh_origin_remote(local_path, authenticated_url)
        run_command([self.settings.git_binary, "-C", str(local_path), "checkout", default_branch], timeout=120)
        if fetch_full_history:
            try:
                self._refresh_full_history_checkout(local_path, default_branch)
            except RuntimeError as error:
                self._recover_diverged_checkout(
                    local_path,
                    default_branch,
                    fetch_full_history=True,
                    original_error=error,
                )
            if target_commit_sha:
                self._align_checkout_to_target_commit(local_path, target_commit_sha)
            return
        try:
            run_command([self.settings.git_binary, "-C", str(local_path), "pull", "--ff-only"], timeout=900)
        except RuntimeError as error:
            self._recover_diverged_checkout(
                local_path,
                default_branch,
                fetch_full_history=False,
                original_error=error,
            )
        if target_commit_sha:
            self._align_checkout_to_target_commit(local_path, target_commit_sha)

    def _align_checkout_to_target_commit(self, local_path: Path, target_commit_sha: str) -> None:
        """
        Move a repository cache to the exact commit requested by pre-deploy scans.

        Why this exists:
        Deployment-gate evidence is evaluated against a precise commit SHA.
        Checkout drift to the default branch after inventory sync can otherwise block deployment
        even when an exact target commit has been scanned and is in Git history.
        """

        target_commit_sha = target_commit_sha.lower()
        head_commit = run_command(
            [
                self.settings.git_binary,
                "-C",
                str(local_path),
                "rev-parse",
                "--verify",
                "HEAD^{commit}",
            ],
            timeout=120,
        ).lower()
        if head_commit == target_commit_sha:
            return

        target_available_locally = False
        try:
            resolved_target = run_command(
                [
                    self.settings.git_binary,
                    "-C",
                    str(local_path),
                    "rev-parse",
                    "--verify",
                    f"{target_commit_sha}^{{commit}}",
                ],
                timeout=120,
            ).lower()
            target_available_locally = resolved_target == target_commit_sha
        except RuntimeError:
            LOGGER.debug(
                "Target commit is not available locally; fetching explicit commit from origin.",
                extra={"target": target_commit_sha},
            )
        if not target_available_locally:
            try:
                run_command(
                    [
                        self.settings.git_binary,
                        "-C",
                        str(local_path),
                        "fetch",
                        "--depth=1",
                        "origin",
                        target_commit_sha,
                    ],
                    timeout=900,
                )
            except RuntimeError:
                LOGGER.warning(
                    "Target commit was not directly reachable; refreshing remote heads for exact checkout.",
                    extra={"local_path": str(local_path), "target_commit_sha": target_commit_sha},
                )
                run_command(
                    [
                        self.settings.git_binary,
                        "-C",
                        str(local_path),
                        "fetch",
                        "--depth=1",
                        "origin",
                        "+refs/heads/*:refs/remotes/origin/*",
                    ],
                    timeout=900,
                )

        run_command(
            [self.settings.git_binary, "-C", str(local_path), "checkout", "--detach", target_commit_sha],
            timeout=120,
        )
        detached_commit = run_command(
            [self.settings.git_binary, "-C", str(local_path), "rev-parse", "--verify", "HEAD^{commit}"],
            timeout=120,
        ).lower()
        if detached_commit != target_commit_sha:
            raise RuntimeError(
                "Target commit could not be checked out for pre-deploy scanning. "
                f"local_path={local_path} expected={target_commit_sha} actual={detached_commit}"
            )

    def _refresh_full_history_checkout(self, local_path: Path, default_branch: str) -> None:
        """Ensure public repositories are unshallowed before history-based secret scanning."""

        if (local_path / ".git" / "shallow").exists():
            run_command(
                [self.settings.git_binary, "-C", str(local_path), "fetch", "--unshallow", "--tags", "origin"],
                timeout=900,
            )
        else:
            run_command(
                [self.settings.git_binary, "-C", str(local_path), "fetch", "--tags", "--prune", "origin"],
                timeout=900,
            )
        run_command(
            [self.settings.git_binary, "-C", str(local_path), "pull", "--ff-only", "origin", default_branch],
            timeout=900,
        )

    def _recover_diverged_checkout(
        self,
        local_path: Path,
        default_branch: str,
        *,
        fetch_full_history: bool,
        original_error: RuntimeError,
    ) -> None:
        """
        Reset a disposable scanner checkout when fast-forward update cannot proceed.

        Why this exists:
        `data/repos/...` is not a developer worktree; it is a cache used to inspect the current
        GitHub state. A diverged branch would otherwise make a full scan silently skip an owned repo
        until someone manually deletes the cache. Resetting to `origin/<default_branch>` keeps the
        scan complete while preserving the stable cache path for debug inspection.
        """

        LOGGER.warning(
            "Recovering diverged repository checkout",
            extra={"local_path": str(local_path), "default_branch": default_branch, "error": str(original_error)},
        )
        if fetch_full_history:
            if (local_path / ".git" / "shallow").exists():
                run_command(
                    [self.settings.git_binary, "-C", str(local_path), "fetch", "--unshallow", "--tags", "origin"],
                    timeout=900,
                )
            else:
                run_command(
                    [self.settings.git_binary, "-C", str(local_path), "fetch", "--tags", "--prune", "origin"],
                    timeout=900,
                )
        else:
            run_command(
                [self.settings.git_binary, "-C", str(local_path), "fetch", "--prune", "origin", default_branch],
                timeout=900,
            )
        remote_ref = f"origin/{default_branch}"
        run_command([self.settings.git_binary, "-C", str(local_path), "reset", "--hard"], timeout=120)
        run_command([self.settings.git_binary, "-C", str(local_path), "clean", "-fdx"], timeout=120)
        run_command(
            [self.settings.git_binary, "-C", str(local_path), "checkout", "-B", default_branch, remote_ref],
            timeout=120,
        )
        run_command([self.settings.git_binary, "-C", str(local_path), "reset", "--hard", remote_ref], timeout=120)

    def _authenticated_clone_url(self, clone_url: str) -> str:
        """Inject the GitHub token for private repository cloning without exposing it in logs."""

        if not self.settings.github_token or "https://" not in clone_url:
            return clone_url
        return clone_url.replace("https://", f"https://x-access-token:{self.settings.github_token}@")

    def _refresh_origin_remote(self, local_path: Path, authenticated_url: str) -> None:
        """Keep the cached checkout remote aligned with the current token before pull/fetch runs."""

        if "https://" not in authenticated_url:
            return
        run_command(
            [
                self.settings.git_binary,
                "-C",
                str(local_path),
                "remote",
                "set-url",
                "origin",
                authenticated_url,
            ],
            timeout=120,
        )

    def _should_fetch_full_history(self, repository_data: dict) -> bool:
        """Only fetch full history when public repo history scanning is enabled."""

        return self.settings.secret_history_scan_enabled and not repository_data.get("private", False)

    def _should_sync_repository(
        self,
        repository_data: dict,
        *,
        repository_full_name: str | None,
        include_archived: bool,
    ) -> bool:
        """Apply operator repository selection rules before cloning or scanning."""

        full_name = repository_data.get("full_name", "")
        if repository_full_name and full_name != repository_full_name:
            return False
        if repository_data.get("archived") and not include_archived:
            return False
        if repository_data.get("fork") and not self.settings.github_include_forks:
            LOGGER.debug("Skipping forked GitHub repository", extra={"repository": full_name})
            return False
        return True
