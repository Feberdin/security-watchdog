"""
Purpose: Synchronize GitHub repositories into local checkouts that other scanners can inspect.
Input/Output: Uses the GitHub API plus local `git` commands and returns repository metadata.
Important invariants: Existing repositories are updated with fast-forward pulls only; clone paths are
stable so historical scan artifacts remain easy to inspect on disk.
Debugging: If a repository does not update, inspect the logged git command and local checkout path.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.utils import run_command, safe_slug
from app.repositories.store import upsert_repository
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
    ) -> list:
        """Fetch repository metadata from GitHub and clone or pull locally."""

        synced = []
        try:
            repositories = self.github_client.list_repositories()
        except Exception as error:  # noqa: BLE001
            LOGGER.warning("GitHub repository inventory failed", extra={"error": str(error)})
            return synced

        for repository_data in repositories:
            if repository_full_name and repository_data["full_name"] != repository_full_name:
                continue
            if repository_data.get("archived") and not include_archived:
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
                )
                synced.append(repository)
            except Exception as error:  # noqa: BLE001
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

    def _sync_local_checkout(
        self,
        clone_url: str,
        local_path: Path,
        default_branch: str,
        *,
        fetch_full_history: bool,
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
            return

        self._refresh_origin_remote(local_path, authenticated_url)
        run_command([self.settings.git_binary, "-C", str(local_path), "checkout", default_branch], timeout=120)
        if fetch_full_history:
            self._refresh_full_history_checkout(local_path, default_branch)
            return
        run_command([self.settings.git_binary, "-C", str(local_path), "pull", "--ff-only"], timeout=900)

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

    def _authenticated_clone_url(self, clone_url: str) -> str:
        """Inject the GitHub token for private repository cloning without exposing it in logs."""

        if not self.settings.github_token or "https://" not in clone_url:
            return clone_url
        return clone_url.replace(
            "https://", f"https://x-access-token:{self.settings.github_token}@"
        )

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
