"""
Purpose: Verify GitHub repository synchronization degrades gracefully on per-repository failures.
Input/Output: Injects synthetic GitHub inventory rows and forces one local checkout update to fail.
Important invariants: One broken clone or pull must not block the rest of the repository inventory.
Debugging: If GitHub inventory drops to zero after one checkout error, inspect
`RepositoryScanner.sync_repositories()` and this test together.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import app.models.entities  # noqa: F401
from app.db.base import Base
from app.scanners.repository_scanner import RepositoryScanner


def build_test_session() -> Session:
    """Create a throwaway in-memory database session for repository scanner tests."""

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return Session(engine)


def test_sync_repositories_skips_only_the_repo_that_failed_checkout() -> None:
    """A checkout error should be logged and skipped without dropping healthy repositories."""

    session = build_test_session()
    scanner = RepositoryScanner()
    scanner.github_client.list_repositories = lambda: [
        {
            "id": 1,
            "name": "broken-repo",
            "full_name": "Feberdin/broken-repo",
            "clone_url": "https://github.com/Feberdin/broken-repo.git",
            "default_branch": "main",
            "archived": False,
            "owner": {"login": "Feberdin"},
        },
        {
            "id": 2,
            "name": "healthy-repo",
            "full_name": "Feberdin/healthy-repo",
            "clone_url": "https://github.com/Feberdin/healthy-repo.git",
            "default_branch": "main",
            "archived": False,
            "owner": {"login": "Feberdin"},
        },
    ]

    def fake_sync_local_checkout(
        clone_url: str,
        local_path,
        default_branch: str,
        *,
        fetch_full_history: bool,
    ) -> None:
        if "broken-repo" in clone_url:
            raise RuntimeError("simulated checkout failure")

    scanner._sync_local_checkout = fake_sync_local_checkout

    repositories = scanner.sync_repositories(session)

    assert [repository.full_name for repository in repositories] == ["Feberdin/healthy-repo"]


def test_public_repository_clone_uses_full_history(tmp_path, monkeypatch) -> None:
    """Public repositories should be cloned without `--depth 1` so history scans can run."""

    scanner = RepositoryScanner()
    scanner.settings.repo_storage_path = tmp_path
    recorded_commands: list[list[str]] = []

    monkeypatch.setattr(
        "app.scanners.repository_scanner.run_command",
        lambda command, **kwargs: recorded_commands.append(command) or "",
    )

    scanner._sync_local_checkout(
        "https://github.com/Feberdin/public-repo.git",
        tmp_path / "public-repo",
        "main",
        fetch_full_history=True,
    )

    assert recorded_commands
    assert recorded_commands[0][:4] == [scanner.settings.git_binary, "clone", "--branch", "main"]
    assert "--depth" not in recorded_commands[0]


def test_existing_repository_pull_refreshes_origin_with_current_token(tmp_path, monkeypatch) -> None:
    """Cached private checkouts should refresh the origin URL before pulling new commits."""

    scanner = RepositoryScanner()
    scanner.settings.github_token = "fresh-token"
    checkout_path = tmp_path / "private-repo"
    checkout_path.mkdir(parents=True)
    recorded_commands: list[list[str]] = []

    monkeypatch.setattr(
        "app.scanners.repository_scanner.run_command",
        lambda command, **kwargs: recorded_commands.append(command) or "",
    )

    scanner._sync_local_checkout(
        "https://github.com/Feberdin/private-repo.git",
        checkout_path,
        "main",
        fetch_full_history=False,
    )

    assert recorded_commands[0] == [
        scanner.settings.git_binary,
        "-C",
        str(checkout_path),
        "remote",
        "set-url",
        "origin",
        "https://x-access-token:fresh-token@github.com/Feberdin/private-repo.git",
    ]
    assert recorded_commands[1][:4] == [scanner.settings.git_binary, "-C", str(checkout_path), "checkout"]
    assert recorded_commands[2][:4] == [scanner.settings.git_binary, "-C", str(checkout_path), "pull"]
