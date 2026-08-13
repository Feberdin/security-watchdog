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
        target_commit_sha: str | None = None,
    ) -> None:
        if "broken-repo" in clone_url:
            raise RuntimeError("simulated checkout failure")

    scanner._sync_local_checkout = fake_sync_local_checkout

    repositories = scanner.sync_repositories(session)

    assert [repository.full_name for repository in repositories] == ["Feberdin/healthy-repo"]


def test_sync_repositories_skips_forks_by_default() -> None:
    """Forked repositories should stay out of normal scans unless explicitly enabled."""

    session = build_test_session()
    scanner = RepositoryScanner()
    scanner.github_client.list_repositories = lambda: [
        {
            "id": 1,
            "name": "core",
            "full_name": "Feberdin/core",
            "clone_url": "https://github.com/Feberdin/core.git",
            "default_branch": "dev",
            "archived": False,
            "fork": True,
            "owner": {"login": "Feberdin"},
        },
        {
            "id": 2,
            "name": "security-watchdog",
            "full_name": "Feberdin/security-watchdog",
            "clone_url": "https://github.com/Feberdin/security-watchdog.git",
            "default_branch": "main",
            "archived": False,
            "fork": False,
            "owner": {"login": "Feberdin"},
        },
    ]
    scanner._sync_local_checkout = lambda *args, **kwargs: None

    repositories = scanner.sync_repositories(session)

    assert [repository.full_name for repository in repositories] == ["Feberdin/security-watchdog"]


def test_sync_repositories_can_include_forks_when_configured() -> None:
    """Operators can still opt into fork scans for explicit review setups."""

    session = build_test_session()
    scanner = RepositoryScanner()
    original_include_forks = scanner.settings.github_include_forks
    scanner.settings.github_include_forks = True
    scanner.github_client.list_repositories = lambda: [
        {
            "id": 1,
            "name": "core",
            "full_name": "Feberdin/core",
            "clone_url": "https://github.com/Feberdin/core.git",
            "default_branch": "dev",
            "archived": False,
            "fork": True,
            "owner": {"login": "Feberdin"},
        }
    ]
    scanner._sync_local_checkout = lambda *args, **kwargs: None

    try:
        repositories = scanner.sync_repositories(session)
    finally:
        scanner.settings.github_include_forks = original_include_forks

    assert [repository.full_name for repository in repositories] == ["Feberdin/core"]


def test_sync_repositories_includes_explicitly_targeted_fork() -> None:
    """A named pre-deploy scan must inspect its fork even when broad fork scans are disabled."""

    session = build_test_session()
    scanner = RepositoryScanner()
    original_include_forks = scanner.settings.github_include_forks
    scanner.settings.github_include_forks = False
    scanner.github_client.list_repositories = lambda: [
        {
            "id": 1,
            "name": "RuView",
            "full_name": "Feberdin/RuView",
            "clone_url": "https://github.com/Feberdin/RuView.git",
            "default_branch": "main",
            "archived": False,
            "fork": True,
            "owner": {"login": "Feberdin"},
        }
    ]
    requested_commit_sha = "a1" * 20
    requested_calls: list[tuple[str, str | None]] = []

    def fake_sync_local_checkout(
        clone_url: str,
        local_path,
        default_branch: str,
        *,
        fetch_full_history: bool,
        target_commit_sha: str | None = None,
    ) -> None:
        requested_calls.append((clone_url, target_commit_sha))

    scanner._sync_local_checkout = fake_sync_local_checkout

    try:
        repositories = scanner.sync_repositories(
            session,
            repository_full_name="Feberdin/RuView",
            target_commit_sha=requested_commit_sha,
        )
    finally:
        scanner.settings.github_include_forks = original_include_forks

    assert [repository.full_name for repository in repositories] == ["Feberdin/RuView"]
    assert requested_calls == [
        ("https://github.com/Feberdin/RuView.git", requested_commit_sha)
    ]


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


def test_sync_repositories_targets_a_specific_request_for_pre_deploy_commit(tmp_path) -> None:
    """Pre-deploy scans can request a non-default branch commit for one repository."""

    scanner = RepositoryScanner()
    scanner.settings.repo_storage_path = tmp_path
    scanner.github_client.list_repositories = lambda: [
        {
            "id": 1,
            "name": "security-watchdog",
            "full_name": "Feberdin/security-watchdog",
            "clone_url": "https://github.com/Feberdin/security-watchdog.git",
            "default_branch": "main",
            "archived": False,
            "owner": {"login": "Feberdin"},
        },
        {
            "id": 2,
            "name": "other",
            "full_name": "Feberdin/other",
            "clone_url": "https://github.com/Feberdin/other.git",
            "default_branch": "main",
            "archived": False,
            "owner": {"login": "Feberdin"},
        },
    ]

    requested_commit_sha = "a1" * 20
    requested_calls: list[tuple[str, str | None]] = []

    def fake_sync_local_checkout(
        clone_url: str,
        local_path,
        default_branch: str,
        *,
        fetch_full_history: bool,
        target_commit_sha: str | None = None,
    ) -> None:
        requested_calls.append((clone_url, target_commit_sha))

    scanner._sync_local_checkout = fake_sync_local_checkout

    repositories = scanner.sync_repositories(
        build_test_session(),
        repository_full_name="Feberdin/security-watchdog",
        target_commit_sha=requested_commit_sha,
    )

    assert len(requested_calls) == 1
    assert requested_calls[0] == (
        "https://github.com/Feberdin/security-watchdog.git",
        requested_commit_sha,
    )
    assert repositories[0].full_name == "Feberdin/security-watchdog"


def test_align_checkout_to_target_commit_prefers_direct_fetch(tmp_path, monkeypatch) -> None:
    """Direct commit fetch is used first and detached checkout is verified against HEAD."""

    scanner = RepositoryScanner()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    target_commit_sha = "a1" * 20
    commands: list[list[str]] = []
    checked_out = False

    def fake_run_command(command: list[str], **kwargs) -> str:
        nonlocal checked_out
        commands.append(command)
        if command[1:3] == ["-C", str(repo_path)] and command[3] == "rev-parse":
            if command[-1] == f"{target_commit_sha}^{{commit}}":
                raise RuntimeError("missing")
            if command[-1] == "HEAD^{commit}":
                return target_commit_sha if checked_out else "b2" * 20
        if command[1:3] == ["-C", str(repo_path)] and command[3:5] == ["checkout", "--detach"]:
            checked_out = True
        return ""

    monkeypatch.setattr("app.scanners.repository_scanner.run_command", fake_run_command)

    scanner._align_checkout_to_target_commit(repo_path, target_commit_sha)

    assert any(command[-1] == target_commit_sha and command[3] == "fetch" for command in commands)
    assert any(command[3:6] == ["checkout", "--detach", target_commit_sha] for command in commands)
    assert not any(
        "+refs/heads/*:refs/remotes/origin/*" in " ".join(command) for command in commands
    )


def test_align_checkout_to_target_commit_falls_back_to_all_heads_when_direct_fetch_fails(tmp_path, monkeypatch) -> None:
    """Fallback branch-refspec fetch runs when a direct commit fetch is unavailable."""

    scanner = RepositoryScanner()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    target_commit_sha = "a1" * 20
    commands: list[list[str]] = []
    fetch_attempts = {"count": 0}
    checked_out = False

    def fake_run_command(command: list[str], **kwargs) -> str:
        nonlocal checked_out
        commands.append(command)
        if command[1:3] == ["-C", str(repo_path)] and command[3] == "rev-parse":
            if command[-1] == f"{target_commit_sha}^{{commit}}":
                raise RuntimeError("missing")
            if command[-1] == "HEAD^{commit}":
                return target_commit_sha if checked_out else "b2" * 20
        if command[1:3] == ["-C", str(repo_path)] and command[3] == "fetch" and command[4] == "--depth=1":
            if command[-1] == target_commit_sha:
                fetch_attempts["count"] += 1
                if fetch_attempts["count"] == 1:
                    raise RuntimeError("not found")
            return ""
        if command[1:3] == ["-C", str(repo_path)] and command[3:5] == ["checkout", "--detach"]:
            checked_out = True
        return ""

    monkeypatch.setattr("app.scanners.repository_scanner.run_command", fake_run_command)

    scanner._align_checkout_to_target_commit(repo_path, target_commit_sha)

    assert any(
        command[-1] == target_commit_sha
        for command in commands
        if "+refs/heads/*:refs/remotes/origin/*" not in command
    )
    assert any(
        "+refs/heads/*:refs/remotes/origin/*" in " ".join(command) for command in commands
    )


def test_align_checkout_to_cached_target_commit_moves_head_without_fetch(tmp_path, monkeypatch) -> None:
    """A cached target object must still be checked out when HEAD points somewhere else."""

    scanner = RepositoryScanner()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    target_commit_sha = "a1" * 20
    commands: list[list[str]] = []
    checked_out = False

    def fake_run_command(command: list[str], **kwargs) -> str:
        nonlocal checked_out
        commands.append(command)
        if command[1:3] == ["-C", str(repo_path)] and command[3] == "rev-parse":
            if command[-1] == "HEAD^{commit}":
                return target_commit_sha if checked_out else "b2" * 20
            if command[-1] == f"{target_commit_sha}^{{commit}}":
                return target_commit_sha
        if command[1:3] == ["-C", str(repo_path)] and command[3:5] == ["checkout", "--detach"]:
            checked_out = True
        return ""

    monkeypatch.setattr("app.scanners.repository_scanner.run_command", fake_run_command)

    scanner._align_checkout_to_target_commit(repo_path, target_commit_sha)

    assert any(command[3:6] == ["checkout", "--detach", target_commit_sha] for command in commands)
    assert not any(command[3] == "fetch" for command in commands)


def test_existing_repository_pull_refreshes_origin_with_current_token(tmp_path, monkeypatch) -> None:
    """Cached private checkouts should refresh the origin URL before pulling new commits."""

    scanner = RepositoryScanner()
    expected_token = "".join(("fresh", "-", "token"))
    scanner.settings.github_token = expected_token
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
        f"https://x-access-token:{expected_token}@github.com/Feberdin/private-repo.git",
    ]
    assert recorded_commands[1][:4] == [scanner.settings.git_binary, "-C", str(checkout_path), "checkout"]
    assert recorded_commands[2][:4] == [scanner.settings.git_binary, "-C", str(checkout_path), "pull"]


def test_existing_repository_recovers_diverged_checkout(tmp_path, monkeypatch) -> None:
    """A disposable scanner checkout should reset to GitHub when fast-forward pull fails."""

    scanner = RepositoryScanner()
    scanner.settings.github_token = ""
    checkout_path = tmp_path / "diverged-repo"
    checkout_path.mkdir(parents=True)
    recorded_commands: list[list[str]] = []

    def fake_run_command(command: list[str], **kwargs) -> str:
        recorded_commands.append(command)
        if command[-2:] == ["pull", "--ff-only"]:
            raise RuntimeError("fatal: Not possible to fast-forward, aborting.")
        return ""

    monkeypatch.setattr("app.scanners.repository_scanner.run_command", fake_run_command)

    scanner._sync_local_checkout(
        "https://github.com/Feberdin/diverged-repo.git",
        checkout_path,
        "main",
        fetch_full_history=False,
    )

    assert [command[3:] for command in recorded_commands] == [
        ["remote", "set-url", "origin", "https://github.com/Feberdin/diverged-repo.git"],
        ["checkout", "main"],
        ["pull", "--ff-only"],
        ["fetch", "--prune", "origin", "main"],
        ["reset", "--hard"],
        ["clean", "-fdx"],
        ["checkout", "-B", "main", "origin/main"],
        ["reset", "--hard", "origin/main"],
    ]


def test_checkout_commit_sha_requires_full_verified_git_commit(tmp_path, monkeypatch) -> None:
    """Aggregate scan evidence should use the exact full commit returned by Git."""

    scanner = RepositoryScanner()
    checkout_path = tmp_path / "repository"
    (checkout_path / ".git").mkdir(parents=True)
    recorded_commands: list[list[str]] = []
    expected_sha = "a1" * 20

    monkeypatch.setattr(
        "app.scanners.repository_scanner.run_command",
        lambda command, **kwargs: recorded_commands.append(command) or expected_sha.upper(),
    )

    assert scanner.get_checkout_commit_sha(checkout_path) == expected_sha
    assert recorded_commands == [
        [
            scanner.settings.git_binary,
            "-C",
            str(checkout_path),
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        ]
    ]


def test_checkout_commit_sha_rejects_non_repository_path(tmp_path) -> None:
    """Missing Git metadata must block commit provenance instead of returning a guess."""

    scanner = RepositoryScanner()

    try:
        scanner.get_checkout_commit_sha(tmp_path)
    except RuntimeError as error:
        assert "not a Git worktree" in str(error)
    else:
        raise AssertionError("Expected missing Git metadata to raise RuntimeError")
