"""Exercise commit-bound scans against real local Git repositories.

Inputs are synthetic commits and a cached checkout with an existing index lock.
Outputs are scan evidence and temporary-workspace lifecycle checks. The cached
lock must remain untouched. Run this file with pytest when checkout scans fail.
"""

from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.utils import run_command
from app.db.base import Base
from app.models.entities import Repository
from app.models.schemas import ScanRequest
from app.services.orchestrator import ScanOrchestrator
from app.services.scan_control import ScanCanceledError


def git(*arguments: str) -> str:
    """Use real Git with synthetic local data; never access a production remote."""

    return run_command(["git", *arguments], timeout=20)


@pytest.fixture
def locked_checkout(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    git("init", "-b", "main", str(source))
    git("-C", str(source), "config", "user.name", "Test Operator")
    git("-C", str(source), "config", "user.email", "operator@example.invalid")
    (source / "README.md").write_text("default branch\n")
    git("-C", str(source), "add", "README.md")
    git("-C", str(source), "commit", "-m", "Initial fixture")
    git("-C", str(source), "checkout", "-b", "candidate")
    (source / "README.md").write_text("requested commit\n")
    git("-C", str(source), "commit", "-am", "Candidate fixture")
    target = git("-C", str(source), "rev-parse", "HEAD")
    storage = tmp_path / "storage"
    cache = storage / "feberdin" / "example"
    cache.parent.mkdir(parents=True)
    git("clone", "--branch", "main", str(source), str(cache))
    lock = cache / ".git" / "index.lock"
    lock.write_bytes(b"existing lock: do not remove")

    orchestrator = ScanOrchestrator()
    scanner = orchestrator.repository_scanner
    scanner.settings = scanner.settings.model_copy(update={"repo_storage_path": storage, "github_token": ""})
    scanner.github_client.list_repositories = lambda: [
        {
            "id": 1,
            "name": "example",
            "full_name": "Feberdin/example",
            "clone_url": str(source),
            "default_branch": "main",
            "owner": {"login": "Feberdin"},
            "private": True,
        }
    ]
    orchestrator._dispatch_open_alerts = lambda *_args, **_kwargs: None
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield orchestrator, session, target, cache, lock, storage
    engine.dispose()


def test_predeploy_scan_succeeds_with_locked_cache_and_keeps_exact_evidence(locked_checkout):
    orchestrator, session, target, cache, lock, storage = locked_checkout
    scanned_paths = []

    def inspect_checkout(_session, repository, *_args, **_kwargs):
        path = orchestrator.repository_scanner.get_scan_path(repository)
        assert path != cache
        assert (path / "README.md").read_text() == "requested commit\n"
        scanned_paths.append(path)
        return 0

    orchestrator._scan_repository_asset = inspect_checkout
    request = ScanRequest(
        repository_full_name="Feberdin/example",
        scan_sources=["github"],
        purpose="pre_deploy",
        target_commit_sha=target,
    )
    response = orchestrator.run_manual_scan(session, request)

    assert response.repository_count == 1, "A locked disposable cache must not drop the requested repository"
    assert response.failed_system_count == 0
    assert response.scanned_commit_sha == target
    assert len(scanned_paths) == 1
    assert not scanned_paths[0].exists()
    assert not list(storage.glob(".predeploy-*"))
    assert lock.read_bytes() == b"existing lock: do not remove"
    assert (cache / "README.md").read_text() == "default branch\n"
    repository = session.scalar(select(Repository))
    assert Path(repository.local_path) == cache


def test_predeploy_missing_commit_produces_no_evidence_and_cleans_workspace(locked_checkout):
    orchestrator, session, _target, _cache, lock, storage = locked_checkout
    response = orchestrator.run_manual_scan(
        session,
        ScanRequest(
            repository_full_name="Feberdin/example",
            scan_sources=["github"],
            purpose="pre_deploy",
            target_commit_sha="a" * 40,
        ),
    )

    assert response.repository_count == 0
    assert response.scanned_commit_sha is None
    assert not list(storage.glob(".predeploy-*"))
    assert lock.read_bytes() == b"existing lock: do not remove"


def test_predeploy_cancellation_cleans_workspace_without_touching_cache(locked_checkout):
    orchestrator, session, target, _cache, lock, storage = locked_checkout
    checks = 0

    def cancel_after_inventory():
        nonlocal checks
        checks += 1
        if checks == 2:
            assert list(storage.glob(".predeploy-*"))
            raise ScanCanceledError("synthetic cancellation")

    with pytest.raises(ScanCanceledError, match="synthetic cancellation"):
        orchestrator.run_manual_scan(
            session,
            ScanRequest(
                repository_full_name="Feberdin/example",
                scan_sources=["github"],
                purpose="pre_deploy",
                target_commit_sha=target,
            ),
            cancellation_check=cancel_after_inventory,
        )

    assert not list(storage.glob(".predeploy-*"))
    assert lock.read_bytes() == b"existing lock: do not remove"
