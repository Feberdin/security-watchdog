"""
Purpose: Verify the manual scan orchestrator stays resilient when one asset fails mid-run.
Input/Output: Builds an in-memory database, injects synthetic repositories, and forces one scan
branch to fail while another succeeds.
Important invariants: A single asset failure must not abort the whole manual scan because operators
need fresh data from the rest of the estate even when one repository or scanner is broken.
Debugging: If `/scan` starts returning 500 again, inspect the guarded helper methods in the
orchestrator and this regression test first.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import pairwise

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

import app.models.entities  # noqa: F401
from app.db.base import Base
from app.models.entities import ManualScanJob, ManualScanJobStatus, Repository, ScanResult
from app.models.schemas import ScanProgressUpdate, ScanRequest
from app.services.orchestrator import ScanOrchestrator


def build_test_session() -> Session:
    """Create a throwaway in-memory database session for orchestrator tests."""

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return Session(engine)


def test_manual_scan_continues_when_one_repository_asset_fails() -> None:
    """One broken repository should be recorded as failed without aborting the full scan."""

    session = build_test_session()
    failing_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="broken-repo",
        full_name="Feberdin/broken-repo",
        local_path="/tmp/broken-repo",
    )
    healthy_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="healthy-repo",
        full_name="Feberdin/healthy-repo",
        local_path="/tmp/healthy-repo",
    )
    session.add_all([failing_repository, healthy_repository])
    session.commit()

    orchestrator = ScanOrchestrator()
    orchestrator.repository_scanner.sync_repositories = lambda *args, **kwargs: [
        failing_repository,
        healthy_repository,
    ]
    orchestrator.unraid_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator.homeassistant_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator._dispatch_open_alerts = lambda *args, **kwargs: None
    orchestrator.repository_scanner.get_checkout_commit_sha = (
        lambda *args, **kwargs: "a" * 40
    )

    def fake_repository_scan(
        _session: Session,
        repository: Repository,
        _progress=None,
    ) -> int:
        if repository.id == failing_repository.id:
            raise RuntimeError("simulated repository scan failure")
        return 2

    orchestrator._scan_repository_asset = fake_repository_scan

    progress_updates: list[ScanProgressUpdate] = []
    response = orchestrator.run_manual_scan(
        session,
        ScanRequest(repository_full_name=None, include_archived=False, force=True),
        progress_callback=progress_updates.append,
    )

    failure_results = session.scalars(
        select(ScanResult).where(ScanResult.scanner_name == "repository_asset_scan")
    ).all()

    assert response.message == "Scan completed with warnings"
    assert response.repository_count == 2
    assert response.alert_count == 2
    assert response.failed_system_count == 1
    assert len(failure_results) == 2
    assert {result.repository_id: result.status for result in failure_results} == {
        failing_repository.id: "error",
        healthy_repository.id: "success",
    }
    healthy_result = next(
        result for result in failure_results if result.repository_id == healthy_repository.id
    )
    assert healthy_result.details_json["commit_sha"] == "a" * 40
    assert progress_updates[-1].phase == "finalizing"
    assert progress_updates[-1].percent == 98
    assert any(update.level == "warning" for update in progress_updates)
    assert all(current.percent <= following.percent for current, following in pairwise(progress_updates))


def test_manual_scan_resume_uses_existing_asset_outcomes_and_updates_checkpoint() -> None:
    """A resumed scan should skip durable successes/failures and continue with pending assets."""

    session = build_test_session()
    job_started_at = datetime.now(UTC) - timedelta(minutes=10)
    already_scanned_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="already-scanned",
        full_name="Feberdin/already-scanned",
        local_path="/tmp/already-scanned",
        last_scanned_at=datetime.now(UTC) - timedelta(minutes=2),
    )
    already_failed_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="already-failed",
        full_name="Feberdin/already-failed",
        local_path="/tmp/already-failed",
    )
    pending_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="pending-repo",
        full_name="Feberdin/pending-repo",
        local_path="/tmp/pending-repo",
    )
    job = ManualScanJob(
        status=ManualScanJobStatus.RUNNING.value,
        started_at=job_started_at,
    )
    session.add_all([already_scanned_repository, already_failed_repository, pending_repository, job])
    session.flush()
    session.add(
        ScanResult(
            repository_id=already_failed_repository.id,
            scanner_name="repository_asset_scan",
            status="error",
            findings_count=0,
            started_at=datetime.now(UTC) - timedelta(minutes=1),
            completed_at=datetime.now(UTC) - timedelta(minutes=1),
            details_json={"error": "previous failure"},
        )
    )
    session.commit()

    orchestrator = ScanOrchestrator()
    orchestrator.repository_scanner.sync_repositories = lambda *args, **kwargs: [
        already_scanned_repository,
        already_failed_repository,
        pending_repository,
    ]
    orchestrator.unraid_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator.homeassistant_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator._dispatch_open_alerts = lambda *args, **kwargs: None
    orchestrator.repository_scanner.get_checkout_commit_sha = lambda *args, **kwargs: "b" * 40
    scanned_repositories: list[str] = []

    def fake_repository_scan(_session: Session, repository: Repository, _progress=None) -> int:
        scanned_repositories.append(repository.full_name)
        return 3

    orchestrator._scan_repository_asset = fake_repository_scan

    response = orchestrator.run_manual_scan(
        session,
        ScanRequest(repository_full_name=None, include_archived=False, force=True),
        job_id=job.id,
        resume_started_at=job_started_at,
    )
    stored_job = session.get(ManualScanJob, job.id)

    assert scanned_repositories == ["Feberdin/pending-repo"]
    assert response.repository_count == 3
    assert response.alert_count == 3
    assert response.failed_system_count == 1
    assert stored_job is not None
    assert stored_job.repository_count == 3
    assert stored_job.alert_count == 3
    assert stored_job.failed_system_count == 1


def test_manual_scan_resume_does_not_double_count_checkpointed_assets() -> None:
    """Counters already stored on the job row should not be inflated by skipped assets."""

    session = build_test_session()
    job_started_at = datetime.now(UTC) - timedelta(minutes=10)
    already_scanned_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="already-scanned",
        full_name="Feberdin/already-scanned",
        local_path="/tmp/already-scanned",
        last_scanned_at=datetime.now(UTC) - timedelta(minutes=2),
    )
    pending_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="pending-repo",
        full_name="Feberdin/pending-repo",
        local_path="/tmp/pending-repo",
    )
    job = ManualScanJob(
        status=ManualScanJobStatus.RUNNING.value,
        started_at=job_started_at,
        repository_count=1,
        alert_count=4,
        failed_system_count=0,
    )
    session.add_all([already_scanned_repository, pending_repository, job])
    session.commit()

    orchestrator = ScanOrchestrator()
    orchestrator.repository_scanner.sync_repositories = lambda *args, **kwargs: [
        already_scanned_repository,
        pending_repository,
    ]
    orchestrator.unraid_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator.homeassistant_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator._dispatch_open_alerts = lambda *args, **kwargs: None
    orchestrator.repository_scanner.get_checkout_commit_sha = lambda *args, **kwargs: "b" * 40
    scanned_repositories: list[str] = []

    def fake_repository_scan(_session: Session, repository: Repository, _progress=None) -> int:
        scanned_repositories.append(repository.full_name)
        return 2

    orchestrator._scan_repository_asset = fake_repository_scan

    response = orchestrator.run_manual_scan(
        session,
        ScanRequest(repository_full_name=None, include_archived=False, force=True),
        job_id=job.id,
        resume_started_at=job_started_at,
    )
    stored_job = session.get(ManualScanJob, job.id)

    assert scanned_repositories == ["Feberdin/pending-repo"]
    assert response.repository_count == 2
    assert response.alert_count == 6
    assert response.failed_system_count == 0
    assert stored_job is not None
    assert stored_job.repository_count == 2
    assert stored_job.alert_count == 6
