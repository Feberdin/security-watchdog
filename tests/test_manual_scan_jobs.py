"""
Purpose: Verify manual scan queueing, status transitions, and failure reporting end to end.
Input/Output: Builds a shared in-memory database, enqueues jobs, runs the queue processor, and
asserts the persisted lifecycle fields.
Important invariants: Only one manual scan should be active at a time, and failures must be stored
on the job row instead of disappearing into logs.
Debugging: If a dashboard scan looks stuck, start with these tests and then inspect
`app/services/manual_scan_jobs.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.models.entities  # noqa: F401
from app.db.base import Base
from app.models.entities import ManualScanJobStatus
from app.models.schemas import ScanProgressUpdate, ScanRequest, ScanResponse
from app.repositories.store import claim_manual_scan_job, get_manual_scan_job
from app.services import manual_scan_jobs


def build_session_factory() -> sessionmaker[Session]:
    """Create a shared in-memory SQLite database so multiple sessions see the same queue rows."""

    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)


def test_enqueue_manual_scan_reuses_active_job() -> None:
    """A second click during an active run should reuse the existing queued job."""

    session_factory = build_session_factory()
    session = session_factory()

    first_job, first_created = manual_scan_jobs.enqueue_manual_scan(
        session,
        ScanRequest(repository_full_name=None, include_archived=False, force=True),
    )
    session.commit()

    second_job, second_created = manual_scan_jobs.enqueue_manual_scan(
        session,
        ScanRequest(repository_full_name=None, include_archived=False, force=True),
    )
    session.commit()

    assert first_created is True
    assert second_created is False
    assert second_job.id == first_job.id
    assert second_job.status == ManualScanJobStatus.QUEUED.value


def test_recover_interrupted_manual_scan_jobs_keeps_running_job_resumable(monkeypatch) -> None:
    """A runner restart should leave a running job available for resume instead of failing it."""

    session_factory = build_session_factory()
    monkeypatch.setattr(manual_scan_jobs, "SessionLocal", session_factory)

    with session_factory() as session:
        job, _ = manual_scan_jobs.enqueue_manual_scan(
            session,
            ScanRequest(repository_full_name=None, include_archived=False, force=True),
        )
        session.commit()
        job_id = job.id

        claimed_job = claim_manual_scan_job(session, job_id=job_id)
        session.commit()
        assert claimed_job is not None
        assert claimed_job.status == ManualScanJobStatus.RUNNING.value

    recovered_count = manual_scan_jobs.recover_interrupted_manual_scan_jobs()

    with session_factory() as session:
        stored_job = get_manual_scan_job(session, job_id)
        replacement_job, replacement_created = manual_scan_jobs.enqueue_manual_scan(
            session,
            ScanRequest(repository_full_name=None, include_archived=False, force=True),
        )

    assert recovered_count == 0
    assert stored_job is not None
    assert stored_job.status == ManualScanJobStatus.RUNNING.value
    assert stored_job.completed_at is None
    assert stored_job.error_message is None
    assert replacement_created is False
    assert replacement_job.id == job_id


def test_recover_interrupted_manual_scan_jobs_leaves_queued_job_active(monkeypatch) -> None:
    """Recovery must not fail a queued scan that no process has claimed yet."""

    session_factory = build_session_factory()
    monkeypatch.setattr(manual_scan_jobs, "SessionLocal", session_factory)

    with session_factory() as session:
        queued_job, _ = manual_scan_jobs.enqueue_manual_scan(
            session,
            ScanRequest(repository_full_name="Feberdin/security-watchdog", include_archived=False, force=False),
        )
        session.commit()
        queued_job_id = queued_job.id

    recovered_count = manual_scan_jobs.recover_interrupted_manual_scan_jobs()

    with session_factory() as session:
        stored_job = get_manual_scan_job(session, queued_job_id)

    assert recovered_count == 0
    assert stored_job is not None
    assert stored_job.status == ManualScanJobStatus.QUEUED.value
    assert stored_job.completed_at is None
    assert stored_job.error_message is None


def test_process_manual_scan_job_marks_job_succeeded(monkeypatch) -> None:
    """A claimed job should persist running and success metadata after orchestration finishes."""

    session_factory = build_session_factory()
    monkeypatch.setattr(manual_scan_jobs, "SessionLocal", session_factory)

    class FakeOrchestrator:
        """Minimal orchestrator stub that keeps the test offline and deterministic."""

        def run_manual_scan(
            self,
            session: Session,
            request: ScanRequest,
            *,
            job_id: int | None = None,
            resume_started_at=None,
            progress_callback=None,
        ) -> ScanResponse:
            assert request.force is True
            assert job_id == 1
            assert resume_started_at is not None
            assert progress_callback is not None
            progress_callback(
                ScanProgressUpdate(
                    phase="vulnerabilities",
                    message="Dependency 2/4 wird geprüft.",
                    current=2,
                    total=4,
                    percent=50.0,
                )
            )
            return ScanResponse(
                message="Scan completed with warnings",
                repository_count=4,
                alert_count=9,
                failed_system_count=1,
            )

    monkeypatch.setattr(manual_scan_jobs, "ScanOrchestrator", FakeOrchestrator)

    with session_factory() as session:
        job, created = manual_scan_jobs.enqueue_manual_scan(
            session,
            ScanRequest(repository_full_name="Feberdin/security-watchdog", include_archived=False, force=True),
        )
        session.commit()
        job_id = job.id

    result = manual_scan_jobs.process_manual_scan_job(job_id)

    with session_factory() as session:
        stored_job = get_manual_scan_job(session, job_id)

    assert created is True
    assert result is not None
    assert result.status == ManualScanJobStatus.SUCCEEDED.value
    assert result.repository_count == 4
    assert result.alert_count == 9
    assert result.failed_system_count == 1
    assert result.progress.phase == "completed"
    assert result.progress.percent == 100
    assert any(event.percent == 50 for event in result.progress.events)
    assert stored_job is not None
    assert stored_job.status == ManualScanJobStatus.SUCCEEDED.value
    assert stored_job.started_at is not None
    assert stored_job.completed_at is not None
    assert stored_job.error_message is None


def test_process_manual_scan_job_marks_job_failed(monkeypatch) -> None:
    """Unexpected scan errors should be reflected on the job row and in the returned status."""

    session_factory = build_session_factory()
    monkeypatch.setattr(manual_scan_jobs, "SessionLocal", session_factory)

    class ExplodingOrchestrator:
        """Force a reproducible failure so the queue error path can be asserted."""

        def run_manual_scan(
            self,
            session: Session,
            request: ScanRequest,
            *,
            job_id: int | None = None,
            resume_started_at=None,
            progress_callback=None,
        ) -> ScanResponse:
            assert job_id == 1
            assert resume_started_at is not None
            assert progress_callback is not None
            raise RuntimeError("simulated queue failure")

    monkeypatch.setattr(manual_scan_jobs, "ScanOrchestrator", ExplodingOrchestrator)

    with session_factory() as session:
        job, created = manual_scan_jobs.enqueue_manual_scan(
            session,
            ScanRequest(repository_full_name=None, include_archived=False, force=False),
        )
        session.commit()
        job_id = job.id

    result = manual_scan_jobs.process_manual_scan_job(job_id)

    with session_factory() as session:
        stored_job = get_manual_scan_job(session, job_id)

    assert created is True
    assert result is not None
    assert result.status == ManualScanJobStatus.FAILED.value
    assert "RuntimeError: simulated queue failure" in (result.error_message or "")
    assert result.progress.phase == "failed"
    assert result.progress.events[-1].level == "error"
    assert stored_job is not None
    assert stored_job.status == ManualScanJobStatus.FAILED.value
    assert stored_job.completed_at is not None


def test_process_manual_scan_job_resumes_running_job_after_restart(monkeypatch) -> None:
    """A job left running by a worker restart should be picked up by the queue processor."""

    session_factory = build_session_factory()
    monkeypatch.setattr(manual_scan_jobs, "SessionLocal", session_factory)
    captured_context: dict[str, object] = {}

    class FakeOrchestrator:
        """Capture resume context without running any external scanners."""

        def run_manual_scan(
            self,
            session: Session,
            request: ScanRequest,
            *,
            job_id: int | None = None,
            resume_started_at=None,
            progress_callback=None,
        ) -> ScanResponse:
            captured_context["job_id"] = job_id
            captured_context["resume_started_at"] = resume_started_at
            assert progress_callback is not None
            assert request.repository_full_name is None
            return ScanResponse(
                message="Scan completed",
                repository_count=6,
                alert_count=2,
                failed_system_count=0,
            )

    monkeypatch.setattr(manual_scan_jobs, "ScanOrchestrator", FakeOrchestrator)

    with session_factory() as session:
        job, created = manual_scan_jobs.enqueue_manual_scan(
            session,
            ScanRequest(repository_full_name=None, include_archived=False, force=False),
        )
        job.status = ManualScanJobStatus.RUNNING.value
        job.started_at = datetime.now(UTC) - timedelta(minutes=5)
        session.commit()
        job_id = job.id

    result = manual_scan_jobs.process_manual_scan_job()

    with session_factory() as session:
        stored_job = get_manual_scan_job(session, job_id)

    assert created is True
    assert result is not None
    assert result.status == ManualScanJobStatus.SUCCEEDED.value
    assert captured_context["job_id"] == job_id
    assert captured_context["resume_started_at"] is not None
    assert stored_job is not None
    assert stored_job.status == ManualScanJobStatus.SUCCEEDED.value
