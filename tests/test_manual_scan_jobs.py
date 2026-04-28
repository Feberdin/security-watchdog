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

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.models.entities  # noqa: F401
from app.db.base import Base
from app.models.entities import ManualScanJobStatus
from app.models.schemas import ScanRequest, ScanResponse
from app.repositories.store import get_manual_scan_job
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


def test_process_manual_scan_job_marks_job_succeeded(monkeypatch) -> None:
    """A claimed job should persist running and success metadata after orchestration finishes."""

    session_factory = build_session_factory()
    monkeypatch.setattr(manual_scan_jobs, "SessionLocal", session_factory)

    class FakeOrchestrator:
        """Minimal orchestrator stub that keeps the test offline and deterministic."""

        def run_manual_scan(self, session: Session, request: ScanRequest) -> ScanResponse:
            assert request.force is True
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

        def run_manual_scan(self, session: Session, request: ScanRequest) -> ScanResponse:
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
    assert stored_job is not None
    assert stored_job.status == ManualScanJobStatus.FAILED.value
    assert stored_job.completed_at is not None
