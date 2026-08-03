"""
Purpose: Queue, execute, and serialize manual scan jobs independently from HTTP request lifetimes.
Input/Output: Accepts `ScanRequest` objects, persists durable queue rows, and returns API-friendly
scan-job snapshots that the dashboard can poll.
Important invariants: Only one manual scan should actively run at a time; job claims must be
idempotent, and only a durable worker or embedded scheduler executes queued scans.
Debugging: If a scan seems stuck, inspect `manual_scan_jobs.status`, `started_at`,
`completed_at`, and `error_message` first to see whether the job is queued, running, or failed.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.entities import ManualScanJob, ManualScanJobStatus, ManualScanProgressEvent
from app.models.schemas import (
    ManualScanJobOut,
    ManualScanProgressEventOut,
    ManualScanProgressOut,
    ScanProgressUpdate,
    ScanRequest,
)
from app.repositories.store import (
    claim_manual_scan_job,
    create_manual_scan_job,
    get_active_manual_scan_job,
    get_latest_manual_scan_job,
    get_manual_scan_job,
    list_manual_scan_progress_events,
    mark_manual_scan_job_failed,
    mark_manual_scan_job_succeeded,
    record_manual_scan_progress,
)
from app.services.orchestrator import ScanOrchestrator

LOGGER = logging.getLogger(__name__)
INTERRUPTED_SCAN_MESSAGE = (
    "Scan runner restarted before this scan completed. The replacement worker will resume from "
    "the newest durable checkpoint."
)


def enqueue_manual_scan(session: Session, request: ScanRequest) -> tuple[ManualScanJob, bool]:
    """
    Persist a new manual scan request unless another manual scan is already in flight.

    Why this exists:
    A full scan can take long enough that multiple impatient clicks would otherwise spawn duplicate
    expensive runs. Reusing an already active job keeps the system predictable and the UI easier to
    understand.
    """

    active_job = get_active_manual_scan_job(session)
    if active_job is not None:
        return active_job, False

    job = create_manual_scan_job(session, request)
    record_manual_scan_progress(
        session,
        job_id=job.id,
        phase="queued",
        message="Scan wurde eingereiht und wartet auf den Scan-Worker.",
        level="info",
        current=0,
        total=0,
        percent=0.0,
    )
    return job, True


def get_manual_scan_job_out(session: Session, job_id: int) -> ManualScanJobOut | None:
    """Return one serialized manual scan job for REST responses."""

    job = get_manual_scan_job(session, job_id)
    if job is None:
        return None
    events = list_manual_scan_progress_events(session, job_id=job.id)
    return serialize_manual_scan_job(job, events)


def get_latest_manual_scan_job_out(session: Session) -> ManualScanJobOut | None:
    """Return the newest manual scan job or `None` when the queue is still empty."""

    job = get_latest_manual_scan_job(session)
    if job is None:
        return None
    events = list_manual_scan_progress_events(session, job_id=job.id)
    return serialize_manual_scan_job(job, events)


def recover_interrupted_manual_scan_jobs() -> int:
    """
    Leave interrupted running jobs available for the queue worker to resume.

    Why this exists:
    Scan orchestration state lives in memory while durable scan outcomes live in PostgreSQL. Once a
    runner restarts, any row still marked `running` should stay visible and resumable; the next
    queue poll reclaims it after the short duplicate-run grace period.
    """

    LOGGER.info("Manual scan startup recovery keeps running jobs resumable")
    return 0


def process_manual_scan_job(job_id: int | None = None) -> ManualScanJobOut | None:
    """
    Claim and execute one queued manual scan job outside the request transaction.

    Why this exists:
    The API should acknowledge scan requests quickly, while the actual orchestration happens in a
    dedicated runner context that is independent from the original HTTP request.
    """

    claim_session = SessionLocal()
    claimed_job: ManualScanJob | None = None
    try:
        claimed_job = claim_manual_scan_job(claim_session, job_id=job_id)
        if claimed_job is None:
            claim_session.commit()
            return None
        request = ScanRequest(
            repository_full_name=claimed_job.repository_full_name,
            include_archived=claimed_job.include_archived,
            force=claimed_job.force,
        )
        claimed_job_id = claimed_job.id
        claimed_job_started_at = claimed_job.started_at
        claim_session.commit()
    except Exception:
        claim_session.rollback()
        LOGGER.exception("Failed to claim queued manual scan job", extra={"job_id": job_id})
        raise
    finally:
        claim_session.close()

    _persist_manual_scan_progress(
        claimed_job_id,
        ScanProgressUpdate(
            phase="starting",
            message="Scan-Worker hat den Auftrag übernommen.",
            current=0,
            total=0,
            percent=1.0,
        ),
    )

    work_session = SessionLocal()
    try:
        response = ScanOrchestrator().run_manual_scan(
            work_session,
            request,
            job_id=claimed_job_id,
            resume_started_at=claimed_job_started_at,
            progress_callback=lambda update: _persist_manual_scan_progress(
                claimed_job_id,
                update,
            ),
        )
    except Exception as error:
        work_session.rollback()
        LOGGER.exception(
            "Manual scan job failed during execution",
            extra={"job_id": claimed_job_id},
        )
        failure_session = SessionLocal()
        try:
            error_message = _format_manual_scan_error(error)
            failed_job = mark_manual_scan_job_failed(
                failure_session,
                job_id=claimed_job_id,
                error_message=error_message,
            )
            previous_events = list_manual_scan_progress_events(
                failure_session,
                job_id=claimed_job_id,
                limit=1,
            )
            previous_event = previous_events[-1] if previous_events else None
            record_manual_scan_progress(
                failure_session,
                job_id=claimed_job_id,
                phase="failed",
                message="Scan ist fehlgeschlagen. Details stehen im Fehlerstatus.",
                level="error",
                current=previous_event.current if previous_event else 0,
                total=previous_event.total if previous_event else 0,
                percent=previous_event.percent if previous_event else 0.0,
            )
            failure_session.commit()
            events = list_manual_scan_progress_events(failure_session, job_id=claimed_job_id)
            return serialize_manual_scan_job(failed_job, events) if failed_job else None
        finally:
            failure_session.close()
    finally:
        work_session.close()

    finish_session = SessionLocal()
    try:
        finished_job = mark_manual_scan_job_succeeded(
            finish_session,
            job_id=claimed_job_id,
            response=response,
        )
        record_manual_scan_progress(
            finish_session,
            job_id=claimed_job_id,
            phase="completed",
            message=(
                f"Scan abgeschlossen: {response.repository_count} Systeme verarbeitet, "
                f"{response.alert_count} Alerts aktualisiert."
            ),
            level="warning" if response.failed_system_count else "info",
            current=response.repository_count,
            total=response.repository_count,
            percent=100.0,
        )
        finish_session.commit()
        events = list_manual_scan_progress_events(finish_session, job_id=claimed_job_id)
        return serialize_manual_scan_job(finished_job, events) if finished_job else None
    finally:
        finish_session.close()


def serialize_manual_scan_job(
    job: ManualScanJob,
    events: list[ManualScanProgressEvent] | None = None,
) -> ManualScanJobOut:
    """Convert one ORM job row into the stable API contract consumed by the dashboard."""

    progress = _build_manual_scan_progress(job, events or [])

    return ManualScanJobOut(
        id=job.id,
        status=job.status,
        message=_build_manual_scan_message(job, progress),
        repository_full_name=job.repository_full_name,
        include_archived=job.include_archived,
        force=job.force,
        requested_at=job.requested_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        repository_count=job.repository_count,
        alert_count=job.alert_count,
        failed_system_count=job.failed_system_count,
        error_message=job.error_message,
        progress=progress,
    )


def _build_manual_scan_progress(
    job: ManualScanJob,
    events: list[ManualScanProgressEvent],
) -> ManualScanProgressOut:
    """Build a current snapshot while remaining compatible with jobs created before this feature."""

    event_outputs = [
        ManualScanProgressEventOut(
            phase=event.phase,
            message=event.message,
            level=event.level,
            current=event.current,
            total=event.total,
            percent=event.percent,
            created_at=event.created_at,
        )
        for event in events
    ]
    if event_outputs:
        latest = event_outputs[-1]
        return ManualScanProgressOut(
            phase=latest.phase,
            message=latest.message,
            current=latest.current,
            total=latest.total,
            percent=latest.percent,
            events=event_outputs,
        )

    fallback_percent = 100.0 if job.status == ManualScanJobStatus.SUCCEEDED.value else 0.0
    fallback_phase = job.status if job.status else ManualScanJobStatus.QUEUED.value
    return ManualScanProgressOut(
        phase=fallback_phase,
        message="Für diesen älteren Scan sind keine Fortschrittsereignisse gespeichert.",
        current=job.repository_count,
        total=job.repository_count,
        percent=fallback_percent,
        events=[],
    )


def _build_manual_scan_message(job: ManualScanJob, progress: ManualScanProgressOut) -> str:
    """Return a user-facing summary that explains the current scan state without extra lookups."""

    scope = job.repository_full_name or "gesamte Plattform"
    if job.status == ManualScanJobStatus.QUEUED.value:
        return f"Scan für {scope} ist eingereiht und wartet auf Verarbeitung."
    if job.status == ManualScanJobStatus.RUNNING.value:
        return progress.message
    if job.status == ManualScanJobStatus.FAILED.value:
        return job.error_message or f"Scan für {scope} ist fehlgeschlagen."
    if job.failed_system_count:
        return (
            f"Scan für {scope} abgeschlossen mit Warnungen: {job.failed_system_count} Systeme "
            "konnten nicht vollständig verarbeitet werden."
        )
    return (
        f"Scan für {scope} abgeschlossen: {job.repository_count} Systeme verarbeitet und "
        f"{job.alert_count} Alerts aktualisiert."
    )


def _persist_manual_scan_progress(job_id: int, update: ScanProgressUpdate) -> None:
    """Commit one short progress transaction without holding up or failing the main scan."""

    progress_session = SessionLocal()
    try:
        record_manual_scan_progress(
            progress_session,
            job_id=job_id,
            phase=update.phase,
            message=update.message,
            level=update.level,
            current=update.current,
            total=update.total,
            percent=update.percent,
        )
        progress_session.commit()
    except Exception:
        progress_session.rollback()
        LOGGER.exception(
            "Failed to persist manual scan progress",
            extra={"job_id": job_id, "progress_phase": update.phase},
        )
    finally:
        progress_session.close()


def _format_manual_scan_error(error: Exception) -> str:
    """Build a compact but actionable failure message for operators and logs."""

    error_name = type(error).__name__
    error_message = str(error).strip()
    if not error_message:
        return f"{error_name}: Scan job aborted without a detailed error message."
    return f"{error_name}: {error_message}"
