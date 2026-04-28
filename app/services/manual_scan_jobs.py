"""
Purpose: Queue, execute, and serialize manual scan jobs independently from HTTP request lifetimes.
Input/Output: Accepts `ScanRequest` objects, persists durable queue rows, and returns API-friendly
scan-job snapshots that the dashboard can poll.
Important invariants: Only one manual scan should actively run at a time; job claims must be
idempotent so API fallback processing and the worker never execute the same scan twice.
Debugging: If a scan seems stuck, inspect `manual_scan_jobs.status`, `started_at`,
`completed_at`, and `error_message` first to see whether the job is queued, running, or failed.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.entities import ManualScanJob, ManualScanJobStatus
from app.models.schemas import ManualScanJobOut, ScanRequest
from app.repositories.store import (
    claim_manual_scan_job,
    create_manual_scan_job,
    get_active_manual_scan_job,
    get_latest_manual_scan_job,
    get_manual_scan_job,
    mark_manual_scan_job_failed,
    mark_manual_scan_job_succeeded,
)
from app.services.orchestrator import ScanOrchestrator

LOGGER = logging.getLogger(__name__)


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

    return create_manual_scan_job(session, request), True


def get_manual_scan_job_out(session: Session, job_id: int) -> ManualScanJobOut | None:
    """Return one serialized manual scan job for REST responses."""

    job = get_manual_scan_job(session, job_id)
    if job is None:
        return None
    return serialize_manual_scan_job(job)


def get_latest_manual_scan_job_out(session: Session) -> ManualScanJobOut | None:
    """Return the newest manual scan job or `None` when the queue is still empty."""

    job = get_latest_manual_scan_job(session)
    if job is None:
        return None
    return serialize_manual_scan_job(job)


def process_manual_scan_job(job_id: int | None = None) -> ManualScanJobOut | None:
    """
    Claim and execute one queued manual scan job outside the request transaction.

    Why this exists:
    The API should acknowledge scan requests quickly, while the actual orchestration happens in a
    dedicated job context that survives much longer than the original HTTP request.
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
        claim_session.commit()
    except Exception:
        claim_session.rollback()
        LOGGER.exception("Failed to claim queued manual scan job", extra={"job_id": job_id})
        raise
    finally:
        claim_session.close()

    work_session = SessionLocal()
    try:
        response = ScanOrchestrator().run_manual_scan(work_session, request)
    except Exception as error:  # noqa: BLE001
        work_session.rollback()
        LOGGER.exception(
            "Manual scan job failed during execution",
            extra={"job_id": claimed_job_id},
        )
        failure_session = SessionLocal()
        try:
            failed_job = mark_manual_scan_job_failed(
                failure_session,
                job_id=claimed_job_id,
                error_message=_format_manual_scan_error(error),
            )
            failure_session.commit()
            return serialize_manual_scan_job(failed_job) if failed_job else None
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
        finish_session.commit()
        return serialize_manual_scan_job(finished_job) if finished_job else None
    finally:
        finish_session.close()


def serialize_manual_scan_job(job: ManualScanJob) -> ManualScanJobOut:
    """Convert one ORM job row into the stable API contract consumed by the dashboard."""

    return ManualScanJobOut(
        id=job.id,
        status=job.status,
        message=_build_manual_scan_message(job),
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
    )


def _build_manual_scan_message(job: ManualScanJob) -> str:
    """Return a user-facing summary that explains the current scan state without extra lookups."""

    scope = job.repository_full_name or "gesamte Plattform"
    if job.status == ManualScanJobStatus.QUEUED.value:
        return f"Scan für {scope} ist eingereiht und wartet auf Verarbeitung."
    if job.status == ManualScanJobStatus.RUNNING.value:
        return f"Scan für {scope} läuft gerade."
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


def _format_manual_scan_error(error: Exception) -> str:
    """Build a compact but actionable failure message for operators and logs."""

    error_name = type(error).__name__
    error_message = str(error).strip()
    if not error_message:
        return f"{error_name}: Scan job aborted without a detailed error message."
    return f"{error_name}: {error_message}"
