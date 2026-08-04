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
    DEFAULT_SCAN_SOURCES,
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
    get_matching_queued_manual_scan_job,
    get_running_manual_scan_job,
    is_manual_scan_cancel_requested,
    is_manual_scan_pause_requested,
    list_manual_scan_progress_events,
    mark_manual_scan_job_canceled,
    mark_manual_scan_job_failed,
    mark_manual_scan_job_paused,
    mark_manual_scan_job_succeeded,
    record_manual_scan_progress,
    request_manual_scan_cancel,
    request_manual_scan_pause,
    resume_manual_scan_job,
)
from app.services.orchestrator import ScanOrchestrator
from app.services.scan_control import ScanCanceledError, ScanPausedError

LOGGER = logging.getLogger(__name__)
INTERRUPTED_SCAN_MESSAGE = (
    "Scan runner restarted before this scan completed. The replacement worker will resume from "
    "the newest durable checkpoint."
)
AUTO_PRIORITY_FULL_SCAN = 0
AUTO_PRIORITY_REPOSITORY_SCAN = 60
AUTO_PRIORITY_GITHUB_ONLY = 25
AUTO_PRIORITY_PRE_DEPLOY = 100


def enqueue_manual_scan(session: Session, request: ScanRequest) -> tuple[ManualScanJob, bool]:
    """
    Persist a new manual scan request unless another manual scan is already in flight.

    Why this exists:
    A full scan can take long enough that multiple impatient clicks would otherwise spawn duplicate
    expensive runs. Reusing an already active job keeps the system predictable and the UI easier to
    understand.
    """

    request = request.model_copy(update={"priority": _resolve_auto_priority(request)})

    duplicate_job = get_matching_queued_manual_scan_job(session, request)
    if duplicate_job is not None:
        return duplicate_job, False

    active_job = get_active_manual_scan_job(session)
    should_queue_behind_active = (
        active_job is not None and _should_queue_behind_active_scan(active_job, request)
    )

    if active_job is not None and not should_queue_behind_active:
        return active_job, False

    active_priority = active_job.priority if active_job is not None else 0
    auto_pause_when_queued = should_queue_behind_active and request.priority > active_priority

    if should_queue_behind_active and (request.pause_active or auto_pause_when_queued):
        running_job = get_running_manual_scan_job(session)
        if running_job is not None:
            request_manual_scan_pause(session, job_id=running_job.id)
            record_manual_scan_progress(
                session,
                job_id=running_job.id,
                phase="pausing",
                message="Pause angefordert. Der Worker stoppt nach dem aktuellen sicheren Schritt.",
                level="warning",
                current=running_job.repository_count,
                total=running_job.repository_count,
                percent=0.0,
            )

    job = create_manual_scan_job(session, request)
    record_manual_scan_progress(
        session,
        job_id=job.id,
        phase="queued",
        message=_build_queued_message(job),
        level="info",
        current=0,
        total=0,
        percent=0.0,
    )
    return job, True


def pause_manual_scan_job(session: Session, job_id: int) -> ManualScanJobOut | None:
    """Request pause for one queued or running manual scan and return its visible state."""

    job = request_manual_scan_pause(session, job_id=job_id)
    if job is None:
        return None

    if job.status == ManualScanJobStatus.PAUSED.value:
        record_manual_scan_progress(
            session,
            job_id=job.id,
            phase="paused",
            message="Scan wurde vor dem Start pausiert.",
            level="warning",
            current=job.repository_count,
            total=job.repository_count,
            percent=0.0,
        )
    elif job.pause_requested:
        previous_events = list_manual_scan_progress_events(session, job_id=job.id, limit=1)
        previous_event = previous_events[-1] if previous_events else None
        record_manual_scan_progress(
            session,
            job_id=job.id,
            phase="pausing",
            message="Pause angefordert. Der Worker stoppt nach dem aktuellen sicheren Schritt.",
            level="warning",
            current=previous_event.current if previous_event else job.repository_count,
            total=previous_event.total if previous_event else job.repository_count,
            percent=previous_event.percent if previous_event else 0.0,
        )

    events = list_manual_scan_progress_events(session, job_id=job.id)
    return serialize_manual_scan_job(job, events)


def resume_paused_manual_scan_job(session: Session, job_id: int) -> ManualScanJobOut | None:
    """Return one paused scan to the queue so the worker can continue it later."""

    job = resume_manual_scan_job(session, job_id=job_id)
    if job is None:
        return None
    record_manual_scan_progress(
        session,
        job_id=job.id,
        phase="queued",
        message="Pausierter Scan wurde wieder eingereiht.",
        level="info",
        current=job.repository_count,
        total=job.repository_count,
        percent=0.0,
    )
    events = list_manual_scan_progress_events(session, job_id=job.id)
    return serialize_manual_scan_job(job, events)


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


def cancel_manual_scan_job(session: Session, job_id: int) -> ManualScanJobOut | None:
    """Request cancellation for one queued or running manual scan and return its visible state."""

    job = request_manual_scan_cancel(session, job_id=job_id)
    if job is None:
        return None

    if job.status == ManualScanJobStatus.CANCELED.value:
        record_manual_scan_progress(
            session,
            job_id=job.id,
            phase="canceled",
            message="Scan wurde vor dem Start abgebrochen.",
            level="warning",
            current=job.repository_count,
            total=job.repository_count,
            percent=100.0,
        )
    elif job.cancel_requested:
        previous_events = list_manual_scan_progress_events(session, job_id=job.id, limit=1)
        previous_event = previous_events[-1] if previous_events else None
        record_manual_scan_progress(
            session,
            job_id=job.id,
            phase="canceling",
            message="Abbruch angefordert. Der Worker stoppt nach dem aktuellen sicheren Schritt.",
            level="warning",
            current=previous_event.current if previous_event else job.repository_count,
            total=previous_event.total if previous_event else job.repository_count,
            percent=previous_event.percent if previous_event else 0.0,
        )

    events = list_manual_scan_progress_events(session, job_id=job.id)
    return serialize_manual_scan_job(job, events)


def _should_queue_behind_active_scan(active_job: ManualScanJob, request: ScanRequest) -> bool:
    """
    Decide whether a request should become a new queued job instead of reusing the active one.

    Why this exists:
    A full estate scan is expensive and should still be de-duplicated. Targeted pre-deploy or
    repository scans are operator intent with smaller scope, so they need to wait in priority order
    instead of being hidden behind an unrelated running job.
    """

    if request.purpose == "pre_deploy":
        return True
    if request.repository_full_name and request.repository_full_name != active_job.repository_full_name:
        return True
    return request.priority > active_job.priority


def _resolve_auto_priority(request: ScanRequest) -> int:
    """Determine a deterministic default priority when clients do not set one explicitly."""

    if request.priority:
        return request.priority

    if request.purpose == "pre_deploy":
        return AUTO_PRIORITY_PRE_DEPLOY

    if request.repository_full_name is not None:
        return AUTO_PRIORITY_REPOSITORY_SCAN

    if request.scan_sources == ["github"]:
        return AUTO_PRIORITY_GITHUB_ONLY

    return AUTO_PRIORITY_FULL_SCAN


def _build_queued_message(job: ManualScanJob) -> str:
    """Return a short queue message that surfaces priority and pre-deploy intent."""

    scope = job.repository_full_name or "gesamte Plattform"
    if job.purpose == "pre_deploy":
        return f"Pre-Deploy-Scan für {scope} wurde mit hoher Priorität eingereiht."
    if job.priority:
        return f"Scan für {scope} wurde mit Priorität {job.priority} eingereiht."
    return "Scan wurde eingereiht und wartet auf den Scan-Worker."


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
            scan_sources=claimed_job.scan_sources_json or list(DEFAULT_SCAN_SOURCES),
            priority=claimed_job.priority,
            purpose=claimed_job.purpose,
            target_commit_sha=claimed_job.target_commit_sha,
            refresh_image_cache=claimed_job.refresh_image_cache,
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
            cancellation_check=lambda: _raise_if_manual_scan_stopped(claimed_job_id),
        )
    except ScanCanceledError:
        work_session.rollback()
        LOGGER.info("Manual scan job was canceled by operator", extra={"job_id": claimed_job_id})
        cancel_session = SessionLocal()
        try:
            canceled_job = mark_manual_scan_job_canceled(cancel_session, job_id=claimed_job_id)
            previous_events = list_manual_scan_progress_events(
                cancel_session,
                job_id=claimed_job_id,
                limit=1,
            )
            previous_event = previous_events[-1] if previous_events else None
            record_manual_scan_progress(
                cancel_session,
                job_id=claimed_job_id,
                phase="canceled",
                message="Scan wurde abgebrochen. Bereits gespeicherte Teilergebnisse bleiben erhalten.",
                level="warning",
                current=previous_event.current if previous_event else 0,
                total=previous_event.total if previous_event else 0,
                percent=previous_event.percent if previous_event else 0.0,
            )
            cancel_session.commit()
            events = list_manual_scan_progress_events(cancel_session, job_id=claimed_job_id)
            return serialize_manual_scan_job(canceled_job, events) if canceled_job else None
        finally:
            cancel_session.close()
    except ScanPausedError:
        work_session.rollback()
        LOGGER.info("Manual scan job was paused by operator", extra={"job_id": claimed_job_id})
        pause_session = SessionLocal()
        try:
            paused_job = mark_manual_scan_job_paused(pause_session, job_id=claimed_job_id)
            previous_events = list_manual_scan_progress_events(
                pause_session,
                job_id=claimed_job_id,
                limit=1,
            )
            previous_event = previous_events[-1] if previous_events else None
            record_manual_scan_progress(
                pause_session,
                job_id=claimed_job_id,
                phase="paused",
                message="Scan wurde pausiert. Bereits gespeicherte Teilergebnisse bleiben erhalten.",
                level="warning",
                current=previous_event.current if previous_event else 0,
                total=previous_event.total if previous_event else 0,
                percent=previous_event.percent if previous_event else 0.0,
            )
            pause_session.commit()
            events = list_manual_scan_progress_events(pause_session, job_id=claimed_job_id)
            return serialize_manual_scan_job(paused_job, events) if paused_job else None
        finally:
            pause_session.close()
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
        scan_sources=job.scan_sources_json or list(DEFAULT_SCAN_SOURCES),
        cancel_requested=job.cancel_requested,
        pause_requested=job.pause_requested,
        priority=job.priority,
        purpose=job.purpose,
        target_commit_sha=job.target_commit_sha,
        refresh_image_cache=job.refresh_image_cache,
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
    if job.status == ManualScanJobStatus.PAUSED.value:
        return f"Scan für {scope} ist pausiert und kann später fortgesetzt werden."
    if job.status == ManualScanJobStatus.FAILED.value:
        return job.error_message or f"Scan für {scope} ist fehlgeschlagen."
    if job.status == ManualScanJobStatus.CANCELED.value:
        return f"Scan für {scope} wurde abgebrochen."
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


def _raise_if_manual_scan_stopped(job_id: int) -> None:
    """Raise a typed lifecycle exception when the durable job row requests stop or pause."""

    control_session = SessionLocal()
    try:
        if is_manual_scan_cancel_requested(control_session, job_id=job_id):
            raise ScanCanceledError(f"Manual scan job {job_id} was canceled by the operator.")
        if is_manual_scan_pause_requested(control_session, job_id=job_id):
            raise ScanPausedError(f"Manual scan job {job_id} was paused by the operator.")
    finally:
        control_session.close()


def _format_manual_scan_error(error: Exception) -> str:
    """Build a compact but actionable failure message for operators and logs."""

    error_name = type(error).__name__
    error_message = str(error).strip()
    if not error_message:
        return f"{error_name}: Scan job aborted without a detailed error message."
    return f"{error_name}: {error_message}"
