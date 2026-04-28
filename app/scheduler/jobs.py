"""
Purpose: Register APScheduler jobs for periodic scans, feed collection, and AI analysis.
Input/Output: Builds a configured scheduler instance for the worker entry point.
Important invariants: Each job opens its own DB session to avoid stale transactions; job intervals
come from configuration so operators can slow down or accelerate polling without code changes.
Debugging: If a job fails silently, inspect worker logs for the wrapped exception handling here.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import BaseScheduler
from apscheduler.schedulers.blocking import BlockingScheduler

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models.schemas import ScanRequest
from app.services.cache import RedisStateStore
from app.services.manual_scan_jobs import process_manual_scan_job
from app.services.orchestrator import ScanOrchestrator

LOGGER = logging.getLogger(__name__)


def register_jobs(scheduler: BaseScheduler) -> BaseScheduler:
    """Attach all recurring jobs to a scheduler implementation."""

    settings = get_settings()
    orchestrator = ScanOrchestrator()
    state_store = RedisStateStore()

    def repo_scan_job() -> None:
        try:
            with SessionLocal() as session:
                orchestrator.run_manual_scan(
                    session,
                    ScanRequest(repository_full_name=None, include_archived=False, force=False),
                )
                session.commit()
        except Exception:
            LOGGER.exception("Scheduled repository scan failed")
            raise
        state_store.set_job_heartbeat("repo_scan")

    def threat_feed_job() -> None:
        try:
            with SessionLocal() as session:
                orchestrator.collect_threat_intelligence(session)
                session.commit()
        except Exception:
            LOGGER.exception("Scheduled threat-feed collection failed")
            raise
        state_store.set_job_heartbeat("threat_feed")

    def ai_analysis_job() -> None:
        try:
            with SessionLocal() as session:
                orchestrator.run_ai_analysis(session)
                session.commit()
        except Exception:
            LOGGER.exception("Scheduled AI analysis failed")
            raise
        state_store.set_job_heartbeat("ai_analysis")

    def manual_scan_queue_job() -> None:
        try:
            queued_job = process_manual_scan_job()
            if queued_job is not None:
                LOGGER.info(
                    "Processed queued manual scan job",
                    extra={"job_id": queued_job.id, "status": queued_job.status},
                )
        except Exception:
            LOGGER.exception("Queued manual scan processing failed")
            raise

    scheduler.add_job(
        repo_scan_job,
        "interval",
        hours=settings.scan_schedule_hours,
        id="repo_scan",
        next_run_time=_initial_next_run_time("repo_scan", hours=settings.scan_schedule_hours, state_store=state_store),
        coalesce=True,
        max_instances=1,
        misfire_grace_time=3600,
    )
    scheduler.add_job(
        threat_feed_job,
        "interval",
        hours=settings.feed_schedule_hours,
        id="threat_feed",
        next_run_time=_initial_next_run_time(
            "threat_feed",
            hours=settings.feed_schedule_hours,
            state_store=state_store,
        ),
        coalesce=True,
        max_instances=1,
        misfire_grace_time=3600,
    )
    scheduler.add_job(
        ai_analysis_job,
        "interval",
        days=settings.ai_schedule_days,
        id="ai_analysis",
        next_run_time=_initial_next_run_time(
            "ai_analysis",
            days=settings.ai_schedule_days,
            state_store=state_store,
        ),
        coalesce=True,
        max_instances=1,
        misfire_grace_time=86400,
    )
    scheduler.add_job(
        manual_scan_queue_job,
        "interval",
        seconds=settings.manual_scan_poll_seconds,
        id="manual_scan_queue",
        next_run_time=datetime.now(UTC),
        coalesce=True,
        max_instances=1,
        misfire_grace_time=max(settings.manual_scan_poll_seconds * 2, 30),
    )
    return scheduler


def build_scheduler() -> BlockingScheduler:
    """Create and register the recurring jobs for the worker process."""

    return register_jobs(BlockingScheduler(timezone="UTC"))  # type: ignore[return-value]


def build_background_scheduler() -> BackgroundScheduler:
    """Create a background scheduler for single-container deployments."""

    return register_jobs(BackgroundScheduler(timezone="UTC"))  # type: ignore[return-value]


def _initial_next_run_time(
    job_name: str,
    *,
    state_store: RedisStateStore,
    hours: int = 0,
    days: int = 0,
) -> datetime:
    """
    Decide whether a recurring job should run immediately after startup.

    Why this exists:
    In single-container setups the embedded scheduler restarts with the web service. If the next run
    is always scheduled strictly `interval` hours from startup, a missed day can stay missed until
    the following interval. We instead run immediately when the last heartbeat is absent or overdue.
    """

    now = datetime.now(UTC)
    heartbeat = state_store.get_job_heartbeat(job_name)
    interval = timedelta(hours=hours, days=days)
    if heartbeat is None:
        return now
    if heartbeat.tzinfo is None:
        heartbeat = heartbeat.replace(tzinfo=UTC)
    if heartbeat + interval <= now:
        return now
    return heartbeat + interval
