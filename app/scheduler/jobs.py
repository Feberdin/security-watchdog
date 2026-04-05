"""
Purpose: Register APScheduler jobs for periodic scans, feed collection, and AI analysis.
Input/Output: Builds a configured scheduler instance for the worker entry point.
Important invariants: Each job opens its own DB session to avoid stale transactions; job intervals
come from configuration so operators can slow down or accelerate polling without code changes.
Debugging: If a job fails silently, inspect worker logs for the wrapped exception handling here.
"""

from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import BaseScheduler
from apscheduler.schedulers.blocking import BlockingScheduler

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models.schemas import ScanRequest
from app.services.cache import RedisStateStore
from app.services.orchestrator import ScanOrchestrator

LOGGER = logging.getLogger(__name__)


def register_jobs(scheduler: BaseScheduler) -> BaseScheduler:
    """Attach all recurring jobs to a scheduler implementation."""

    settings = get_settings()
    orchestrator = ScanOrchestrator()
    state_store = RedisStateStore()

    def repo_scan_job() -> None:
        with SessionLocal() as session:
            orchestrator.run_manual_scan(
                session,
                ScanRequest(repository_full_name=None, include_archived=False, force=False),
            )
            session.commit()
            state_store.set_job_heartbeat("repo_scan")

    def threat_feed_job() -> None:
        with SessionLocal() as session:
            orchestrator.collect_threat_intelligence(session)
            session.commit()
            state_store.set_job_heartbeat("threat_feed")

    def ai_analysis_job() -> None:
        with SessionLocal() as session:
            orchestrator.run_ai_analysis(session)
            session.commit()
            state_store.set_job_heartbeat("ai_analysis")

    scheduler.add_job(repo_scan_job, "interval", hours=settings.scan_schedule_hours, id="repo_scan")
    scheduler.add_job(
        threat_feed_job,
        "interval",
        hours=settings.feed_schedule_hours,
        id="threat_feed",
    )
    scheduler.add_job(ai_analysis_job, "interval", days=settings.ai_schedule_days, id="ai_analysis")
    return scheduler


def build_scheduler() -> BlockingScheduler:
    """Create and register the recurring jobs for the worker process."""

    return register_jobs(BlockingScheduler(timezone="UTC"))  # type: ignore[return-value]


def build_background_scheduler() -> BackgroundScheduler:
    """Create a background scheduler for single-container deployments."""

    return register_jobs(BackgroundScheduler(timezone="UTC"))  # type: ignore[return-value]
