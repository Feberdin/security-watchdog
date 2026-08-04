"""
Purpose: Verify recurring scheduler jobs use the durable manual-scan queue.
Input/Output: Registers jobs against in-memory fakes and calls captured job functions directly.
Important invariants: Scheduled repository scans must be visible, cancellable queue jobs; they must
not run a second hidden orchestrator scan beside an operator-triggered manual scan.
Debugging: If deploy restarts cause invisible long scans, inspect `app/scheduler/jobs.py` first.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.models.schemas import ScanRequest
from app.scheduler import jobs


class FakeScheduler:
    """Capture APScheduler registrations without starting background threads."""

    def __init__(self) -> None:
        self.jobs_by_id: dict[str, Callable[[], None]] = {}

    def add_job(self, func: Callable[[], None], _trigger: str, **kwargs: Any) -> None:
        """Store jobs by id so tests can execute the closures deterministically."""

        self.jobs_by_id[str(kwargs["id"])] = func


class FakeSettings:
    """Provide only scheduler configuration values used during job registration."""

    scan_schedule_hours = 24
    feed_schedule_hours = 6
    ai_schedule_days = 30
    manual_scan_poll_seconds = 15


class FakeSession:
    """Minimal context-managed session fake for queue registration tests."""

    def __init__(self, events: list[str]) -> None:
        self.events = events

    def __enter__(self) -> FakeSession:
        self.events.append("session_opened")
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.events.append("session_closed")

    def commit(self) -> None:
        self.events.append("session_committed")


class FakeStateStore:
    """Record heartbeat reads and writes without contacting Redis."""

    def __init__(self) -> None:
        self.heartbeat_reads: list[str] = []
        self.heartbeat_writes: list[str] = []

    def get_job_heartbeat(self, job_name: str) -> None:
        """Return no heartbeat so registrations schedule their first run immediately."""

        self.heartbeat_reads.append(job_name)
        return None

    def set_job_heartbeat(self, job_name: str) -> None:
        """Record the heartbeat that production would persist in Redis."""

        self.heartbeat_writes.append(job_name)


class FakeQueuedJob:
    """Small job result returned by the queue worker fake."""

    def __init__(self, *, purpose: str, status: str) -> None:
        self.id = 42
        self.purpose = purpose
        self.status = status


def test_scheduled_repo_scan_is_enqueued_as_visible_manual_job(monkeypatch) -> None:
    """The recurring repo job should not run the scanner directly inside APScheduler."""

    events: list[str] = []
    queued_requests: list[ScanRequest] = []
    state_store = FakeStateStore()
    scheduler = FakeScheduler()

    def fake_session_local() -> FakeSession:
        return FakeSession(events)

    def fake_enqueue_manual_scan(_session: FakeSession, request: ScanRequest) -> tuple[FakeQueuedJob, bool]:
        queued_requests.append(request)
        return FakeQueuedJob(purpose=request.purpose, status="queued"), True

    monkeypatch.setattr(jobs, "get_settings", lambda: FakeSettings())
    monkeypatch.setattr(jobs, "RedisStateStore", lambda: state_store)
    monkeypatch.setattr(jobs, "SessionLocal", fake_session_local)
    monkeypatch.setattr(jobs, "enqueue_manual_scan", fake_enqueue_manual_scan)
    monkeypatch.setattr(jobs, "process_manual_scan_job", lambda: None)

    jobs.register_jobs(scheduler)
    scheduler.jobs_by_id["repo_scan"]()

    assert events == ["session_opened", "session_committed", "session_closed"]
    assert len(queued_requests) == 1
    assert queued_requests[0].purpose == "scheduled"
    assert queued_requests[0].repository_full_name is None
    assert queued_requests[0].scan_sources == ["github", "unraid", "homeassistant"]
    assert state_store.heartbeat_writes == []


def test_manual_queue_job_sets_repo_heartbeat_after_scheduled_success(monkeypatch) -> None:
    """The scheduler heartbeat should mean the queued scheduled scan actually succeeded."""

    state_store = FakeStateStore()
    scheduler = FakeScheduler()

    monkeypatch.setattr(jobs, "get_settings", lambda: FakeSettings())
    monkeypatch.setattr(jobs, "RedisStateStore", lambda: state_store)
    monkeypatch.setattr(jobs, "SessionLocal", lambda: FakeSession([]))
    monkeypatch.setattr(
        jobs,
        "enqueue_manual_scan",
        lambda _session, request: (FakeQueuedJob(purpose=request.purpose, status="queued"), True),
    )
    monkeypatch.setattr(
        jobs,
        "process_manual_scan_job",
        lambda: FakeQueuedJob(purpose="scheduled", status="succeeded"),
    )

    jobs.register_jobs(scheduler)
    scheduler.jobs_by_id["manual_scan_queue"]()

    assert state_store.heartbeat_writes == ["repo_scan"]


def test_manual_queue_job_does_not_set_repo_heartbeat_for_manual_success(monkeypatch) -> None:
    """Operator-triggered scans should not move the recurring scheduler heartbeat."""

    state_store = FakeStateStore()
    scheduler = FakeScheduler()

    monkeypatch.setattr(jobs, "get_settings", lambda: FakeSettings())
    monkeypatch.setattr(jobs, "RedisStateStore", lambda: state_store)
    monkeypatch.setattr(jobs, "SessionLocal", lambda: FakeSession([]))
    monkeypatch.setattr(
        jobs,
        "enqueue_manual_scan",
        lambda _session, request: (FakeQueuedJob(purpose=request.purpose, status="queued"), True),
    )
    monkeypatch.setattr(
        jobs,
        "process_manual_scan_job",
        lambda: FakeQueuedJob(purpose="manual", status="succeeded"),
    )

    jobs.register_jobs(scheduler)
    scheduler.jobs_by_id["manual_scan_queue"]()

    assert state_store.heartbeat_writes == []
