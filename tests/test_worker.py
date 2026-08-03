"""
Purpose: Verify that the durable worker repairs interrupted scan state before polling the queue.
Input/Output: Replaces startup collaborators with in-memory fakes and records their call order.
Important invariants: Database initialization must precede recovery, and recovery must precede the
scheduler start so orphaned `running` rows cannot block the first queue poll.
Debugging: If deployments leave manual scans stuck after a worker restart, run this test and inspect
`app/worker.py` plus the recovery log entry.
"""

from __future__ import annotations

from app import worker


def test_worker_recovers_interrupted_jobs_before_starting_scheduler(monkeypatch) -> None:
    """Worker startup should repair the queue before any scheduled job can execute."""

    events: list[str] = []

    class FakeSettings:
        """Provide only the non-sensitive setting used during worker startup."""

        log_level = "INFO"

    class FakeScheduler:
        """Record scheduler startup without entering the blocking production loop."""

        def start(self) -> None:
            events.append("scheduler_started")

    monkeypatch.setattr(worker, "get_settings", lambda: FakeSettings())
    monkeypatch.setattr(worker, "configure_logging", lambda _level: events.append("logging_configured"))
    monkeypatch.setattr(worker, "initialize_database", lambda: events.append("database_initialized"))
    monkeypatch.setattr(
        worker,
        "recover_interrupted_manual_scan_jobs",
        lambda: events.append("interrupted_jobs_recovered"),
    )
    monkeypatch.setattr(worker, "build_scheduler", lambda: FakeScheduler())

    worker.main()

    assert events == [
        "logging_configured",
        "database_initialized",
        "interrupted_jobs_recovered",
        "scheduler_started",
    ]
