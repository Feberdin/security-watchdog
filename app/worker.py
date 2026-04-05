"""
Purpose: Background worker entry point that runs APScheduler jobs inside Docker.
Input/Output: Starts recurring jobs for repo scans, feed polling, and AI extraction.
Important invariants: The worker should share the same logging and DB initialization as the API;
all scan jobs run inside this long-lived process, not inside request handlers.
Debugging: If scheduled work is missing, start by checking this process and the job registrations.
"""

from __future__ import annotations

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import initialize_database
from app.scheduler.jobs import build_scheduler


def main() -> None:
    """Initialize runtime state and block forever in the scheduler loop."""

    settings = get_settings()
    configure_logging(settings.log_level)
    initialize_database()
    scheduler = build_scheduler()
    scheduler.start()


if __name__ == "__main__":
    main()
