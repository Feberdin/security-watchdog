"""
Purpose: FastAPI application entry point for the self-hosted security-watchdog API and dashboard.
Input/Output: Starts the web application, initializes logging/DB state, and mounts routes/static
assets for browsers and automation clients.
Important invariants: Logging and database initialization must happen exactly once at startup; route
modules stay thin so worker jobs and API triggers share the same orchestration logic.
Debugging: If the web service starts but endpoints fail, inspect startup logs and `/health` first.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as api_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import initialize_database
from app.dashboard.router import router as dashboard_router
from app.scheduler.jobs import build_background_scheduler

settings = get_settings()
configure_logging(settings.log_level)

app = FastAPI(title="security-watchdog", version="0.1.0")
app.include_router(api_router)
app.include_router(dashboard_router)
app.mount(
    "/static",
    StaticFiles(directory=str(Path(__file__).resolve().parent / "static")),
    name="static",
)
embedded_scheduler = None


@app.on_event("startup")
def startup() -> None:
    """Initialize database tables on application startup."""

    global embedded_scheduler
    initialize_database()
    if settings.run_embedded_scheduler and embedded_scheduler is None:
        embedded_scheduler = build_background_scheduler()
        embedded_scheduler.start()


@app.on_event("shutdown")
def shutdown() -> None:
    """Stop the embedded scheduler cleanly if it was started in this process."""

    global embedded_scheduler
    if embedded_scheduler is not None:
        embedded_scheduler.shutdown(wait=False)
        embedded_scheduler = None
