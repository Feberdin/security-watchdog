"""
Purpose: Protect the scan API contract for accepted background jobs and job-status lookups.
Input/Output: Spins up a small FastAPI app with an overridden test database and exercises the
manual scan endpoints through `TestClient`.
Important invariants: `POST /scan` must respond quickly with `202 Accepted`, and the dashboard must
be able to read the latest job status from the API.
Debugging: If the dashboard no longer shows progress after clicking the scan button, inspect these
route tests and `app/api/routes.py`.
"""

from __future__ import annotations

from collections.abc import Generator

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.models.entities  # noqa: F401
from app.api.routes import router as api_router
from app.db.base import Base
from app.db.session import get_db_session
from app.models.schemas import ScanRequest, ScanResponse
from app.services import manual_scan_jobs


def build_session_factory() -> sessionmaker[Session]:
    """Create a shared in-memory database suitable for route tests plus background tasks."""

    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)


def test_post_scan_returns_accepted_and_exposes_latest_job(monkeypatch) -> None:
    """The API should accept the request immediately and expose the resulting job state."""

    session_factory = build_session_factory()
    monkeypatch.setattr(manual_scan_jobs, "SessionLocal", session_factory)

    class FakeOrchestrator:
        """Deterministic stand-in so the route test does not hit real scanners."""

        def run_manual_scan(
            self,
            session: Session,
            request: ScanRequest,
            *,
            job_id: int | None = None,
            resume_started_at=None,
        ) -> ScanResponse:
            assert job_id is not None
            assert resume_started_at is not None
            return ScanResponse(
                message="Scan completed",
                repository_count=6,
                alert_count=11,
                failed_system_count=0,
            )

    monkeypatch.setattr(manual_scan_jobs, "ScanOrchestrator", FakeOrchestrator)

    def override_db_session() -> Generator[Session, None, None]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_db_session] = override_db_session

    client = TestClient(app)

    response = client.post("/scan", json={"include_archived": False, "force": True})
    payload = response.json()

    assert response.status_code == 202
    assert payload["job_id"] > 0
    assert payload["status"] == "queued"
    assert payload["status_url"].endswith(f"/scan-jobs/{payload['job_id']}")

    latest_response = client.get("/scan-jobs/latest")
    latest_job = latest_response.json()

    assert latest_response.status_code == 200
    assert latest_job["id"] == payload["job_id"]
    assert latest_job["status"] == "succeeded"
    assert latest_job["repository_count"] == 6
    assert latest_job["alert_count"] == 11


def test_daily_security_check_endpoint_returns_codex_runbook() -> None:
    """Codex automation should be able to fetch one JSON runbook without scraping dashboard HTML."""

    session_factory = build_session_factory()

    def override_db_session() -> Generator[Session, None, None]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_db_session] = override_db_session

    response = TestClient(app).get("/automation/daily-security-check?limit=5&max_tasks_per_run=2")
    payload = response.json()

    assert response.status_code == 200
    assert payload["api_version"] == "2026-07-30"
    assert payload["recommended_schedule"] == "daily"
    assert payload["max_tasks_per_run"] == 2
    assert payload["queue"]["task_count"] == 0
    assert payload["source_endpoints"]["runbook"] == "/automation/daily-security-check"
    assert "Do not update solely because a target version is higher" in payload["guardrails"][0]
    assert "daily Security Watchdog maintenance task" in payload["codex_prompt"]
