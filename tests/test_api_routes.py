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
from app.core.config import Settings, get_settings
from app.db.base import Base
from app.db.session import get_db_session


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


def test_post_scan_returns_accepted_and_leaves_job_queued_for_worker() -> None:
    """The API should persist work without tying scan execution to the request process."""

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

    client = TestClient(app)

    response = client.post("/scan", json={"include_archived": False, "force": True})
    payload = response.json()

    assert response.status_code == 202
    assert payload["job_id"] > 0
    assert payload["status"] == "queued"
    assert payload["message"] == "Manual scan accepted and queued for worker processing."
    assert payload["status_url"].endswith(f"/scan-jobs/{payload['job_id']}")

    latest_response = client.get("/scan-jobs/latest")
    latest_job = latest_response.json()

    assert latest_response.status_code == 200
    assert latest_job["id"] == payload["job_id"]
    assert latest_job["status"] == "queued"
    assert latest_job["repository_count"] == 0
    assert latest_job["alert_count"] == 0


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


def test_deployment_security_gate_requires_bearer_token_and_fails_closed() -> None:
    """The Broker endpoint must reject unauthenticated calls and unknown repositories."""

    session_factory = build_session_factory()
    gate_token = "test-only-deployment-gate-token"
    gate_settings = Settings(deployment_gate_token=gate_token)

    def override_db_session() -> Generator[Session, None, None]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_db_session] = override_db_session
    app.dependency_overrides[get_settings] = lambda: gate_settings
    client = TestClient(app)
    request_body = {
        "stack_name": "example",
        "repository_full_name": "Feberdin/example",
        "commit_sha": "a1" * 20,
        "compose_file": "docker-compose.yml",
    }

    missing_token_response = client.post(
        "/automation/deployment-security-gate",
        json=request_body,
    )
    invalid_token_response = client.post(
        "/automation/deployment-security-gate",
        headers={"Authorization": "Bearer invalid-token"},
        json=request_body,
    )
    valid_response = client.post(
        "/automation/deployment-security-gate",
        headers={"Authorization": f"Bearer {gate_token}"},
        json=request_body,
    )

    assert missing_token_response.status_code == 401
    assert invalid_token_response.status_code == 401
    assert valid_response.status_code == 200
    assert valid_response.json()["decision"] == "indeterminate"
    assert valid_response.json()["deploy_allowed"] is False
    assert valid_response.json()["reason_codes"] == ["REPOSITORY_NOT_SCANNED"]


def test_deployment_security_gate_is_unavailable_without_server_secret() -> None:
    """A missing server-side token must disable the endpoint instead of opening access."""

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
    app.dependency_overrides[get_settings] = lambda: Settings(deployment_gate_token="")

    response = TestClient(app).post(
        "/automation/deployment-security-gate",
        headers={"Authorization": "Bearer any-token"},
        json={
            "stack_name": "example",
            "repository_full_name": "Feberdin/example",
            "commit_sha": "a1" * 20,
        },
    )

    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]
