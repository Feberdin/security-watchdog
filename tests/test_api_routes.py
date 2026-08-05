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

import app.api.routes as api_routes
import app.models.entities  # noqa: F401
from app.api.routes import router as api_router
from app.core.config import Settings, get_settings
from app.db.base import Base
from app.db.session import get_db_session
from app.models.entities import Dependency, Repository
from app.services.reporting import ReportingService


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
    assert latest_job["scan_sources"] == ["github", "unraid", "homeassistant"]
    assert latest_job["progress"]["phase"] == "queued"
    assert latest_job["progress"]["percent"] == 0
    assert latest_job["progress"]["events"][0]["message"].startswith("Scan wurde eingereiht")


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


def test_grouped_remediation_prompt_endpoint_returns_codex_prompt() -> None:
    """The dashboard should be able to fetch the grouped full-scan remediation prompt."""

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

    response = TestClient(app).get("/automation/grouped-remediation/codex-prompt?limit=5")
    payload = response.json()

    assert response.status_code == 200
    assert payload["title"] == "Codex Grouped Security Watchdog Remediation"
    assert "grouped Security Watchdog remediation queue is currently empty" in payload["prompt"]


def test_systems_endpoint_skips_latest_version_lookup_by_default(monkeypatch) -> None:
    """Dashboard inventory must return from persisted data instead of blocking on registries."""

    class ExplodingVersionCatalog:
        """Fail if the route accidentally performs live latest-version lookups."""

        def resolve_latest_version(self, ecosystem: str, package_name: str) -> None:
            raise AssertionError(f"Unexpected registry lookup for {ecosystem}:{package_name}")

    class FastDashboardReportingService(ReportingService):
        """Inject the exploding catalog while keeping normal reporting behavior."""

        def __init__(self) -> None:
            super().__init__(version_catalog=ExplodingVersionCatalog())

    session_factory = build_session_factory()
    with session_factory() as session:
        repository = Repository(
            source_type="github",
            owner="Feberdin",
            name="security-watchdog",
            full_name="Feberdin/security-watchdog",
            local_path="/tmp/security-watchdog",
            risk_score=10.0,
        )
        session.add(repository)
        session.flush()
        session.add(
            Dependency(
                repository_id=repository.id,
                manifest_path="pyproject.toml",
                package_name="fastapi",
                version="0.115.0",
                ecosystem="pypi",
            )
        )
        session.commit()

    def override_db_session() -> Generator[Session, None, None]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    monkeypatch.setattr(api_routes, "ReportingService", FastDashboardReportingService)

    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_db_session] = override_db_session
    response = TestClient(app).get("/systems")
    payload = response.json()

    assert response.status_code == 200
    assert payload[0]["full_name"] == "Feberdin/security-watchdog"
    assert payload[0]["dependencies"][0]["latest_version"] is None
    assert payload[0]["dependencies"][0]["latest_version_status"] == "skipped"


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


def test_post_scan_accepts_targeted_scan_sources() -> None:
    """Operators should be able to queue one source-specific scan instead of a full estate run."""

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

    response = client.post(
        "/scan",
        json={
            "repository_full_name": "Feberdin/security-watchdog",
            "include_archived": False,
            "force": True,
            "scan_sources": ["github"],
        },
    )
    payload = response.json()
    latest_job = client.get("/scan-jobs/latest").json()

    assert response.status_code == 202
    assert payload["status"] == "queued"
    assert latest_job["repository_full_name"] == "Feberdin/security-watchdog"
    assert latest_job["scan_sources"] == ["github"]


def test_cancel_scan_endpoint_marks_queued_job_canceled() -> None:
    """The API should expose a clear cancellation route for queued or running manual scans."""

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

    scan_response = client.post("/scan", json={"include_archived": False, "force": True})
    job_id = scan_response.json()["job_id"]
    cancel_response = client.post(f"/scan-jobs/{job_id}/cancel")
    payload = cancel_response.json()

    assert cancel_response.status_code == 200
    assert payload["id"] == job_id
    assert payload["status"] == "canceled"
    assert payload["cancel_requested"] is True
    assert payload["progress"]["phase"] == "canceled"


def test_pause_and_resume_scan_endpoints_requeue_job() -> None:
    """The API should expose pause and resume controls for dashboard scan management."""

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

    scan_response = client.post("/scan", json={"include_archived": False, "force": True})
    job_id = scan_response.json()["job_id"]
    pause_response = client.post(f"/scan-jobs/{job_id}/pause")
    resume_response = client.post(f"/scan-jobs/{job_id}/resume")
    latest_job = client.get("/scan-jobs/latest").json()

    assert pause_response.status_code == 200
    assert pause_response.json()["status"] == "paused"
    assert pause_response.json()["pause_requested"] is True
    assert resume_response.status_code == 200
    assert resume_response.json()["status"] == "queued"
    assert resume_response.json()["pause_requested"] is False
    assert latest_job["status"] == "queued"


def test_pre_deploy_scan_endpoint_queues_high_priority_commit_bound_job() -> None:
    """The dashboard should be able to queue exact-commit scan evidence before a deployment."""

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
    commit_sha = "b" * 40

    response = client.post(
        "/automation/pre-deploy-scan",
        json={
            "stack_name": "security-watchdog",
            "repository_full_name": "Feberdin/security-watchdog",
            "commit_sha": commit_sha,
            "compose_file": "docker-compose.yml",
        },
    )
    latest_job = client.get("/scan-jobs/latest").json()

    assert response.status_code == 202
    assert latest_job["status"] == "queued"
    assert latest_job["repository_full_name"] == "Feberdin/security-watchdog"
    assert latest_job["scan_sources"] == ["github"]
    assert latest_job["priority"] == 100
    assert latest_job["purpose"] == "pre_deploy"
    assert latest_job["target_commit_sha"] == commit_sha
    assert latest_job["scanned_commit_sha"] is None


def test_gate_status_endpoint_is_dashboard_safe_without_bearer_token() -> None:
    """The dashboard can ask for gate evidence without receiving or sending the Broker secret."""

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

    response = client.get(
        "/automation/deployment-security-gate/status",
        params={
            "stack_name": "security-watchdog",
            "repository_full_name": "Feberdin/security-watchdog",
            "commit_sha": "c" * 40,
            "compose_file": "docker-compose.yml",
        },
    )
    payload = response.json()

    assert response.status_code == 200
    assert payload["gate"]["decision"] == "indeterminate"
    assert payload["gate"]["deploy_allowed"] is False
    assert payload["gate"]["reason_codes"] == ["REPOSITORY_NOT_SCANNED"]
    assert payload["recommended_action"] == "queue_pre_deploy_scan"
    assert payload["can_queue_pre_deploy_scan"] is True


def test_repository_scan_settings_can_disable_asset() -> None:
    """Irrelevant repositories should be switchable out of future scans without deleting history."""

    session_factory = build_session_factory()

    def override_db_session() -> Generator[Session, None, None]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    with session_factory() as session:
        repository = Repository(
            source_type="github",
            owner="Feberdin",
            name="old-repo",
            full_name="Feberdin/old-repo",
            default_branch="main",
            local_path="/tmp/old-repo",
        )
        session.add(repository)
        session.commit()
        repository_id = repository.id

    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_db_session] = override_db_session
    client = TestClient(app)

    response = client.patch(
        f"/repositories/{repository_id}/scan-settings",
        json={"scan_enabled": False},
    )
    repositories = client.get("/repositories").json()

    assert response.status_code == 200
    assert response.json()["scan_enabled"] is False
    assert repositories[0]["scan_enabled"] is False


def test_repository_scan_settings_bulk_updates_multiple_assets() -> None:
    """Operators should be able to disable stale repositories in batches."""

    session_factory = build_session_factory()

    def override_db_session() -> Generator[Session, None, None]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    with session_factory() as session:
        first_repository = Repository(
            source_type="github",
            owner="Feberdin",
            name="old-repo",
            full_name="Feberdin/old-repo",
            default_branch="main",
            local_path="/tmp/old-repo",
        )
        second_repository = Repository(
            source_type="github",
            owner="Feberdin",
            name="obsolete-repo",
            full_name="Feberdin/obsolete-repo",
            default_branch="main",
            local_path="/tmp/obsolete-repo",
        )
        session.add_all([first_repository, second_repository])
        session.commit()
        repository_ids = [first_repository.id, second_repository.id]

    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_db_session] = override_db_session
    client = TestClient(app)

    response = client.patch(
        "/repositories/scan-settings/bulk",
        json={"repository_ids": repository_ids, "scan_enabled": False},
    )
    repositories = client.get("/repositories").json()

    assert response.status_code == 200
    assert {repository["scan_enabled"] for repository in response.json()} == {False}
    assert {repository["scan_enabled"] for repository in repositories} == {False}
