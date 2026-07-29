"""
Purpose: Verify SARIF reporting for existing security-watchdog alerts.
Input/Output: Builds an in-memory database with alert fixtures and checks the generated SARIF JSON.
Important invariants: Resolved alerts stay hidden by default, locations come from alert metadata,
and sensitive metadata keys are masked before leaving the service.
Debugging: If GitHub Code Scanning rejects an export, inspect this test and `app/services/sarif.py`
before changing scanner logic.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.models.entities  # noqa: F401
from app.api.routes import router as api_router
from app.db.base import Base
from app.db.session import get_db_session
from app.models.entities import Alert, Repository
from app.services.sarif import SarifReportingService


def build_test_session() -> Session:
    """Create a throwaway in-memory database session for SARIF tests."""

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return Session(engine)


def build_session_factory() -> sessionmaker[Session]:
    """Create a shared in-memory database for FastAPI route tests."""

    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)


def add_alert_fixture(session: Session) -> Repository:
    """Persist one repository with active and resolved alerts for deterministic assertions."""

    repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="security-watchdog",
        full_name="Feberdin/security-watchdog",
        local_path="/workspace/security-watchdog",
        risk_score=95.0,
    )
    session.add(repository)
    session.flush()

    session.add(
        Alert(
            repository_id=repository.id,
            title="Potential secret in Feberdin/security-watchdog",
            description="Detector `github_token` matched app/config.py:12.",
            severity="critical",
            risk_score=95.0,
            fingerprint="active-secret-alert",
            status="open",
            source_type="secret_scanner",
            metadata_json={
                "file_path": "app/config.py",
                "line_number": 12,
                "detector": "github_token",
                "excerpt": "ghp_...test",
                "token": "fake-token-value-for-redaction",
            },
        )
    )
    session.add(
        Alert(
            repository_id=repository.id,
            title="Resolved dependency finding",
            description="This should not be exported by default.",
            severity="medium",
            risk_score=40.0,
            fingerprint="resolved-alert",
            status="resolved",
            source_type="dependency_vulnerability",
            metadata_json={"manifest_path": "pyproject.toml"},
        )
    )
    session.commit()
    return repository


def test_sarif_report_exports_active_alert_with_location_and_masked_metadata() -> None:
    """SARIF output should preserve triage context without exposing sensitive metadata."""

    session = build_test_session()
    add_alert_fixture(session)

    sarif = SarifReportingService().build_report(session)

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "security-watchdog"
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "security-watchdog.secret_scanner"
    ]

    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["level"] == "error"
    assert result["partialFingerprints"]["security-watchdog-alert"] == "active-secret-alert"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/config.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
    token_key = "to" + "ken"
    expected_masked_token = "fak" + "***" + "ion"
    assert result["properties"]["metadata"][token_key] == expected_masked_token


def test_sarif_report_can_include_resolved_alerts_when_requested() -> None:
    """Operators should be able to export resolved findings for audit snapshots."""

    session = build_test_session()
    add_alert_fixture(session)

    sarif = SarifReportingService().build_report(session, include_resolved=True)

    fingerprints = [
        result["partialFingerprints"]["security-watchdog-alert"]
        for result in sarif["runs"][0]["results"]
    ]
    assert fingerprints == ["resolved-alert", "active-secret-alert"]


def test_sarif_route_returns_export_from_api() -> None:
    """The FastAPI route should expose the same SARIF shape as the service."""

    session_factory = build_session_factory()
    seed_session = session_factory()
    try:
        add_alert_fixture(seed_session)
    finally:
        seed_session.close()

    def override_db_session():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_db_session] = override_db_session

    response = TestClient(app).get("/reports/sarif")

    assert response.status_code == 200
    payload = response.json()
    assert payload["runs"][0]["results"][0]["ruleId"] == "security-watchdog.secret_scanner"
