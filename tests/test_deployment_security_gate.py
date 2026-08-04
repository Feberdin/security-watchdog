"""
Purpose: Verify exact-commit deployment decisions and secret-safe blocker responses.
Input/Output: Builds in-memory repositories, aggregate scans, and alerts for the gate service.
Important invariants: Missing/stale/mismatched evidence fails closed; unresolved HIGH/CRITICAL
findings deny deployment; secret excerpts never leave the service.
Debugging: Inspect reason codes first, then the aggregate `repository_asset_scan` fixture.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import app.models.entities  # noqa: F401
from app.core.config import Settings
from app.core.security import mask_sensitive_values
from app.db.base import Base
from app.models.entities import Alert, Repository, ScanResult
from app.models.schemas import DeploymentSecurityGateRequest
from app.services.deployment_security_gate import DeploymentSecurityGateService

COMMIT_SHA = "a1" * 20
TEST_GATE_TOKEN = "dummy-token"


def build_test_session() -> Session:
    """Create an isolated database for one deployment-gate scenario."""

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return Session(engine)


def build_settings(**overrides) -> Settings:
    """Return deterministic gate policy settings without reading local secrets."""

    return Settings(
        deployment_gate_token=TEST_GATE_TOKEN,
        deployment_gate_max_scan_age_hours=24,
        deployment_gate_max_blockers=50,
        **overrides,
    )


def add_repository_with_scan(
    session: Session,
    *,
    commit_sha: str = COMMIT_SHA,
    status: str = "success",
    completed_at: datetime | None = None,
) -> Repository:
    """Persist one GitHub repository and its aggregate scan evidence."""

    repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="example",
        full_name="Feberdin/example",
        local_path="/tmp/example",
    )
    session.add(repository)
    session.flush()
    session.add(
        ScanResult(
            repository_id=repository.id,
            scanner_name="repository_asset_scan",
            status=status,
            findings_count=0,
            completed_at=completed_at or datetime.now(UTC) - timedelta(hours=1),
            details_json={"commit_sha": commit_sha},
        )
    )
    session.commit()
    return repository


def gate_request(commit_sha: str = COMMIT_SHA) -> DeploymentSecurityGateRequest:
    """Build the stable request shape used by the Deployment Broker."""

    return DeploymentSecurityGateRequest(
        stack_name="example",
        repository_full_name="Feberdin/example",
        commit_sha=commit_sha,
        compose_file="docker-compose.yml",
    )


def test_fresh_exact_commit_without_blockers_allows_deployment() -> None:
    """A fresh successful exact-commit scan with no active blockers should allow deploy."""

    session = build_test_session()
    add_repository_with_scan(session)

    response = DeploymentSecurityGateService(build_settings()).evaluate(session, gate_request())

    assert response.decision == "allow"
    assert response.deploy_allowed is True
    assert response.reason_codes == ["SECURITY_POLICY_SATISFIED"]
    assert response.evidence is not None
    assert response.evidence.commit_matches is True
    assert response.summary.blocker_count == 0


def test_unresolved_critical_secret_denies_without_returning_excerpt() -> None:
    """Secret findings should deny deployment while keeping the matched content private."""

    session = build_test_session()
    repository = add_repository_with_scan(session)
    session.add(
        Alert(
            repository_id=repository.id,
            title="Potential secret in Feberdin/example",
            description="sensitive matched content",
            severity="critical",
            risk_score=95.0,
            fingerprint="f" * 64,
            status="open",
            source_type="secret_scanner",
            metadata_json={
                "file_path": "src/settings.py",
                "line_number": 12,
                "excerpt": "must-not-leave-the-service",
                "detector": "generic-api-key",
            },
        )
    )
    session.commit()

    response = DeploymentSecurityGateService(build_settings()).evaluate(session, gate_request())
    serialized_response = response.model_dump_json()

    assert response.decision == "deny"
    assert response.deploy_allowed is False
    assert response.summary.critical_count == 1
    assert response.blockers[0].source_type == "secret_scanner"
    assert response.blockers[0].context["file_path"] == "src/settings.py"
    assert "must-not-leave-the-service" not in serialized_response
    assert "sensitive matched content" not in serialized_response


def test_stale_mismatched_scan_is_indeterminate_even_without_alerts() -> None:
    """Alert-free data must not allow deploy when scan provenance is stale and mismatched."""

    session = build_test_session()
    add_repository_with_scan(
        session,
        commit_sha="b2" * 20,
        completed_at=datetime.now(UTC) - timedelta(hours=48),
    )

    response = DeploymentSecurityGateService(build_settings()).evaluate(session, gate_request())

    assert response.decision == "indeterminate"
    assert response.deploy_allowed is False
    assert "SCAN_EVIDENCE_STALE" in response.reason_codes
    assert "SCANNED_COMMIT_MISMATCH" in response.reason_codes


def test_latest_failed_scan_blocks_despite_older_success() -> None:
    """The newest aggregate result controls the decision so failures cannot be bypassed."""

    session = build_test_session()
    repository = add_repository_with_scan(session)
    session.add(
        ScanResult(
            repository_id=repository.id,
            scanner_name="repository_asset_scan",
            status="error",
            findings_count=0,
            completed_at=datetime.now(UTC),
            details_json={"commit_sha": COMMIT_SHA},
        )
    )
    session.commit()

    response = DeploymentSecurityGateService(build_settings()).evaluate(session, gate_request())

    assert response.decision == "indeterminate"
    assert response.deploy_allowed is False
    assert "LATEST_SCAN_FAILED" in response.reason_codes


def test_unknown_repository_fails_closed_with_scan_instruction() -> None:
    """A repository absent from inventory should return an actionable indeterminate result."""

    session = build_test_session()

    response = DeploymentSecurityGateService(build_settings()).evaluate(session, gate_request())

    assert response.decision == "indeterminate"
    assert response.deploy_allowed is False
    assert response.reason_codes == ["REPOSITORY_NOT_SCANNED"]


def test_deployment_gate_tokens_are_masked_by_structured_logging() -> None:
    """Dedicated inbound and outbound token names must be treated as secrets in logs."""

    masked = mask_sensitive_values(
        {
            "deployment_gate_token": TEST_GATE_TOKEN,
            "security_watchdog_gate_token": TEST_GATE_TOKEN,
        }
    )

    assert masked["deployment_gate_token"] != TEST_GATE_TOKEN
    assert masked["security_watchdog_gate_token"] != TEST_GATE_TOKEN
