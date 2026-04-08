"""
Purpose: Verify alert fingerprint dedupe and stale-alert resolution in the persistence layer.
Input/Output: Creates an in-memory database, writes alerts, resolves old ones, and ensures repeated
findings reopen the same alert instead of creating endless new rows.
Important invariants: Alert fingerprints must stay stable across scans and old findings must be
resolved when they disappear, otherwise dashboard counts and risk scores become unusable.
Debugging: If alert counts balloon unexpectedly, start with `resolve_stale_alerts()` and
`upsert_alert()` because they define the entire alert lifecycle.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import app.models.entities  # noqa: F401
from app.db.base import Base
from app.models.entities import AlertStatus
from app.repositories.store import resolve_stale_alerts, upsert_alert, upsert_repository


def build_test_session() -> Session:
    """Create a throwaway in-memory database session for repository-store tests."""

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return Session(engine)


def test_stale_alerts_are_resolved_and_reopened_when_they_return() -> None:
    """A disappeared finding should resolve and reopen on reoccurrence with the same fingerprint."""

    session = build_test_session()
    repository = upsert_repository(
        session,
        source_type="github",
        owner="Feberdin",
        name="security-watchdog",
        full_name="Feberdin/security-watchdog",
        local_path="/tmp/security-watchdog",
    )
    session.commit()

    alert = upsert_alert(
        session,
        repository_id=repository.id,
        title="Vulnerable dependency fastapi",
        description="fastapi matched GHSA-123",
        severity="high",
        risk_score=49.2,
        source_type="dependency_vulnerability",
        metadata={
            "dependency": "fastapi",
            "version": "0.115.12",
            "manifest_path": "pyproject.toml",
            "vulnerability": "GHSA-123",
            "references": [],
        },
    )
    fingerprint = alert.fingerprint
    session.commit()

    resolved_count = resolve_stale_alerts(
        session,
        repository_id=repository.id,
        source_types=["dependency_vulnerability"],
        active_fingerprints=set(),
    )
    session.commit()

    assert resolved_count == 1
    assert alert.status == AlertStatus.RESOLVED.value

    reopened = upsert_alert(
        session,
        repository_id=repository.id,
        title="Vulnerable dependency fastapi",
        description="fastapi matched GHSA-123 again",
        severity="high",
        risk_score=49.2,
        source_type="dependency_vulnerability",
        metadata={
            "dependency": "fastapi",
            "version": "0.115.12",
            "manifest_path": "pyproject.toml",
            "vulnerability": "GHSA-123",
            "references": [],
        },
    )
    session.commit()

    assert reopened.id == alert.id
    assert reopened.fingerprint == fingerprint
    assert reopened.status == AlertStatus.OPEN.value
