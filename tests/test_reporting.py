"""
Purpose: Verify the system-centric reporting view used by the dashboard accordion and `/systems`.
Input/Output: Builds an in-memory database with one repository, dependency, vulnerability, and
alert, then checks the enriched system inventory output.
Important invariants: The reporting layer should expose dependency-level risk plus the latest known
version hint without requiring the browser to stitch together multiple endpoints.
Debugging: If this test fails, inspect `ReportingService.build_system_inventory()` and the version
resolver injected into the service first.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import app.models.entities  # noqa: F401
from app.db.base import Base
from app.models.entities import Alert, Dependency, DependencyVulnerability, Repository, Vulnerability
from app.services.reporting import ReportingService
from app.services.version_catalog import LatestVersionRecord


class FakeVersionCatalog:
    """Deterministic resolver used to keep reporting tests offline and predictable."""

    def resolve_latest_version(self, ecosystem: str, package_name: str) -> LatestVersionRecord:
        assert ecosystem == "pypi"
        assert package_name == "requests"
        return LatestVersionRecord(latest_version="2.32.3", source="unit-test")


def build_test_session() -> Session:
    """Create a throwaway in-memory database session for reporting tests."""

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return Session(engine)


def test_build_system_inventory_returns_expandable_dependency_details() -> None:
    """The system inventory should include version and risk context per dependency row."""

    session = build_test_session()
    repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="security-watchdog",
        full_name="Feberdin/security-watchdog",
        local_path="/tmp/security-watchdog",
        risk_score=82.5,
    )
    session.add(repository)
    session.flush()

    dependency = Dependency(
        repository_id=repository.id,
        manifest_path="requirements.txt",
        package_name="requests",
        version="2.25.0",
        ecosystem="pypi",
    )
    session.add(dependency)
    session.flush()

    vulnerability = Vulnerability(
        source="osv",
        source_identifier="CVE-2026-0001",
        package_name="requests",
        ecosystem="pypi",
        summary="Example vulnerability",
        severity="high",
    )
    session.add(vulnerability)
    session.flush()

    session.add(
        DependencyVulnerability(
            dependency_id=dependency.id,
            vulnerability_id=vulnerability.id,
            risk_score=82.5,
            match_reason="Unit test match",
        )
    )
    session.add(
        Alert(
            repository_id=repository.id,
            title="High risk dependency",
            description="requests is vulnerable",
            severity="high",
            risk_score=82.5,
            fingerprint="unit-test-alert",
            status="open",
            source_type="dependency_vulnerability",
            metadata_json={},
        )
    )
    session.commit()

    systems = ReportingService(version_catalog=FakeVersionCatalog()).build_system_inventory(session)

    assert len(systems) == 1
    system = systems[0]
    assert system.full_name == "Feberdin/security-watchdog"
    assert system.dependency_count == 1
    assert system.vulnerable_dependency_count == 1
    assert system.open_alert_count == 1

    dependency_row = system.dependencies[0]
    assert dependency_row.package_name == "requests"
    assert dependency_row.detected_version == "2.25.0"
    assert dependency_row.latest_version == "2.32.3"
    assert dependency_row.latest_version_status == "outdated"
    assert dependency_row.risk_severity == "high"
    assert dependency_row.vulnerability_ids == ["CVE-2026-0001"]
