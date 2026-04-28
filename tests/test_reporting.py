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

from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import app.models.entities  # noqa: F401
from app.db.base import Base
from app.models.entities import (
    Alert,
    Dependency,
    DependencyVulnerability,
    Repository,
    ScanResult,
    Vulnerability,
)
from app.services.reporting import ReportingService
from app.services.version_catalog import LatestVersionRecord


class FakeVersionCatalog:
    """Deterministic resolver used to keep reporting tests offline and predictable."""

    def resolve_latest_version(self, ecosystem: str, package_name: str) -> LatestVersionRecord:
        assert ecosystem == "pypi"
        assert package_name == "requests"
        return LatestVersionRecord(
            latest_version="2.32.3",
            source="unit-test",
            checked_at=datetime(2026, 4, 8, 14, 30, tzinfo=UTC),
            released_at=datetime(2026, 4, 7, 8, 15, tzinfo=UTC),
        )


class ExplodingVersionCatalog:
    """Fail loudly if debug export accidentally performs latest-version lookups."""

    def resolve_latest_version(self, ecosystem: str, package_name: str) -> LatestVersionRecord:
        raise AssertionError(
            f"Debug export should not resolve latest versions, but got {ecosystem}:{package_name}"
        )


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
        malicious_package=True,
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
    assert dependency_row.latest_version_published_at == datetime(2026, 4, 7, 8, 15, tzinfo=UTC)
    assert dependency_row.latest_version_status == "outdated"
    assert dependency_row.was_compromised is True
    assert dependency_row.compromised_signal == "malicious_package:CVE-2026-0001"
    assert dependency_row.risk_severity == "high"
    assert dependency_row.vulnerability_ids == ["CVE-2026-0001"]


def test_build_platform_debug_export_includes_suspicious_systems() -> None:
    """The global debug export should surface risky systems in a compact structured payload."""

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
        malicious_package=True,
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
    session.commit()

    export_payload = ReportingService(version_catalog=FakeVersionCatalog()).build_platform_debug_export(session)

    assert export_payload["diagnostics"]["suspicious_system_count"] == 1
    assert export_payload["suspicious_systems"][0]["full_name"] == "Feberdin/security-watchdog"
    assert export_payload["suspicious_systems"][0]["flagged_dependencies"][0]["was_compromised"] is True


def test_build_platform_debug_export_handles_naive_scan_timestamps() -> None:
    """Naive SQLite timestamps should not crash the scheduler health block in exports."""

    session = build_test_session()
    repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="security-watchdog",
        full_name="Feberdin/security-watchdog",
        local_path="/tmp/security-watchdog",
        risk_score=12.0,
    )
    session.add(repository)
    session.flush()

    session.add(
        ScanResult(
            repository_id=repository.id,
            scanner_name="dependency_extractor",
            status="success",
            findings_count=3,
            started_at=datetime(2026, 4, 8, 10, 0),
            completed_at=datetime(2026, 4, 8, 10, 5),
            details_json={"note": "naive timestamp regression test"},
        )
    )
    session.commit()

    export_payload = ReportingService(version_catalog=FakeVersionCatalog()).build_platform_debug_export(session)

    scheduler = export_payload["scheduler"]["repo_scan"]
    assert scheduler["last_status"] == "success"
    assert scheduler["last_completed_at"] == "2026-04-08T10:05:00+00:00"


def test_build_platform_debug_export_skips_latest_version_lookups_for_speed() -> None:
    """The large debug export should stay offline-friendly and fast even with many dependencies."""

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
        malicious_package=True,
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
    session.commit()

    export_payload = ReportingService(
        version_catalog=ExplodingVersionCatalog()
    ).build_platform_debug_export(session)

    flagged_dependency = export_payload["suspicious_systems"][0]["flagged_dependencies"][0]
    assert flagged_dependency["latest_version"] is None
    assert flagged_dependency["latest_version_status"] == "skipped"
    assert flagged_dependency["latest_version_source"] == "skipped_debug_export"


def test_build_codex_remediation_prompt_contains_findings() -> None:
    """The remediation prompt should include actionable dependency findings for Codex."""

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
        malicious_package=True,
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
    session.commit()

    prompt = ReportingService(version_catalog=FakeVersionCatalog()).build_codex_remediation_prompt(
        session,
        repository.id,
    )

    assert "Please review and remediate security issues" in prompt
    assert "Feberdin/security-watchdog" in prompt
    assert "requests" in prompt
    assert "Previously compromised: yes" in prompt


def test_build_system_inventory_surfaces_runtime_findings_from_alerts() -> None:
    """Container or secret alerts should appear as runtime findings on the system card."""

    session = build_test_session()
    repository = Repository(
        source_type="unraid_docker",
        owner="unraid",
        name="watchtower",
        full_name="unraid/watchtower",
        local_path="",
        risk_score=70.0,
    )
    session.add(repository)
    session.flush()

    session.add(
        Alert(
            repository_id=repository.id,
            title="Unraid container vulnerability in watchtower",
            description="Moby authorization bypass vulnerability",
            severity="high",
            risk_score=70.0,
            fingerprint="unit-test-runtime-finding",
            status="open",
            source_type="unraid_container",
            metadata_json={
                "vulnerability_id": "CVE-2026-34040",
                "package_name": "github.com/docker/docker",
                "installed_version": "v24.0.7+incompatible",
                "fix_version": "29.3.1",
                "target": "containrrr/watchtower:latest",
                "description": "Moby authorization bypass vulnerability",
            },
        )
    )
    session.commit()

    systems = ReportingService(version_catalog=FakeVersionCatalog()).build_system_inventory(session)

    assert len(systems) == 1
    runtime_finding = systems[0].runtime_findings[0]
    assert runtime_finding.vulnerability_id == "CVE-2026-34040"
    assert runtime_finding.package_name == "github.com/docker/docker"
    assert runtime_finding.fix_version == "29.3.1"
