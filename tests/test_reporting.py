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
from app.repositories.store import build_alert_fingerprint
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


def test_build_high_risk_update_queue_prioritizes_risky_outdated_dependencies() -> None:
    """The Codex automation queue should expose risky outdated packages with target versions."""

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

    queue = ReportingService(version_catalog=FakeVersionCatalog()).build_high_risk_update_queue(session)

    assert queue.task_count == 1
    task = queue.tasks[0]
    assert task.full_name == "Feberdin/security-watchdog"
    assert task.priority == "critical"
    assert "vulnerable dependency update" in task.reason
    dependency_action = task.dependencies[0]
    assert dependency_action.package_name == "requests"
    assert dependency_action.current_version == "2.25.0"
    assert dependency_action.target_version == "2.32.3"
    assert dependency_action.action == "replace_or_remove_compromised_package"


def test_build_high_risk_update_prompt_contains_safe_codex_rules() -> None:
    """The master prompt should include package targets plus guardrails for CI and deployments."""

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
    session.commit()

    prompt = ReportingService(version_catalog=FakeVersionCatalog()).build_high_risk_update_prompt(session)

    assert "Feberdin/security-watchdog" in prompt
    assert "requests" in prompt
    assert "Current version: 2.25.0" in prompt
    assert "Target version: 2.32.3" in prompt
    assert "wait for CI for the exact pushed commit" in prompt
    assert "use only the `unraid_deploy` MCP broker flow" in prompt
    assert "Do not update solely because a target version is higher" in prompt
    assert "Treat `constraint` status as a warning" in prompt
    assert "If compatibility cannot be proven locally, do not force the update" in prompt


def test_high_risk_update_queue_marks_constraints_for_review() -> None:
    """Constraint drift should tell Codex to inspect compatibility before changing ranges."""

    session = build_test_session()
    repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="security-watchdog",
        full_name="Feberdin/security-watchdog",
        local_path="/tmp/security-watchdog",
        risk_score=20.0,
    )
    session.add(repository)
    session.flush()

    session.add(
        Dependency(
            repository_id=repository.id,
            manifest_path="pyproject.toml",
            package_name="requests",
            version=">=2.25,<2.26",
            ecosystem="pypi",
        )
    )
    session.commit()

    queue = ReportingService(version_catalog=FakeVersionCatalog()).build_high_risk_update_queue(session)

    assert queue.task_count == 1
    dependency_action = queue.tasks[0].dependencies[0]
    assert dependency_action.latest_version_status == "constraint"
    assert dependency_action.action == "review_constraint_and_update_config_if_safe"


def test_build_daily_security_automation_returns_machine_readable_runbook() -> None:
    """The daily automation API payload should include queue data and the strict update guardrails."""

    session = build_test_session()
    repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="security-watchdog",
        full_name="Feberdin/security-watchdog",
        local_path="/tmp/security-watchdog",
        risk_score=20.0,
    )
    session.add(repository)
    session.flush()

    session.add(
        Dependency(
            repository_id=repository.id,
            manifest_path="requirements.txt",
            package_name="requests",
            version="2.25.0",
            ecosystem="pypi",
        )
    )
    session.commit()

    runbook = ReportingService(version_catalog=FakeVersionCatalog()).build_daily_security_automation(
        session,
        max_tasks_per_run=2,
    )

    assert runbook.api_version == "2026-07-30"
    assert runbook.recommended_schedule == "daily"
    assert runbook.max_tasks_per_run == 2
    assert runbook.source_endpoints["runbook"] == "/automation/daily-security-check"
    assert runbook.queue.task_count == 1
    assert "Do not update solely because a target version is higher" in runbook.guardrails[0]
    assert "Do not merge pull requests and do not deploy automatically" in runbook.codex_prompt


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


def test_report_counts_unique_secret_findings_not_history_duplicates() -> None:
    """Repeated git-history rows for the same secret location should count as one finding."""

    session = build_test_session()
    repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="core",
        full_name="Feberdin/core",
        local_path="/tmp/core",
        risk_score=95.0,
    )
    session.add(repository)
    session.flush()

    base_metadata = {
        "file_path": "app/observer/WeatherWatcher.py",
        "line_number": 42,
        "detector": "github_token",
        "excerpt": "ghp_...wxyz",
        "content_source": "git_history",
    }
    for index, commit_sha in enumerate(("a" * 40, "b" * 40), start=1):
        session.add(
            Alert(
                repository_id=repository.id,
                title="Potential secret in Feberdin/core",
                description=f"Detector matched public git history commit {commit_sha[:12]}.",
                severity="critical",
                risk_score=95.0,
                fingerprint=f"legacy-history-alert-{index}",
                status="open",
                source_type="secret_scanner",
                metadata_json={**base_metadata, "commit_sha": commit_sha},
            )
        )
    session.commit()

    report = ReportingService(version_catalog=FakeVersionCatalog()).build_report(session)
    systems = ReportingService(version_catalog=FakeVersionCatalog()).build_system_inventory(session)

    assert report.alert_count == 1
    assert report.critical_alert_count == 1
    assert systems[0].open_alert_count == 1
    assert len(systems[0].runtime_findings) == 1


def test_secret_alert_fingerprint_ignores_git_history_commit_sha() -> None:
    """New secret alert fingerprints should stay stable across repeated history scans."""

    metadata = {
        "file_path": "app/observer/WeatherWatcher.py",
        "line_number": 42,
        "detector": "github_token",
        "excerpt": "ghp_...wxyz",
        "content_source": "git_history",
    }

    first = build_alert_fingerprint(
        repository_id=7,
        title="Potential secret in Feberdin/core",
        source_type="secret_scanner",
        metadata={**metadata, "commit_sha": "a" * 40},
    )
    second = build_alert_fingerprint(
        repository_id=7,
        title="Potential secret in Feberdin/core",
        source_type="secret_scanner",
        metadata={**metadata, "commit_sha": "b" * 40},
    )

    assert first == second


def test_report_excludes_legacy_git_history_entropy_noise() -> None:
    """Entropy-only history findings should not inflate critical operator metrics."""

    session = build_test_session()
    repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="core",
        full_name="Feberdin/core",
        local_path="/tmp/core",
        risk_score=95.0,
    )
    session.add(repository)
    session.flush()
    session.add(
        Alert(
            repository_id=repository.id,
            title="Potential secret in Feberdin/core",
            description="Detector matched public git history commit abc123.",
            severity="critical",
            risk_score=95.0,
            fingerprint="legacy-history-entropy-alert",
            status="open",
            source_type="secret_scanner",
            metadata_json={
                "file_path": "README.md",
                "line_number": 46,
                "detector": "high_entropy",
                "excerpt": "abcd...wxyz",
                "content_source": "git_history",
                "commit_sha": "a" * 40,
            },
        )
    )
    session.commit()

    service = ReportingService(version_catalog=FakeVersionCatalog())
    report = service.build_report(session)
    systems = service.build_system_inventory(session)

    assert report.alert_count == 0
    assert report.critical_alert_count == 0
    assert systems[0].open_alert_count == 0
    assert systems[0].runtime_findings == []


def test_system_debug_export_loads_only_actionable_alerts() -> None:
    """Single-system exports should not spend time rendering legacy entropy-only history rows."""

    session = build_test_session()
    repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="core",
        full_name="Feberdin/core",
        local_path="/tmp/core",
        risk_score=95.0,
    )
    session.add(repository)
    session.flush()
    session.add_all(
        [
            Alert(
                repository_id=repository.id,
                title="Legacy entropy-only history finding",
                description="Low-confidence git history entropy match.",
                severity="critical",
                risk_score=95.0,
                fingerprint="legacy-history-entropy-alert",
                status="open",
                source_type="secret_scanner",
                metadata_json={
                    "file_path": "README.md",
                    "line_number": 46,
                    "detector": "high_entropy",
                    "excerpt": "abcd...wxyz",
                    "content_source": "git_history",
                    "commit_sha": "a" * 40,
                },
            ),
            Alert(
                repository_id=repository.id,
                title="Signature-based history finding",
                description="High-confidence token pattern in git history.",
                severity="critical",
                risk_score=95.0,
                fingerprint="history-github-token-alert",
                status="open",
                source_type="secret_scanner",
                metadata_json={
                    "file_path": "app/config.py",
                    "line_number": 12,
                    "detector": "github_token",
                    "excerpt": "ghp_...wxyz",
                    "content_source": "git_history",
                    "commit_sha": "b" * 40,
                },
            ),
        ]
    )
    session.commit()
    session.expire_all()

    export_payload = ReportingService(version_catalog=FakeVersionCatalog()).build_system_debug_export(
        session,
        repository.id,
    )

    assert export_payload["system"]["open_alert_count"] == 1
    assert len(export_payload["system"]["runtime_findings"]) == 1
    assert export_payload["system"]["runtime_findings"][0]["vulnerability_id"] == "github_token"
    assert [alert["title"] for alert in export_payload["recent_alerts"]] == ["Signature-based history finding"]


def test_alert_diagnostics_summarizes_actionable_rows_without_secret_values() -> None:
    """Alert diagnostics should expose aggregate causes while excluding legacy noise."""

    session = build_test_session()
    repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="security-watchdog",
        full_name="Feberdin/security-watchdog",
        local_path="/tmp/security-watchdog",
        risk_score=95.0,
    )
    session.add(repository)
    session.flush()
    session.add_all(
        [
            Alert(
                repository_id=repository.id,
                title="Legacy entropy-only history finding",
                description="Low-confidence git history entropy match.",
                severity="critical",
                risk_score=95.0,
                fingerprint="legacy-history-entropy-alert",
                status="open",
                source_type="secret_scanner",
                metadata_json={
                    "file_path": "README.md",
                    "line_number": 46,
                    "detector": "high_entropy",
                    "excerpt": "abcd...wxyz",
                    "content_source": "git_history",
                },
            ),
            Alert(
                repository_id=repository.id,
                title="Signature-based history finding",
                description="High-confidence token pattern in git history.",
                severity="critical",
                risk_score=95.0,
                fingerprint="history-github-token-alert",
                status="open",
                source_type="secret_scanner",
                metadata_json={
                    "file_path": "app/config.py",
                    "line_number": 12,
                    "detector": "github_token",
                    "excerpt": "ghp_...wxyz",
                    "content_source": "git_history",
                },
            ),
            Alert(
                repository_id=repository.id,
                title="Container CVE",
                description="Container package vulnerability.",
                severity="high",
                risk_score=80.0,
                fingerprint="container-cve-alert",
                status="open",
                source_type="unraid_container",
                metadata_json={
                    "vulnerability_id": "CVE-2026-34040",
                    "package_name": "github.com/docker/docker",
                    "target": "containrrr/watchtower:latest",
                },
            ),
        ]
    )
    session.commit()

    diagnostics = ReportingService(version_catalog=FakeVersionCatalog()).build_alert_diagnostics(
        session,
        limit=10,
    )

    assert diagnostics["open_alert_rows"] == 3
    assert diagnostics["operator_actionable_alert_rows"] == 2
    assert diagnostics["excluded_legacy_git_history_entropy_rows"] == 1
    assert {
        (entry["source_type"], entry["severity"], entry["alert_rows"])
        for entry in diagnostics["by_source_and_severity"]
    } == {("secret_scanner", "critical", 1), ("unraid_container", "high", 1)}
    assert any(
        entry["finding_kind"] == "github_token" and entry["content_source"] == "git_history"
        for entry in diagnostics["by_finding_kind"]
    )
