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
    assert "Pull request allowed: yes" in prompt
    assert "Propose code changes only in `Feberdin/security-watchdog`" in prompt


def test_system_inventory_marks_owned_github_repository_as_managed_fix() -> None:
    """Owned non-fork GitHub repositories may receive Codex issue and PR prompts."""

    session = build_test_session()
    repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="watchlog",
        full_name="Feberdin/watchlog",
        local_path="/tmp/watchlog",
        risk_score=75.0,
        metadata_json={"fork": False},
    )
    session.add(repository)
    session.commit()

    systems = ReportingService(version_catalog=FakeVersionCatalog()).build_system_inventory(session)

    remediation = systems[0].remediation
    assert remediation.ownership == "owned"
    assert remediation.mode == "managed_fix"
    assert remediation.source_repository == "Feberdin/watchlog"
    assert remediation.issue_recommended is True
    assert remediation.pull_request_allowed is True


def test_system_inventory_recommends_excluding_managed_forks() -> None:
    """Managed-namespace forks should not produce automatic PR tasks by default."""

    session = build_test_session()
    repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="core",
        full_name="Feberdin/core",
        local_path="/tmp/core",
        risk_score=95.0,
        metadata_json={
            "fork": True,
            "parent": {"full_name": "home-assistant/core"},
        },
    )
    session.add(repository)
    session.commit()

    prompt = ReportingService(version_catalog=FakeVersionCatalog()).build_codex_remediation_prompt(
        session,
        repository.id,
    )

    assert "Ownership: fork" in prompt
    assert "Mode: exclude_recommended" in prompt
    assert "Source repository: home-assistant/core" in prompt
    assert "Pull request allowed: no" in prompt
    assert "Scan exclusion recommended: yes" in prompt


def test_unraid_owned_image_requires_source_mapping_before_pr() -> None:
    """Owned image namespaces still need a source repository before Codex may propose code changes."""

    session = build_test_session()
    repository = Repository(
        source_type="unraid_docker",
        owner="unraid",
        name="Arr-Duplicates",
        full_name="unraid/Arr-Duplicates",
        local_path="",
        risk_score=90.0,
        metadata_json={"image": "ghcr.io/feberdin/arr-duplicates:latest"},
    )
    session.add(repository)
    session.commit()

    systems = ReportingService(version_catalog=FakeVersionCatalog()).build_system_inventory(session)

    remediation = systems[0].remediation
    assert remediation.ownership == "owned_image"
    assert remediation.mode == "source_mapping_required"
    assert remediation.target == "ghcr.io/feberdin/arr-duplicates:latest"
    assert remediation.source_repository is None
    assert remediation.pull_request_allowed is False


def test_unraid_owned_image_with_oci_source_allows_source_repo_pr() -> None:
    """OCI source labels let the Watchdog route image findings back to the owned source repo."""

    session = build_test_session()
    repository = Repository(
        source_type="unraid_docker",
        owner="unraid",
        name="security-watchdog",
        full_name="unraid/security-watchdog",
        local_path="",
        risk_score=90.0,
        metadata_json={
            "image": "ghcr.io/feberdin/security-watchdog:latest",
            "labels": {
                "org.opencontainers.image.source": "https://github.com/Feberdin/security-watchdog",
            },
        },
    )
    session.add(repository)
    session.commit()

    systems = ReportingService(version_catalog=FakeVersionCatalog()).build_system_inventory(session)

    remediation = systems[0].remediation
    assert remediation.ownership == "owned_image"
    assert remediation.mode == "managed_fix"
    assert remediation.source_repository == "Feberdin/security-watchdog"
    assert remediation.pull_request_allowed is True


def test_codex_remediation_prompt_keeps_external_images_advisory_only() -> None:
    """External runtime images should produce advisory instructions instead of PR instructions."""

    session = build_test_session()
    repository = Repository(
        source_type="unraid_docker",
        owner="unraid",
        name="watchtower",
        full_name="unraid/watchtower",
        local_path="",
        risk_score=90.0,
        metadata_json={"image": "containrrr/watchtower:latest"},
    )
    session.add(repository)
    session.flush()
    session.add(
        Alert(
            repository_id=repository.id,
            title="Unraid container vulnerability in watchtower",
            description="Moby authorization bypass vulnerability",
            severity="critical",
            risk_score=90.0,
            fingerprint="external-image-remediation",
            status="open",
            source_type="unraid_container",
            metadata_json={
                "vulnerability_id": "CVE-2026-34040",
                "package_name": "github.com/docker/docker",
                "installed_version": "v24.0.7+incompatible",
                "fix_version": "29.3.1",
                "target": "containrrr/watchtower:latest",
            },
        )
    )
    session.commit()

    prompt = ReportingService(version_catalog=FakeVersionCatalog()).build_codex_remediation_prompt(
        session,
        repository.id,
    )

    assert "Ownership: external" in prompt
    assert "Pull request allowed: no" in prompt
    assert "Do not create branches or pull requests for this target." in prompt
    assert "CVE-2026-34040" in prompt


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


def test_reporting_excludes_github_forks_by_default() -> None:
    """Forked GitHub repositories should not drive reports or automation queues by default."""

    session = build_test_session()
    fork_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="core",
        full_name="Feberdin/core",
        local_path="/tmp/core",
        risk_score=95.0,
        metadata_json={"fork": True, "parent": {"full_name": "home-assistant/core"}},
    )
    session.add(fork_repository)
    session.flush()

    dependency = Dependency(
        repository_id=fork_repository.id,
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
        severity="critical",
    )
    session.add(vulnerability)
    session.flush()

    session.add_all(
        [
            DependencyVulnerability(
                dependency_id=dependency.id,
                vulnerability_id=vulnerability.id,
                risk_score=95.0,
                match_reason="Unit test match",
            ),
            Alert(
                repository_id=fork_repository.id,
                title="Potential secret in Feberdin/core",
                description="Fork-only finding",
                severity="critical",
                risk_score=95.0,
                fingerprint="fork-alert",
                status="open",
                source_type="secret_scanner",
                metadata_json={"detector": "github_token", "content_source": "working_tree"},
            ),
        ]
    )
    session.commit()

    service = ReportingService(version_catalog=FakeVersionCatalog())
    service.settings.github_include_forks = False

    report = service.build_report(session)
    systems = service.build_system_inventory(session)
    queue = service.build_high_risk_update_queue(session)

    assert report.repository_count == 0
    assert report.dependency_count == 0
    assert report.vulnerability_count == 0
    assert report.alert_count == 0
    assert systems == []
    assert queue.task_count == 0


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


def test_grouped_remediation_prompt_orders_groups_and_merges_owned_runtime_image() -> None:
    """Full-scan prompts should group owned repos with matching owned Unraid images first."""

    session = build_test_session()
    commit_sha = "a" * 40
    github_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="security-watchdog",
        full_name="Feberdin/security-watchdog",
        local_path="/tmp/security-watchdog",
        risk_score=82.5,
        metadata_json={"fork": False},
    )
    owned_container = Repository(
        source_type="unraid_docker",
        owner="unraid",
        name="security-watchdog",
        full_name="unraid/security-watchdog",
        local_path="",
        risk_score=90.0,
        metadata_json={
            "image": "ghcr.io/feberdin/security-watchdog:latest",
            "labels": {
                "org.opencontainers.image.source": "https://github.com/Feberdin/security-watchdog",
                "org.opencontainers.image.revision": commit_sha,
            },
        },
    )
    external_container = Repository(
        source_type="unraid_docker",
        owner="unraid",
        name="watchtower",
        full_name="unraid/watchtower",
        local_path="",
        risk_score=95.0,
        metadata_json={"image": "containrrr/watchtower:latest"},
    )
    homeassistant_asset = Repository(
        source_type="homeassistant",
        owner="homeassistant",
        name="hacs",
        full_name="homeassistant/hacs",
        local_path="",
        risk_score=85.0,
        metadata_json={"domain": "hacs"},
    )
    session.add_all([github_repository, owned_container, external_container, homeassistant_asset])
    session.flush()
    session.add(
        ScanResult(
            repository_id=github_repository.id,
            scanner_name="repository_asset_scan",
            status="success",
            findings_count=1,
            details_json={"commit_sha": commit_sha},
            completed_at=datetime(2026, 8, 4, 9, 30, tzinfo=UTC),
        )
    )
    dependency = Dependency(
        repository_id=github_repository.id,
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
    session.add_all(
        [
            Alert(
                repository_id=owned_container.id,
                title="Unraid container vulnerability in security-watchdog",
                description="Runtime image package vulnerability.",
                severity="critical",
                risk_score=90.0,
                fingerprint="owned-container-critical",
                status="open",
                source_type="unraid_container",
                metadata_json={
                    "vulnerability_id": "CVE-2026-1111",
                    "package_name": "openssl",
                    "target": "ghcr.io/feberdin/security-watchdog:latest",
                },
            ),
            Alert(
                repository_id=external_container.id,
                title="Unraid container vulnerability in watchtower",
                description="External runtime image vulnerability.",
                severity="critical",
                risk_score=95.0,
                fingerprint="external-container-critical",
                status="open",
                source_type="unraid_container",
                metadata_json={
                    "vulnerability_id": "CVE-2026-2222",
                    "package_name": "docker",
                    "target": "containrrr/watchtower:latest",
                },
            ),
            Alert(
                repository_id=homeassistant_asset.id,
                title="Home Assistant secret finding",
                description="High-confidence Home Assistant token pattern.",
                severity="high",
                risk_score=85.0,
                fingerprint="homeassistant-token",
                status="open",
                source_type="homeassistant_secret",
                metadata_json={
                    "detector": "github_token",
                    "content_source": "working_tree",
                    "file_path": ".storage/core.config_entries",
                },
            ),
        ]
    )
    session.commit()

    prompt = ReportingService(version_catalog=ExplodingVersionCatalog()).build_grouped_remediation_prompt(
        session
    )

    own_index = prompt.index("## Eigene GitHub-Repos und eigene Unraid-Container")
    external_index = prompt.index("## Fremde oder nicht zugeordnete Unraid-Container")
    homeassistant_index = prompt.index("## Home Assistant")
    assert own_index < external_index < homeassistant_index
    assert "## Eigene GitHub-Repos und eigene Unraid-Container derselben Source: Feberdin/security-watchdog" in prompt
    assert "System: Feberdin/security-watchdog" in prompt
    assert "System: unraid/security-watchdog" in prompt
    assert "GitHub scan commit and Unraid image revision match" in prompt
    assert "Create one branch and PR in `Feberdin/security-watchdog`" in prompt
    assert "System: unraid/watchtower" in prompt
    assert "System: homeassistant/hacs" in prompt


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
    """The daily automation runbook should stay fast and avoid live latest-version lookups."""

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

    runbook = ReportingService(version_catalog=ExplodingVersionCatalog()).build_daily_security_automation(
        session,
        max_tasks_per_run=2,
    )

    assert runbook.api_version == "2026-07-30"
    assert runbook.recommended_schedule == "daily"
    assert runbook.max_tasks_per_run == 2
    assert runbook.source_endpoints["runbook"] == "/automation/daily-security-check"
    assert runbook.queue.task_count == 1
    assert runbook.queue.tasks[0].dependencies[0].target_version is None
    assert runbook.queue.tasks[0].dependencies[0].latest_version_status == "skipped"
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
