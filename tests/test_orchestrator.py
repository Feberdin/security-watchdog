"""
Purpose: Verify the manual scan orchestrator stays resilient when one asset fails mid-run.
Input/Output: Builds an in-memory database, injects synthetic repositories, and forces one scan
branch to fail while another succeeds.
Important invariants: A single asset failure must not abort the whole manual scan because operators
need fresh data from the rest of the estate even when one repository or scanner is broken.
Debugging: If `/scan` starts returning 500 again, inspect the guarded helper methods in the
orchestrator and this regression test first.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import pairwise

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

import app.models.entities  # noqa: F401
from app.db.base import Base
from app.models.entities import ContainerImageScanCache, ManualScanJob, ManualScanJobStatus, Repository, ScanResult
from app.models.schemas import ContainerFinding, ScanProgressUpdate, ScanRequest
from app.services.orchestrator import ScanOrchestrator


def build_test_session() -> Session:
    """Create a throwaway in-memory database session for orchestrator tests."""

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return Session(engine)


def test_manual_scan_continues_when_one_repository_asset_fails() -> None:
    """One broken repository should be recorded as failed without aborting the full scan."""

    session = build_test_session()
    failing_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="broken-repo",
        full_name="Feberdin/broken-repo",
        local_path="/tmp/broken-repo",
    )
    healthy_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="healthy-repo",
        full_name="Feberdin/healthy-repo",
        local_path="/tmp/healthy-repo",
    )
    session.add_all([failing_repository, healthy_repository])
    session.commit()

    orchestrator = ScanOrchestrator()
    orchestrator.repository_scanner.sync_repositories = lambda *args, **kwargs: [
        failing_repository,
        healthy_repository,
    ]
    orchestrator.unraid_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator.homeassistant_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator._dispatch_open_alerts = lambda *args, **kwargs: None
    orchestrator.repository_scanner.get_checkout_commit_sha = lambda *args, **kwargs: "a" * 40

    def fake_repository_scan(
        _session: Session,
        repository: Repository,
        _progress=None,
        cancellation_check=None,
    ) -> int:
        if repository.id == failing_repository.id:
            raise RuntimeError("simulated repository scan failure")
        return 2

    orchestrator._scan_repository_asset = fake_repository_scan

    progress_updates: list[ScanProgressUpdate] = []
    response = orchestrator.run_manual_scan(
        session,
        ScanRequest(repository_full_name=None, include_archived=False, force=True),
        progress_callback=progress_updates.append,
    )

    failure_results = session.scalars(
        select(ScanResult).where(ScanResult.scanner_name == "repository_asset_scan")
    ).all()

    assert response.message == "Scan completed with warnings"
    assert response.repository_count == 2
    assert response.alert_count == 2
    assert response.failed_system_count == 1
    assert len(failure_results) == 2
    assert {result.repository_id: result.status for result in failure_results} == {
        failing_repository.id: "error",
        healthy_repository.id: "success",
    }
    healthy_result = next(result for result in failure_results if result.repository_id == healthy_repository.id)
    assert healthy_result.details_json["commit_sha"] == "a" * 40
    assert progress_updates[-1].phase == "finalizing"
    assert progress_updates[-1].percent == 98
    assert any(update.level == "warning" for update in progress_updates)
    assert all(current.percent <= following.percent for current, following in pairwise(progress_updates))


def test_manual_scan_targets_specific_commit_during_inventory_sync() -> None:
    """Pre-deploy scans should pass the target commit to repository sync."""

    session = build_test_session()
    orchestrator = ScanOrchestrator()
    requested_commit_sha = "a" * 40
    sync_kwargs: dict[str, object] = {}

    def fake_sync_repositories(
        *args,
        **kwargs,
    ) -> list:
        sync_kwargs["repository_full_name"] = kwargs.get("repository_full_name")
        sync_kwargs["include_archived"] = kwargs.get("include_archived")
        sync_kwargs["target_commit_sha"] = kwargs.get("target_commit_sha")
        return []

    orchestrator.repository_scanner.sync_repositories = fake_sync_repositories
    orchestrator.unraid_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator.homeassistant_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator._dispatch_open_alerts = lambda *args, **kwargs: None

    response = orchestrator.run_manual_scan(
        session,
        ScanRequest(
            repository_full_name="Feberdin/security-watchdog",
            include_archived=False,
            force=True,
            scan_sources=["github"],
            target_commit_sha=requested_commit_sha,
            purpose="pre_deploy",
        ),
    )

    assert sync_kwargs["repository_full_name"] == "Feberdin/security-watchdog"
    assert sync_kwargs["include_archived"] is False
    assert sync_kwargs["target_commit_sha"] == requested_commit_sha
    assert response.repository_count == 0


def test_manual_scan_resume_uses_existing_asset_outcomes_and_updates_checkpoint() -> None:
    """A resumed scan should skip durable successes/failures and continue with pending assets."""

    session = build_test_session()
    job_started_at = datetime.now(UTC) - timedelta(minutes=10)
    already_scanned_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="already-scanned",
        full_name="Feberdin/already-scanned",
        local_path="/tmp/already-scanned",
        last_scanned_at=datetime.now(UTC) - timedelta(minutes=2),
    )
    already_failed_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="already-failed",
        full_name="Feberdin/already-failed",
        local_path="/tmp/already-failed",
    )
    pending_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="pending-repo",
        full_name="Feberdin/pending-repo",
        local_path="/tmp/pending-repo",
    )
    job = ManualScanJob(
        status=ManualScanJobStatus.RUNNING.value,
        started_at=job_started_at,
    )
    session.add_all([already_scanned_repository, already_failed_repository, pending_repository, job])
    session.flush()
    session.add(
        ScanResult(
            repository_id=already_failed_repository.id,
            scanner_name="repository_asset_scan",
            status="error",
            findings_count=0,
            started_at=datetime.now(UTC) - timedelta(minutes=1),
            completed_at=datetime.now(UTC) - timedelta(minutes=1),
            details_json={"error": "previous failure"},
        )
    )
    session.commit()

    orchestrator = ScanOrchestrator()
    orchestrator.repository_scanner.sync_repositories = lambda *args, **kwargs: [
        already_scanned_repository,
        already_failed_repository,
        pending_repository,
    ]
    orchestrator.unraid_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator.homeassistant_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator._dispatch_open_alerts = lambda *args, **kwargs: None
    orchestrator.repository_scanner.get_checkout_commit_sha = lambda *args, **kwargs: "b" * 40
    scanned_repositories: list[str] = []

    def fake_repository_scan(
        _session: Session,
        repository: Repository,
        _progress=None,
        cancellation_check=None,
    ) -> int:
        scanned_repositories.append(repository.full_name)
        return 3

    orchestrator._scan_repository_asset = fake_repository_scan

    response = orchestrator.run_manual_scan(
        session,
        ScanRequest(repository_full_name=None, include_archived=False, force=True),
        job_id=job.id,
        resume_started_at=job_started_at,
    )
    stored_job = session.get(ManualScanJob, job.id)

    assert scanned_repositories == ["Feberdin/pending-repo"]
    assert response.repository_count == 3
    assert response.alert_count == 3
    assert response.failed_system_count == 1
    assert stored_job is not None
    assert stored_job.repository_count == 3
    assert stored_job.alert_count == 3
    assert stored_job.failed_system_count == 1


def test_manual_scan_resume_does_not_double_count_checkpointed_assets() -> None:
    """Counters already stored on the job row should not be inflated by skipped assets."""

    session = build_test_session()
    job_started_at = datetime.now(UTC) - timedelta(minutes=10)
    already_scanned_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="already-scanned",
        full_name="Feberdin/already-scanned",
        local_path="/tmp/already-scanned",
        last_scanned_at=datetime.now(UTC) - timedelta(minutes=2),
    )
    pending_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="pending-repo",
        full_name="Feberdin/pending-repo",
        local_path="/tmp/pending-repo",
    )
    job = ManualScanJob(
        status=ManualScanJobStatus.RUNNING.value,
        started_at=job_started_at,
        repository_count=1,
        alert_count=4,
        failed_system_count=0,
    )
    session.add_all([already_scanned_repository, pending_repository, job])
    session.commit()

    orchestrator = ScanOrchestrator()
    orchestrator.repository_scanner.sync_repositories = lambda *args, **kwargs: [
        already_scanned_repository,
        pending_repository,
    ]
    orchestrator.unraid_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator.homeassistant_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator._dispatch_open_alerts = lambda *args, **kwargs: None
    orchestrator.repository_scanner.get_checkout_commit_sha = lambda *args, **kwargs: "b" * 40
    scanned_repositories: list[str] = []

    def fake_repository_scan(
        _session: Session,
        repository: Repository,
        _progress=None,
        cancellation_check=None,
    ) -> int:
        scanned_repositories.append(repository.full_name)
        return 2

    orchestrator._scan_repository_asset = fake_repository_scan

    response = orchestrator.run_manual_scan(
        session,
        ScanRequest(repository_full_name=None, include_archived=False, force=True),
        job_id=job.id,
        resume_started_at=job_started_at,
    )
    stored_job = session.get(ManualScanJob, job.id)

    assert scanned_repositories == ["Feberdin/pending-repo"]
    assert response.repository_count == 2
    assert response.alert_count == 6
    assert response.failed_system_count == 0
    assert stored_job is not None
    assert stored_job.repository_count == 2
    assert stored_job.alert_count == 6


def test_manual_scan_respects_source_selection() -> None:
    """A source-specific request should avoid unrelated inventory and scan stages."""

    session = build_test_session()
    unraid_repository = Repository(
        source_type="unraid_docker",
        owner="unraid",
        name="app",
        full_name="unraid/app",
        local_path="",
    )
    session.add(unraid_repository)
    session.commit()

    orchestrator = ScanOrchestrator()
    orchestrator.repository_scanner.sync_repositories = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("GitHub inventory should not run for an Unraid-only scan")
    )
    orchestrator.homeassistant_scanner.sync_assets = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("Home Assistant inventory should not run for an Unraid-only scan")
    )
    orchestrator.unraid_scanner.sync_assets = lambda *args, **kwargs: [
        {"repository": unraid_repository, "image_ref": "example/app:latest"}
    ]
    orchestrator._dispatch_open_alerts = lambda *args, **kwargs: None
    scanned_assets: list[str] = []

    def fake_unraid_scan(
        _session: Session,
        repository: Repository,
        image_ref: str,
        image_identity: str | None = None,
        *,
        refresh_image_cache: bool = False,
        progress=None,
        cancellation_check=None,
    ) -> int:
        scanned_assets.append(f"{repository.full_name}:{image_ref}")
        assert image_identity is None
        assert refresh_image_cache is False
        assert progress is not None
        return 1

    orchestrator._scan_unraid_asset = fake_unraid_scan

    response = orchestrator.run_manual_scan(
        session,
        ScanRequest(
            repository_full_name=None,
            include_archived=False,
            force=True,
            scan_sources=["unraid"],
        ),
    )

    assert scanned_assets == ["unraid/app:example/app:latest"]
    assert response.repository_count == 1
    assert response.alert_count == 1


def test_container_image_scan_reuses_cached_findings_by_image_identity() -> None:
    """Immutable image identities should avoid repeat Trivy/Grype scans across assets."""

    session = build_test_session()
    orchestrator = ScanOrchestrator()

    class FakeContainerScanner:
        """Count image scans while returning one normalized finding."""

        calls = 0

        def scan_image(self, image_ref: str) -> list[ContainerFinding]:
            self.calls += 1
            return [
                ContainerFinding(
                    tool="trivy",
                    target=image_ref,
                    vulnerability_id="CVE-2026-0001",
                    package_name="openssl",
                    installed_version="1.0.0",
                    severity="high",
                    fix_version="1.0.1",
                    description="Synthetic image finding",
                )
            ]

    fake_scanner = FakeContainerScanner()
    orchestrator.container_scanner = fake_scanner

    first_findings, first_cache_hit = orchestrator._scan_container_image(
        session,
        image_ref="example/app:latest",
        image_identity="example/app@sha256:abc",
        refresh_image_cache=False,
    )
    second_findings, second_cache_hit = orchestrator._scan_container_image(
        session,
        image_ref="example/app:latest",
        image_identity="example/app@sha256:abc",
        refresh_image_cache=False,
    )
    refreshed_findings, refreshed_cache_hit = orchestrator._scan_container_image(
        session,
        image_ref="example/app:latest",
        image_identity="example/app@sha256:abc",
        refresh_image_cache=True,
    )
    cache_entries = session.scalars(select(ContainerImageScanCache)).all()

    assert fake_scanner.calls == 2
    assert first_cache_hit is False
    assert second_cache_hit is True
    assert refreshed_cache_hit is False
    assert first_findings == second_findings == refreshed_findings
    assert len(cache_entries) == 1
    assert cache_entries[0].finding_count == 1


def test_manual_scan_skips_disabled_repositories() -> None:
    """Disabled repositories should stay in inventory history but not receive new scan work."""

    session = build_test_session()
    disabled_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="disabled",
        full_name="Feberdin/disabled",
        local_path="/tmp/disabled",
        scan_enabled=False,
    )
    enabled_repository = Repository(
        source_type="github",
        owner="Feberdin",
        name="enabled",
        full_name="Feberdin/enabled",
        local_path="/tmp/enabled",
    )
    session.add_all([disabled_repository, enabled_repository])
    session.commit()

    orchestrator = ScanOrchestrator()
    orchestrator.repository_scanner.sync_repositories = lambda *args, **kwargs: [
        disabled_repository,
        enabled_repository,
    ]
    orchestrator.unraid_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator.homeassistant_scanner.sync_assets = lambda *args, **kwargs: []
    orchestrator._dispatch_open_alerts = lambda *args, **kwargs: None
    orchestrator.repository_scanner.get_checkout_commit_sha = lambda *args, **kwargs: "c" * 40
    scanned_repositories: list[str] = []

    def fake_repository_scan(
        _session: Session,
        repository: Repository,
        _progress=None,
        cancellation_check=None,
    ) -> int:
        scanned_repositories.append(repository.full_name)
        return 1

    orchestrator._scan_repository_asset = fake_repository_scan

    response = orchestrator.run_manual_scan(
        session,
        ScanRequest(repository_full_name=None, include_archived=False, force=True),
    )

    assert scanned_repositories == ["Feberdin/enabled"]
    assert response.repository_count == 1
    assert response.alert_count == 1
