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

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

import app.models.entities  # noqa: F401
from app.db.base import Base
from app.models.entities import Repository, ScanResult
from app.models.schemas import ScanRequest
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

    def fake_repository_scan(_session: Session, repository: Repository) -> int:
        if repository.id == failing_repository.id:
            raise RuntimeError("simulated repository scan failure")
        return 2

    orchestrator._scan_repository_asset = fake_repository_scan

    response = orchestrator.run_manual_scan(
        session,
        ScanRequest(repository_full_name=None, include_archived=False, force=True),
    )

    failure_results = session.scalars(
        select(ScanResult).where(ScanResult.scanner_name == "repository_asset_scan")
    ).all()

    assert response.message == "Scan completed with warnings"
    assert response.repository_count == 2
    assert response.alert_count == 2
    assert response.failed_system_count == 1
    assert len(failure_results) == 1
    assert failure_results[0].repository_id == failing_repository.id
    assert failure_results[0].status == "error"
