"""
Purpose: Expose REST endpoints for scans, reports, dependencies, alerts, and threat intelligence.
Input/Output: Accepts HTTP requests and returns validated Pydantic responses or dictionaries.
Important invariants: Routes should stay thin and delegate business logic to services so the same
workflows remain usable from the worker scheduler and future automation hooks.
Debugging: If an endpoint behaves differently from the worker job, compare the service call inputs.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.models.entities import AIExtractedThreat, Alert, Dependency, Repository, ThreatArticle
from app.models.schemas import (
    AlertOut,
    ReportOut,
    RepositoryOut,
    ScanRequest,
    ScanResponse,
    SystemInventoryOut,
)
from app.services.orchestrator import ScanOrchestrator
from app.services.reporting import ReportingService

router = APIRouter()


@router.get("/health")
def healthcheck() -> dict[str, str]:
    """Simple liveness endpoint for Docker health checks and reverse proxies."""

    return {"status": "ok"}


@router.post("/scan", response_model=ScanResponse)
def trigger_scan(
    request: ScanRequest,
    session: Session = Depends(get_db_session),
) -> ScanResponse:
    """Run a manual full scan across GitHub, Unraid, and Home Assistant assets."""

    orchestrator = ScanOrchestrator()
    response = orchestrator.run_manual_scan(session, request)
    session.commit()
    return response


@router.get("/reports", response_model=ReportOut)
def get_report(session: Session = Depends(get_db_session)) -> ReportOut:
    """Return aggregated risk and activity metrics for operators."""

    return ReportingService().build_report(session)


@router.get("/alerts", response_model=list[AlertOut])
def get_alerts(session: Session = Depends(get_db_session)) -> list[AlertOut]:
    """Return the newest alerts first."""

    alerts = session.scalars(select(Alert).order_by(desc(Alert.created_at)).limit(100)).all()
    return [AlertOut.model_validate(alert) for alert in alerts]


@router.get("/dependencies")
def get_dependencies(session: Session = Depends(get_db_session)) -> list[dict]:
    """Return normalized dependency records with repository context."""

    dependencies = session.scalars(select(Dependency).order_by(desc(Dependency.updated_at)).limit(500)).all()
    return [
        {
            "repository_id": dependency.repository_id,
            "package_name": dependency.package_name,
            "version": dependency.version,
            "ecosystem": dependency.ecosystem,
            "manifest_path": dependency.manifest_path,
            "metadata": dependency.metadata_json,
        }
        for dependency in dependencies
    ]


@router.get("/threats")
def get_threats(session: Session = Depends(get_db_session)) -> dict[str, list[dict]]:
    """Return recent articles and AI-extracted threat records."""

    articles = session.scalars(select(ThreatArticle).order_by(desc(ThreatArticle.created_at)).limit(50)).all()
    threats = session.scalars(
        select(AIExtractedThreat).order_by(desc(AIExtractedThreat.created_at)).limit(100)
    ).all()
    return {
        "articles": [
            {
                "id": article.id,
                "source_type": article.source_type,
                "title": article.title,
                "source_url": article.source_url,
                "published_at": article.published_at,
                "processed_by_ai": article.processed_by_ai,
            }
            for article in articles
        ],
        "extracted_threats": [
            {
                "id": threat.id,
                "package_name": threat.package_name,
                "ecosystem": threat.ecosystem,
                "affected_versions": threat.affected_versions,
                "attack_type": threat.attack_type,
                "confidence_score": threat.confidence_score,
                "source_url": threat.source_url,
                "summary": threat.summary,
            }
            for threat in threats
        ],
    }


@router.get("/repositories", response_model=list[RepositoryOut])
def get_repositories(session: Session = Depends(get_db_session)) -> list[RepositoryOut]:
    """Expose repository-like assets for dashboards and API consumers."""

    repositories = session.scalars(select(Repository).order_by(desc(Repository.updated_at)).limit(500)).all()
    return [RepositoryOut.model_validate(repository) for repository in repositories]


@router.get("/systems", response_model=list[SystemInventoryOut])
def get_systems(session: Session = Depends(get_db_session)) -> list[SystemInventoryOut]:
    """Return all scanned systems with dependency details for the dashboard accordion view."""

    return ReportingService().build_system_inventory(session)
