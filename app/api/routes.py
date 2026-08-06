"""
Purpose: Expose REST endpoints for scans, reports, dependencies, alerts, and threat intelligence.
Input/Output: Accepts HTTP requests and returns validated Pydantic responses or dictionaries.
Important invariants: Routes should stay thin and delegate business logic to services so the same
workflows remain usable from the worker scheduler and future automation hooks.
Debugging: If an endpoint behaves differently from the worker job, compare the service call inputs.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import __version__
from app.api.dependencies import require_deployment_gate_token
from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.models.entities import (
    AIExtractedThreat,
    Alert,
    Dependency,
    ManualScanJob,
    Repository,
    ThreatArticle,
)
from app.models.schemas import (
    AlertOut,
    CodexPromptOut,
    DailySecurityAutomationOut,
    DeploymentGateStatusOut,
    DeploymentSecurityGateRequest,
    DeploymentSecurityGateResponse,
    HighRiskUpdateQueueOut,
    ManualScanJobOut,
    PreDeployScanRequest,
    ReportOut,
    RepositoryBulkScanSettingsRequest,
    RepositoryOut,
    RepositoryScanSettingsRequest,
    ScanAcceptedResponse,
    ScanRequest,
    SystemInventoryOut,
)
from app.repositories.store import set_repositories_scan_enabled_bulk, set_repository_scan_enabled
from app.services.deployment_security_gate import (
    DEPLOYMENT_GATE_API_VERSION,
    DeploymentSecurityGateService,
)
from app.services.manual_scan_jobs import (
    cancel_manual_scan_job,
    enqueue_manual_scan,
    get_latest_manual_scan_job_out,
    get_manual_scan_job_out,
    pause_manual_scan_job,
    resume_paused_manual_scan_job,
)
from app.services.reporting import ReportingService
from app.services.sarif import SarifReportingService

router = APIRouter()
LOGGER = logging.getLogger(__name__)


def _latest_jobs_by_repository(
    session: Session,
    repositories: list[Repository],
) -> dict[str, ManualScanJob]:
    """Load the newest persisted scan job for each requested repository in one bounded query."""

    repository_names = [repository.full_name for repository in repositories]
    if not repository_names:
        return {}

    newest_job_ids = (
        select(func.max(ManualScanJob.id))
        .where(ManualScanJob.repository_full_name.in_(repository_names))
        .group_by(ManualScanJob.repository_full_name)
    )
    jobs = session.scalars(
        select(ManualScanJob).where(ManualScanJob.id.in_(newest_job_ids))
    ).all()
    latest_jobs: dict[str, ManualScanJob] = {}
    for job in jobs:
        if job.repository_full_name is not None:
            latest_jobs.setdefault(job.repository_full_name, job)
    return latest_jobs


def _latest_job_for_repository(
    session: Session,
    repository_full_name: str,
) -> ManualScanJob | None:
    """Return the newest scan job used to enrich one repository response."""

    return session.scalar(
        select(ManualScanJob)
        .where(ManualScanJob.repository_full_name == repository_full_name)
        .order_by(desc(ManualScanJob.requested_at), desc(ManualScanJob.id))
        .limit(1)
    )


def _repository_out(
    repository: Repository,
    latest_job: ManualScanJob | None,
) -> RepositoryOut:
    """Build safe repository metadata used by the Broker without exposing clone credentials."""

    metadata = repository.metadata_json or {}
    checked_out_commit_sha = metadata.get("checked_out_commit_sha")
    if not isinstance(checked_out_commit_sha, str):
        checked_out_commit_sha = None
    return RepositoryOut.model_validate(repository).model_copy(
        update={
            "checked_out_commit_sha": checked_out_commit_sha,
            "latest_scanned_commit_sha": (
                latest_job.scanned_commit_sha if latest_job is not None else None
            ),
            "latest_scan_status": latest_job.status if latest_job is not None else None,
            "latest_scan_completed_at": (
                latest_job.completed_at if latest_job is not None else None
            ),
        }
    )


@router.get("/health")
def healthcheck(session: Session = Depends(get_db_session)) -> dict[str, str]:
    """Return bounded runtime readiness metadata without exposing configuration or secrets."""

    try:
        latest_job = get_latest_manual_scan_job_out(session)
    except SQLAlchemyError:
        LOGGER.warning("Health check could not query the database")
        return {
            "status": "degraded",
            "application_version": __version__,
            "gate_api_version": DEPLOYMENT_GATE_API_VERSION,
            "worker_status": "unknown",
            "database_status": "unavailable",
            "queue_status": "unavailable",
        }

    latest_status = latest_job.status if latest_job is not None else "idle"
    return {
        "status": "ok",
        "application_version": __version__,
        "gate_api_version": DEPLOYMENT_GATE_API_VERSION,
        "worker_status": "running" if latest_status == "running" else "ready",
        "database_status": "ready",
        "queue_status": latest_status,
    }


@router.post("/scan", response_model=ScanAcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(
    scan_request: ScanRequest,
    http_request: Request,
    session: Session = Depends(get_db_session),
) -> ScanAcceptedResponse:
    """Durably queue a manual full scan for the worker or embedded scheduler."""

    try:
        scan_job, created_new_job = enqueue_manual_scan(session, scan_request)
        session.commit()
        if created_new_job:
            message = "Manual scan accepted and queued for worker processing."
        else:
            message = "A manual scan is already queued or running; reusing the active job."
        return ScanAcceptedResponse(
            message=message,
            job_id=scan_job.id,
            status=scan_job.status,
            status_url=str(http_request.url_for("get_scan_job", job_id=scan_job.id)),
        )
    except Exception as error:
        session.rollback()
        LOGGER.exception(
            "Manual scan request failed",
            extra={
                "repository_full_name": scan_request.repository_full_name,
                "include_archived": scan_request.include_archived,
                "force": scan_request.force,
                "scan_sources": scan_request.scan_sources,
            },
        )
        raise HTTPException(status_code=500, detail=f"Manual scan enqueue failed: {error}") from error


@router.get("/scan-jobs/latest", response_model=ManualScanJobOut | None)
def get_latest_scan_job(
    repository_full_name: str | None = Query(default=None, min_length=3, max_length=255),
    session: Session = Depends(get_db_session),
) -> ManualScanJobOut | None:
    """Return the newest global or repository-scoped scan job."""

    return get_latest_manual_scan_job_out(
        session,
        repository_full_name=repository_full_name,
    )


@router.get("/scan-jobs/{job_id}", response_model=ManualScanJobOut)
def get_scan_job(job_id: int, session: Session = Depends(get_db_session)) -> ManualScanJobOut:
    """Return one manual scan job with counts, timestamps, and failure details."""

    job = get_manual_scan_job_out(session, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Manual scan job {job_id} was not found.")
    return job


@router.post("/scan-jobs/{job_id}/cancel", response_model=ManualScanJobOut)
def cancel_scan_job(job_id: int, session: Session = Depends(get_db_session)) -> ManualScanJobOut:
    """Request cooperative cancellation for one queued or running manual scan job."""

    try:
        job = cancel_manual_scan_job(session, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"Manual scan job {job_id} was not found.")
        session.commit()
        return job
    except HTTPException:
        session.rollback()
        raise
    except Exception as error:
        session.rollback()
        LOGGER.exception("Manual scan cancellation failed", extra={"job_id": job_id})
        raise HTTPException(status_code=500, detail=f"Manual scan cancellation failed: {error}") from error


@router.post("/scan-jobs/{job_id}/pause", response_model=ManualScanJobOut)
def pause_scan_job(job_id: int, session: Session = Depends(get_db_session)) -> ManualScanJobOut:
    """Request cooperative pause for one queued or running manual scan job."""

    try:
        job = pause_manual_scan_job(session, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"Manual scan job {job_id} was not found.")
        session.commit()
        return job
    except HTTPException:
        session.rollback()
        raise
    except Exception as error:
        session.rollback()
        LOGGER.exception("Manual scan pause failed", extra={"job_id": job_id})
        raise HTTPException(status_code=500, detail=f"Manual scan pause failed: {error}") from error


@router.post("/scan-jobs/{job_id}/resume", response_model=ManualScanJobOut)
def resume_scan_job(job_id: int, session: Session = Depends(get_db_session)) -> ManualScanJobOut:
    """Move one paused manual scan job back into the prioritized queue."""

    try:
        job = resume_paused_manual_scan_job(session, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"Manual scan job {job_id} was not found.")
        session.commit()
        return job
    except HTTPException:
        session.rollback()
        raise
    except Exception as error:
        session.rollback()
        LOGGER.exception("Manual scan resume failed", extra={"job_id": job_id})
        raise HTTPException(status_code=500, detail=f"Manual scan resume failed: {error}") from error


@router.get("/reports", response_model=ReportOut)
def get_report(session: Session = Depends(get_db_session)) -> ReportOut:
    """Return aggregated risk and activity metrics for operators."""

    return ReportingService().build_report(session)


@router.get("/reports/sarif")
def get_sarif_report(
    include_resolved: bool = False,
    limit: int = Query(default=500, ge=1, le=5000),
    session: Session = Depends(get_db_session),
) -> dict[str, Any]:
    """Return active alerts as SARIF so security tooling can consume the findings."""

    return SarifReportingService().build_report(
        session,
        include_resolved=include_resolved,
        limit=limit,
    )


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
def get_repositories(
    repository_full_name: str | None = Query(default=None, min_length=3, max_length=255),
    session: Session = Depends(get_db_session),
) -> list[RepositoryOut]:
    """Expose repository-like assets for dashboards and API consumers."""

    statement = select(Repository)
    if repository_full_name is not None:
        statement = statement.where(Repository.full_name == repository_full_name)
    repositories = session.scalars(
        statement.order_by(desc(Repository.updated_at)).limit(500)
    ).all()
    latest_jobs = _latest_jobs_by_repository(session, repositories)
    return [
        _repository_out(repository, latest_jobs.get(repository.full_name))
        for repository in repositories
    ]


@router.patch("/repositories/{repository_id}/scan-settings", response_model=RepositoryOut)
def update_repository_scan_settings(
    repository_id: int,
    settings_request: RepositoryScanSettingsRequest,
    session: Session = Depends(get_db_session),
) -> RepositoryOut:
    """Enable or disable future scans for one repository-like asset."""

    repository = set_repository_scan_enabled(
        session,
        repository_id=repository_id,
        scan_enabled=settings_request.scan_enabled,
    )
    if repository is None:
        session.rollback()
        raise HTTPException(status_code=404, detail=f"Repository/system {repository_id} was not found.")
    session.commit()
    return _repository_out(
        repository,
        _latest_job_for_repository(session, repository.full_name),
    )


@router.patch("/repositories/scan-settings/bulk", response_model=list[RepositoryOut])
def update_repository_scan_settings_bulk(
    settings_request: RepositoryBulkScanSettingsRequest,
    session: Session = Depends(get_db_session),
) -> list[RepositoryOut]:
    """Enable or disable future scans for multiple repository-like assets."""

    repositories = set_repositories_scan_enabled_bulk(
        session,
        repository_ids=settings_request.repository_ids,
        scan_enabled=settings_request.scan_enabled,
    )
    missing_ids = set(settings_request.repository_ids) - {repository.id for repository in repositories}
    if missing_ids:
        session.rollback()
        raise HTTPException(
            status_code=404,
            detail=f"Repository/system IDs not found: {sorted(missing_ids)}",
        )
    session.commit()
    latest_jobs = _latest_jobs_by_repository(session, repositories)
    return [
        _repository_out(repository, latest_jobs.get(repository.full_name))
        for repository in repositories
    ]


@router.get("/systems", response_model=list[SystemInventoryOut])
def get_systems(
    resolve_latest_versions: bool = Query(default=False),
    session: Session = Depends(get_db_session),
) -> list[SystemInventoryOut]:
    """Return all scanned systems with dependency details for the dashboard accordion view."""

    return ReportingService().build_system_inventory(
        session,
        resolve_latest_versions=resolve_latest_versions,
    )


@router.get("/automation/high-risk-updates", response_model=HighRiskUpdateQueueOut)
def get_high_risk_update_queue(
    limit: int = Query(default=25, ge=1, le=100),
    session: Session = Depends(get_db_session),
) -> HighRiskUpdateQueueOut:
    """Return the prioritized update queue that a Codex automation can process safely."""

    return ReportingService().build_high_risk_update_queue(session, limit=limit)


@router.get("/automation/high-risk-updates/codex-prompt", response_model=CodexPromptOut)
def get_high_risk_update_prompt(
    limit: int = Query(default=25, ge=1, le=100),
    session: Session = Depends(get_db_session),
) -> CodexPromptOut:
    """Generate the master prompt for a Codex high-risk update run."""

    return CodexPromptOut(
        title="Codex High-Risk Update Queue",
        prompt=ReportingService().build_high_risk_update_prompt(session, limit=limit),
    )


@router.get("/automation/grouped-remediation/codex-prompt", response_model=CodexPromptOut)
def get_grouped_remediation_prompt(
    limit: int = Query(default=200, ge=1, le=500),
    session: Session = Depends(get_db_session),
) -> CodexPromptOut:
    """Generate the full-scan remediation prompt grouped by ownership and runtime source."""

    return CodexPromptOut(
        title="Codex Grouped Security Watchdog Remediation",
        prompt=ReportingService().build_grouped_remediation_prompt(session, limit=limit),
    )


@router.get("/automation/daily-security-check", response_model=DailySecurityAutomationOut)
def get_daily_security_automation_runbook(
    limit: int = Query(default=25, ge=1, le=100),
    max_tasks_per_run: int = Query(default=3, ge=1, le=10),
    session: Session = Depends(get_db_session),
) -> DailySecurityAutomationOut:
    """Return the JSON runbook consumed by the recurring Codex security task."""

    return ReportingService().build_daily_security_automation(
        session,
        limit=limit,
        max_tasks_per_run=max_tasks_per_run,
    )


@router.post(
    "/automation/deployment-security-gate",
    response_model=DeploymentSecurityGateResponse,
)
def evaluate_deployment_security_gate(
    gate_request: DeploymentSecurityGateRequest,
    _authorized: None = Depends(require_deployment_gate_token),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(get_db_session),
) -> DeploymentSecurityGateResponse:
    """Return a fail-closed security decision for one exact deployment commit."""

    try:
        return DeploymentSecurityGateService(settings).evaluate(session, gate_request)
    except Exception as error:
        LOGGER.exception(
            "Deployment security gate evaluation failed",
            extra={
                "stack_name": gate_request.stack_name,
                "repository_full_name": gate_request.repository_full_name,
                "commit_sha": gate_request.commit_sha,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Deployment security gate could not evaluate the candidate. "
                "Deployment must remain blocked; inspect the Security Watchdog API logs."
            ),
        ) from error


@router.get("/automation/deployment-security-gate/status", response_model=DeploymentGateStatusOut)
def get_deployment_security_gate_status(
    stack_name: str,
    repository_full_name: str,
    commit_sha: str,
    compose_file: str = "docker-compose.yml",
    settings: Settings = Depends(get_settings),
    session: Session = Depends(get_db_session),
) -> DeploymentGateStatusOut:
    """Return dashboard-safe gate status without requiring the Broker token."""

    gate_request = DeploymentSecurityGateRequest(
        stack_name=stack_name,
        repository_full_name=repository_full_name,
        commit_sha=commit_sha,
        compose_file=compose_file,
    )
    gate = DeploymentSecurityGateService(settings).evaluate(session, gate_request)
    return DeploymentGateStatusOut(
        gate=gate,
        recommended_action=_recommended_gate_action(gate),
        can_queue_pre_deploy_scan=not gate.deploy_allowed,
    )


@router.post("/automation/pre-deploy-scan", response_model=ScanAcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
def queue_pre_deploy_scan(
    pre_deploy_request: PreDeployScanRequest,
    http_request: Request,
    session: Session = Depends(get_db_session),
) -> ScanAcceptedResponse:
    """Queue a focused high-priority scan for exact deployment-gate evidence."""

    scan_request = ScanRequest(
        repository_full_name=pre_deploy_request.repository_full_name,
        include_archived=False,
        force=True,
        scan_sources=["github"],
        priority=100,
        pause_active=pre_deploy_request.pause_active,
        purpose="pre_deploy",
        target_commit_sha=pre_deploy_request.commit_sha,
    )
    try:
        scan_job, created_new_job = enqueue_manual_scan(session, scan_request)
        session.commit()
        message = (
            "Pre-deploy scan accepted and queued for worker processing."
            if created_new_job
            else "An equivalent pre-deploy scan is already queued or active."
        )
        return ScanAcceptedResponse(
            message=message,
            job_id=scan_job.id,
            status=scan_job.status,
            status_url=str(http_request.url_for("get_scan_job", job_id=scan_job.id)),
        )
    except Exception as error:
        session.rollback()
        LOGGER.exception(
            "Pre-deploy scan request failed",
            extra={
                "stack_name": pre_deploy_request.stack_name,
                "repository_full_name": pre_deploy_request.repository_full_name,
                "commit_sha": pre_deploy_request.commit_sha,
            },
        )
        raise HTTPException(status_code=500, detail=f"Pre-deploy scan enqueue failed: {error}") from error


def _recommended_gate_action(gate: DeploymentSecurityGateResponse) -> str:
    """Return one compact operator action for dashboard and automation callers."""

    if gate.deploy_allowed:
        return "deploy"
    if any(
        code in gate.reason_codes
        for code in ("REPOSITORY_NOT_SCANNED", "SCANNED_COMMIT_MISMATCH", "NO_AGGREGATE_SCAN_EVIDENCE")
    ):
        return "queue_pre_deploy_scan"
    if "SCAN_EVIDENCE_STALE" in gate.reason_codes:
        return "queue_fresh_scan"
    return "review_blockers"


@router.get("/diagnostics/export")
def get_diagnostics_export(session: Session = Depends(get_db_session)) -> dict[str, Any]:
    """Return a compact platform snapshot that operators can paste into Codex for debugging."""

    return ReportingService().build_platform_debug_export(session)


@router.get("/diagnostics/alerts")
def get_alert_diagnostics(
    limit: int = Query(default=20, ge=1, le=100),
    session: Session = Depends(get_db_session),
) -> dict[str, Any]:
    """Return lightweight alert groupings for checking unexpectedly large counters."""

    return ReportingService().build_alert_diagnostics(session, limit=limit)


@router.get("/systems/{system_id}/codex-remediation", response_model=CodexPromptOut)
def get_codex_remediation_prompt(
    system_id: int,
    session: Session = Depends(get_db_session),
) -> CodexPromptOut:
    """Generate a remediation prompt for one selected system."""

    service = ReportingService()
    try:
        prompt = service.build_codex_remediation_prompt(session, system_id)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error

    return CodexPromptOut(
        title=f"Codex remediation prompt for system {system_id}",
        prompt=prompt,
    )


@router.get("/systems/{system_id}/debug-export")
def get_system_debug_export(
    system_id: int,
    session: Session = Depends(get_db_session),
) -> dict[str, Any]:
    """Return a structured debug snapshot for one selected system."""

    service = ReportingService()
    try:
        return service.build_system_debug_export(session, system_id)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
