"""
Purpose: Centralize the most common database write/read operations for scanners and services.
Input/Output: Accepts ORM sessions plus DTOs and returns ORM entities ready for later processing.
Important invariants: Repeated scans should overwrite ephemeral scan data instead of duplicating it;
alert fingerprints remain globally unique to prevent notification storms.
Debugging: If the UI shows duplicates or stale findings, start here and verify replacement logic.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, desc, func, select, update
from sqlalchemy.orm import Session

from app.core.utils import sha256_text, stable_json_dumps
from app.models.entities import (
    Alert,
    AlertStatus,
    ContainerImageScanCache,
    Dependency,
    DependencyVulnerability,
    ManualScanJob,
    ManualScanJobStatus,
    ManualScanProgressEvent,
    Repository,
    ScanResult,
    ThreatArticle,
    Vulnerability,
)
from app.models.schemas import (
    ContainerFinding,
    DependencyRecord,
    ScanRequest,
    ScanResponse,
    ThreatArticleRecord,
    VulnerabilityRecord,
)

LOGGER = logging.getLogger(__name__)
MANUAL_SCAN_RESUME_GRACE_SECONDS = 60
CONTAINER_IMAGE_SCANNER_VERSION = "trivy-grype-v1"


def utcnow() -> datetime:
    """Return an aware UTC timestamp to keep persistence code consistent."""

    return datetime.now(UTC)


def get_repository_by_full_name(session: Session, full_name: str) -> Repository | None:
    """Fetch a repository or synthetic asset by its unique name."""

    return session.scalar(select(Repository).where(Repository.full_name == full_name))


def upsert_repository(
    session: Session,
    *,
    source_type: str,
    owner: str,
    name: str,
    full_name: str,
    clone_url: str | None = None,
    default_branch: str = "",
    local_path: str = "",
    github_id: int | None = None,
    archived: bool = False,
    metadata: dict | None = None,
) -> Repository:
    """Create or update a repository-like asset from any source."""

    repository = get_repository_by_full_name(session, full_name)
    if repository is None:
        repository = Repository(
            source_type=source_type,
            owner=owner,
            name=name,
            full_name=full_name,
            clone_url=clone_url,
            default_branch=default_branch,
            local_path=local_path,
            github_id=github_id,
            archived=archived,
            metadata_json=metadata or {},
        )
        session.add(repository)
    else:
        repository.source_type = source_type
        repository.owner = owner
        repository.name = name
        repository.clone_url = clone_url
        repository.default_branch = default_branch
        repository.local_path = local_path
        repository.github_id = github_id
        repository.archived = archived
        repository.metadata_json = metadata or repository.metadata_json
    session.flush()
    return repository


def set_repository_scan_enabled(
    session: Session,
    *,
    repository_id: int,
    scan_enabled: bool,
) -> Repository | None:
    """Persist whether one repository-like asset participates in normal scans and reports."""

    repository = session.get(Repository, repository_id)
    if repository is None:
        return None

    repository.scan_enabled = scan_enabled
    session.flush()
    return repository


def set_repositories_scan_enabled_bulk(
    session: Session,
    *,
    repository_ids: list[int],
    scan_enabled: bool,
) -> list[Repository]:
    """Persist scan visibility for multiple repository-like assets in one operator action."""

    repositories = session.scalars(
        select(Repository).where(Repository.id.in_(repository_ids)).order_by(Repository.full_name.asc())
    ).all()
    for repository in repositories:
        repository.scan_enabled = scan_enabled
    session.flush()
    return repositories


def create_manual_scan_job(session: Session, request: ScanRequest) -> ManualScanJob:
    """Persist one queued manual scan request for later execution by a durable scan runner."""

    job = ManualScanJob(
        repository_full_name=request.repository_full_name,
        include_archived=request.include_archived,
        force=request.force,
        scan_sources_json=request.scan_sources,
        priority=request.priority,
        purpose=request.purpose,
        target_commit_sha=request.target_commit_sha,
        refresh_image_cache=request.refresh_image_cache,
        status=ManualScanJobStatus.QUEUED.value,
    )
    session.add(job)
    session.flush()
    return job


def record_manual_scan_progress(
    session: Session,
    *,
    job_id: int,
    phase: str,
    message: str,
    level: str,
    current: int,
    total: int,
    percent: float,
    retention_limit: int = 100,
) -> ManualScanProgressEvent:
    """Persist one progress line and keep only the newest bounded set for the job."""

    event = ManualScanProgressEvent(
        job_id=job_id,
        phase=phase,
        message=message,
        level=level,
        current=current,
        total=total,
        percent=percent,
    )
    session.add(event)
    session.flush()

    stale_event_ids = session.scalars(
        select(ManualScanProgressEvent.id)
        .where(ManualScanProgressEvent.job_id == job_id)
        .order_by(desc(ManualScanProgressEvent.id))
        .offset(retention_limit)
    ).all()
    if stale_event_ids:
        session.execute(
            delete(ManualScanProgressEvent).where(
                ManualScanProgressEvent.id.in_(stale_event_ids)
            )
        )
    return event


def list_manual_scan_progress_events(
    session: Session,
    *,
    job_id: int,
    limit: int = 12,
) -> list[ManualScanProgressEvent]:
    """Return the newest progress events in chronological order for readable UI output."""

    newest_first = session.scalars(
        select(ManualScanProgressEvent)
        .where(ManualScanProgressEvent.job_id == job_id)
        .order_by(desc(ManualScanProgressEvent.id))
        .limit(limit)
    ).all()
    return list(reversed(newest_first))


def get_manual_scan_job(session: Session, job_id: int) -> ManualScanJob | None:
    """Return one persisted manual scan job by primary key."""

    return session.get(ManualScanJob, job_id)


def get_latest_manual_scan_job(session: Session) -> ManualScanJob | None:
    """Return the newest manual scan job so the dashboard can restore visible scan state."""

    return session.scalar(
        select(ManualScanJob).order_by(desc(ManualScanJob.requested_at), desc(ManualScanJob.id))
    )


def get_active_manual_scan_job(session: Session) -> ManualScanJob | None:
    """Return the current queued or running manual scan, if any."""

    return session.scalar(
        select(ManualScanJob)
        .where(
            ManualScanJob.status.in_(
                [ManualScanJobStatus.QUEUED.value, ManualScanJobStatus.RUNNING.value]
            )
        )
        .order_by(ManualScanJob.requested_at.asc(), ManualScanJob.id.asc())
    )


def get_running_manual_scan_job(session: Session) -> ManualScanJob | None:
    """Return the currently running manual scan, if a worker owns one."""

    return session.scalar(
        select(ManualScanJob)
        .where(ManualScanJob.status == ManualScanJobStatus.RUNNING.value)
        .order_by(ManualScanJob.started_at.asc(), ManualScanJob.id.asc())
        .limit(1)
    )


def get_matching_queued_manual_scan_job(session: Session, request: ScanRequest) -> ManualScanJob | None:
    """Return an equivalent queued job so repeated clicks do not flood the queue."""

    return session.scalar(
        select(ManualScanJob)
        .where(
            ManualScanJob.status == ManualScanJobStatus.QUEUED.value,
            ManualScanJob.repository_full_name.is_(None)
            if request.repository_full_name is None
            else ManualScanJob.repository_full_name == request.repository_full_name,
            ManualScanJob.include_archived == request.include_archived,
            ManualScanJob.force == request.force,
            ManualScanJob.scan_sources_json == request.scan_sources,
            ManualScanJob.purpose == request.purpose,
            ManualScanJob.target_commit_sha.is_(None)
            if request.target_commit_sha is None
            else ManualScanJob.target_commit_sha == request.target_commit_sha,
            ManualScanJob.refresh_image_cache == request.refresh_image_cache,
        )
        .order_by(desc(ManualScanJob.priority), ManualScanJob.requested_at.asc(), ManualScanJob.id.asc())
        .limit(1)
    )


def fail_running_manual_scan_jobs(session: Session, *, error_message: str) -> int:
    """
    Atomically fail jobs that belonged to a previous scan-runner process.

    Why this exists:
    A process can stop after claiming a job but before storing its result. The replacement runner
    cannot resume the in-memory orchestration safely, so it records the interruption and frees the
    queue for a deliberate retry.
    """

    failure_result = session.execute(
        update(ManualScanJob)
        .where(ManualScanJob.status == ManualScanJobStatus.RUNNING.value)
        .values(
            status=ManualScanJobStatus.FAILED.value,
            completed_at=utcnow(),
            error_message=error_message,
        )
    )
    session.flush()
    return int(failure_result.rowcount or 0)


def request_manual_scan_cancel(session: Session, *, job_id: int) -> ManualScanJob | None:
    """
    Mark a queued or running manual scan for operator-requested cancellation.

    Why this exists:
    Long scans may be waiting on external scanner binaries. A cancellation request must therefore be
    durable and cooperative: queued jobs can stop immediately, while running jobs stop at the next
    cancellation checkpoint in the worker.
    """

    job = get_manual_scan_job(session, job_id)
    if job is None:
        return None

    if job.status == ManualScanJobStatus.QUEUED.value:
        job.status = ManualScanJobStatus.CANCELED.value
        job.cancel_requested = True
        job.completed_at = utcnow()
        job.error_message = None
    elif job.status == ManualScanJobStatus.RUNNING.value:
        job.cancel_requested = True
    session.flush()
    return job


def request_manual_scan_pause(session: Session, *, job_id: int) -> ManualScanJob | None:
    """
    Mark a queued or running scan for cooperative pause.

    Why this exists:
    High-priority targeted scans should be able to interrupt a long estate scan after the current
    safe checkpoint without losing already committed scan results.
    """

    job = get_manual_scan_job(session, job_id)
    if job is None:
        return None

    if job.status == ManualScanJobStatus.QUEUED.value:
        job.status = ManualScanJobStatus.PAUSED.value
        job.pause_requested = True
        job.completed_at = utcnow()
        job.error_message = None
    elif job.status == ManualScanJobStatus.RUNNING.value:
        job.pause_requested = True
    session.flush()
    return job


def resume_manual_scan_job(session: Session, *, job_id: int) -> ManualScanJob | None:
    """Move a paused manual scan back to the prioritized queue."""

    job = get_manual_scan_job(session, job_id)
    if job is None:
        return None
    if job.status != ManualScanJobStatus.PAUSED.value:
        return job

    job.status = ManualScanJobStatus.QUEUED.value
    job.pause_requested = False
    job.cancel_requested = False
    job.completed_at = None
    job.error_message = None
    session.flush()
    return job


def is_manual_scan_cancel_requested(session: Session, *, job_id: int) -> bool:
    """Return whether an operator has requested cancellation for one scan job."""

    return bool(
        session.scalar(
            select(ManualScanJob.cancel_requested).where(
                ManualScanJob.id == job_id,
                ManualScanJob.cancel_requested.is_(True),
            )
        )
    )


def is_manual_scan_pause_requested(session: Session, *, job_id: int) -> bool:
    """Return whether an operator has requested pause for one scan job."""

    return bool(
        session.scalar(
            select(ManualScanJob.pause_requested).where(
                ManualScanJob.id == job_id,
                ManualScanJob.pause_requested.is_(True),
            )
        )
    )


def claim_manual_scan_job(session: Session, *, job_id: int | None = None) -> ManualScanJob | None:
    """
    Atomically transition one queued job into the running state or resume a running job.

    Why this exists:
    A dedicated worker or embedded scheduler may overlap during startup. The conditional update
    below ensures only one runner wins the queued-job claim even if both notice the job at roughly
    the same time. A deployment can stop the worker after it already marked a job as running, so the
    queue worker also treats an older still-running job as resumable when there is no queued job
    left.
    """

    requested_job_id = job_id
    resume_existing_running = False
    if job_id is None:
        job_id = session.scalar(
            select(ManualScanJob.id)
            .where(ManualScanJob.status == ManualScanJobStatus.QUEUED.value)
            .order_by(desc(ManualScanJob.priority), ManualScanJob.requested_at.asc(), ManualScanJob.id.asc())
            .limit(1)
        )
    if job_id is None:
        resume_cutoff = utcnow() - timedelta(seconds=MANUAL_SCAN_RESUME_GRACE_SECONDS)
        job_id = session.scalar(
            select(ManualScanJob.id)
            .where(
                ManualScanJob.status == ManualScanJobStatus.RUNNING.value,
                ManualScanJob.started_at.is_not(None),
                ManualScanJob.started_at <= resume_cutoff,
            )
            .order_by(ManualScanJob.requested_at.asc(), ManualScanJob.id.asc())
            .limit(1)
        )
        resume_existing_running = job_id is not None
    if job_id is None:
        return None

    existing_job = get_manual_scan_job(session, job_id)
    if existing_job is None:
        return None
    if existing_job.status == ManualScanJobStatus.RUNNING.value:
        if requested_job_id is not None or not resume_existing_running:
            return None
        existing_job.completed_at = None
        existing_job.error_message = None
        session.flush()
        return existing_job

    claim_result = session.execute(
        update(ManualScanJob)
        .where(
            ManualScanJob.id == job_id,
            ManualScanJob.status == ManualScanJobStatus.QUEUED.value,
        )
        .values(
            status=ManualScanJobStatus.RUNNING.value,
            started_at=utcnow(),
            completed_at=None,
            error_message=None,
            cancel_requested=False,
            pause_requested=False,
        )
    )
    if claim_result.rowcount != 1:
        session.rollback()
        return None

    session.flush()
    return get_manual_scan_job(session, job_id)


def update_manual_scan_job_checkpoint(
    session: Session,
    *,
    job_id: int,
    repository_count: int,
    alert_count: int,
    failed_system_count: int,
) -> ManualScanJob | None:
    """
    Store durable progress counters for a running manual scan.

    Why this exists:
    Manual scans can outlive a container deployment. Persisting counters after each asset keeps the
    dashboard useful after restart and gives the resumed worker a conservative base count instead of
    resetting visible progress to zero.
    """

    job = get_manual_scan_job(session, job_id)
    if job is None:
        return None

    job.repository_count = repository_count
    job.alert_count = alert_count
    job.failed_system_count = failed_system_count
    session.flush()
    return job


def mark_manual_scan_job_succeeded(
    session: Session,
    *,
    job_id: int,
    response: ScanResponse,
) -> ManualScanJob | None:
    """Store the final counts for a successfully completed manual scan."""

    job = get_manual_scan_job(session, job_id)
    if job is None:
        return None

    job.status = ManualScanJobStatus.SUCCEEDED.value
    job.completed_at = utcnow()
    job.cancel_requested = False
    job.pause_requested = False
    job.repository_count = response.repository_count
    job.alert_count = response.alert_count
    job.failed_system_count = response.failed_system_count
    job.error_message = None
    session.flush()
    return job


def mark_manual_scan_job_failed(
    session: Session,
    *,
    job_id: int,
    error_message: str,
) -> ManualScanJob | None:
    """Persist the final failure state so operators can see what broke and when."""

    job = get_manual_scan_job(session, job_id)
    if job is None:
        return None

    job.status = ManualScanJobStatus.FAILED.value
    job.completed_at = utcnow()
    job.cancel_requested = False
    job.pause_requested = False
    job.error_message = error_message
    session.flush()
    return job


def mark_manual_scan_job_canceled(session: Session, *, job_id: int) -> ManualScanJob | None:
    """Persist the final operator-canceled state for a cooperative scan stop."""

    job = get_manual_scan_job(session, job_id)
    if job is None:
        return None

    job.status = ManualScanJobStatus.CANCELED.value
    job.completed_at = utcnow()
    job.cancel_requested = True
    job.pause_requested = False
    job.error_message = None
    session.flush()
    return job


def mark_manual_scan_job_paused(session: Session, *, job_id: int) -> ManualScanJob | None:
    """Persist an operator-paused state for a cooperative scan stop."""

    job = get_manual_scan_job(session, job_id)
    if job is None:
        return None

    job.status = ManualScanJobStatus.PAUSED.value
    job.completed_at = utcnow()
    job.pause_requested = True
    job.error_message = None
    session.flush()
    return job


def replace_repository_dependencies(
    session: Session, repository: Repository, dependencies: list[DependencyRecord]
) -> list[Dependency]:
    """Replace the dependency inventory for one repository-like asset."""

    existing_dependency_ids = session.scalars(
        select(Dependency.id).where(Dependency.repository_id == repository.id)
    ).all()
    if existing_dependency_ids:
        session.execute(
            delete(DependencyVulnerability).where(
                DependencyVulnerability.dependency_id.in_(existing_dependency_ids)
            )
        )
    session.execute(delete(Dependency).where(Dependency.repository_id == repository.id))

    deduplicated_dependencies = _deduplicate_dependency_records(dependencies)
    if len(deduplicated_dependencies) != len(dependencies):
        LOGGER.debug(
            "Deduplicated dependency records before replacement",
            extra={
                "repository": repository.full_name,
                "input_count": len(dependencies),
                "deduplicated_count": len(deduplicated_dependencies),
            },
        )

    orm_dependencies: list[Dependency] = []
    for dependency in deduplicated_dependencies:
        orm_dependency = Dependency(
            repository_id=repository.id,
            manifest_path=dependency.manifest_path,
            package_name=dependency.package_name,
            version=dependency.version,
            ecosystem=dependency.ecosystem,
            group_name=dependency.group_name,
            direct_dependency=dependency.direct_dependency,
            metadata_json=dependency.metadata,
        )
        session.add(orm_dependency)
        orm_dependencies.append(orm_dependency)
    repository.last_scanned_at = utcnow()
    session.flush()
    return orm_dependencies


def _deduplicate_dependency_records(dependencies: list[DependencyRecord]) -> list[DependencyRecord]:
    """
    Collapse scanner duplicates before they hit the database uniqueness constraint.

    Why this exists:
    Some manifests can report the same package/version pair more than once, for example Dockerfiles
    with repeated base stages or lockfiles plus direct manifests. The database intentionally stores
    one current row per repository, manifest, package, version, and ecosystem, so the in-memory scan
    result must follow the same identity rule before insertion.
    """

    deduplicated: dict[tuple[str, str, str, str], DependencyRecord] = {}
    for dependency in dependencies:
        key = (
            dependency.manifest_path,
            dependency.package_name,
            dependency.version,
            dependency.ecosystem,
        )
        existing = deduplicated.get(key)
        if existing is None:
            deduplicated[key] = dependency
            continue

        merged_metadata = {**dependency.metadata, **existing.metadata}
        deduplicated[key] = existing.model_copy(
            update={
                "direct_dependency": existing.direct_dependency or dependency.direct_dependency,
                "group_name": existing.group_name or dependency.group_name,
                "metadata": merged_metadata,
            }
        )
    return list(deduplicated.values())


def upsert_vulnerability(session: Session, record: VulnerabilityRecord) -> Vulnerability:
    """Create or update a normalized vulnerability entry."""

    vulnerability = session.scalar(
        select(Vulnerability).where(Vulnerability.source_identifier == record.source_identifier)
    )
    if vulnerability is None:
        vulnerability = Vulnerability(
            source=record.source,
            source_identifier=record.source_identifier,
            package_name=record.package_name,
            ecosystem=record.ecosystem,
            summary=record.summary,
            severity=record.severity,
            cvss_score=record.cvss_score,
            kev=record.kev,
            exploit_available=record.exploit_available,
            malicious_package=record.malicious_package,
            affected_versions=record.affected_versions,
            reference_urls=record.reference_urls,
            raw_payload=record.raw_payload,
        )
        session.add(vulnerability)
    else:
        vulnerability.summary = record.summary
        vulnerability.severity = record.severity
        vulnerability.cvss_score = record.cvss_score
        vulnerability.kev = record.kev
        vulnerability.exploit_available = record.exploit_available
        vulnerability.malicious_package = record.malicious_package
        vulnerability.affected_versions = record.affected_versions
        vulnerability.reference_urls = record.reference_urls
        vulnerability.raw_payload = record.raw_payload
    session.flush()
    return vulnerability


def link_dependency_to_vulnerability(
    session: Session,
    *,
    dependency_id: int,
    vulnerability_id: int,
    risk_score: float,
    match_reason: str,
) -> None:
    """Store one correlation result without duplicating existing links."""

    link = session.scalar(
        select(DependencyVulnerability).where(
            DependencyVulnerability.dependency_id == dependency_id,
            DependencyVulnerability.vulnerability_id == vulnerability_id,
        )
    )
    if link is None:
        link = DependencyVulnerability(
            dependency_id=dependency_id,
            vulnerability_id=vulnerability_id,
            risk_score=risk_score,
            match_reason=match_reason,
        )
        session.add(link)
    else:
        link.risk_score = risk_score
        link.match_reason = match_reason


def record_scan_result(
    session: Session,
    *,
    repository_id: int | None,
    scanner_name: str,
    status: str,
    findings_count: int,
    details: dict,
) -> None:
    """Persist a high-level scan outcome for auditability and troubleshooting."""

    session.add(
        ScanResult(
            repository_id=repository_id,
            scanner_name=scanner_name,
            status=status,
            findings_count=findings_count,
            started_at=utcnow(),
            completed_at=utcnow(),
            details_json=details,
        )
    )


def get_container_image_scan_cache(
    session: Session,
    *,
    image_identity: str,
    scanner_version: str = CONTAINER_IMAGE_SCANNER_VERSION,
) -> list[ContainerFinding] | None:
    """Return cached normalized image findings for one immutable image identity."""

    cache_entry = session.scalar(
        select(ContainerImageScanCache).where(
            ContainerImageScanCache.image_identity == image_identity,
            ContainerImageScanCache.scanner_version == scanner_version,
        )
    )
    if cache_entry is None:
        return None
    return [ContainerFinding(**finding) for finding in cache_entry.findings_json]


def upsert_container_image_scan_cache(
    session: Session,
    *,
    image_identity: str,
    image_ref: str,
    findings: list[ContainerFinding],
    scanner_version: str = CONTAINER_IMAGE_SCANNER_VERSION,
) -> ContainerImageScanCache:
    """Store or refresh scanner findings for one immutable image identity."""

    cache_entry = session.scalar(
        select(ContainerImageScanCache).where(
            ContainerImageScanCache.image_identity == image_identity,
            ContainerImageScanCache.scanner_version == scanner_version,
        )
    )
    findings_payload = [finding.model_dump() for finding in findings]
    if cache_entry is None:
        cache_entry = ContainerImageScanCache(
            image_identity=image_identity,
            image_ref=image_ref,
            scanner_version=scanner_version,
            findings_json=findings_payload,
            finding_count=len(findings),
            scanned_at=utcnow(),
        )
        session.add(cache_entry)
    else:
        cache_entry.image_ref = image_ref
        cache_entry.findings_json = findings_payload
        cache_entry.finding_count = len(findings)
        cache_entry.scanned_at = utcnow()
    session.flush()
    return cache_entry


def store_threat_article(session: Session, article: ThreatArticleRecord) -> ThreatArticle:
    """Insert a threat article if it is new, otherwise return the existing row."""

    content_hash = sha256_text(
        stable_json_dumps(
            {
                "url": article.source_url,
                "title": article.title,
                "body": article.normalized_text,
            }
        )
    )
    existing = session.scalar(
        select(ThreatArticle).where(ThreatArticle.source_url == article.source_url)
    )
    if existing:
        existing.source_type = article.source_type
        existing.title = article.title
        existing.published_at = article.published_at
        existing.content_hash = content_hash
        existing.raw_content = article.raw_content
        existing.normalized_text = article.normalized_text
        existing.tags = article.tags
        session.flush()
        return existing

    existing = session.scalar(
        select(ThreatArticle).where(ThreatArticle.content_hash == content_hash)
    )
    if existing:
        return existing

    threat_article = ThreatArticle(
        source_type=article.source_type,
        title=article.title,
        source_url=article.source_url,
        published_at=article.published_at,
        content_hash=content_hash,
        raw_content=article.raw_content,
        normalized_text=article.normalized_text,
        tags=article.tags,
    )
    session.add(threat_article)
    session.flush()
    return threat_article


def upsert_alert(
    session: Session,
    *,
    repository_id: int | None,
    title: str,
    description: str,
    severity: str,
    risk_score: float,
    source_type: str,
    metadata: dict,
) -> Alert:
    """Create or update an alert by deterministic fingerprint."""

    fingerprint = build_alert_fingerprint(
        repository_id=repository_id,
        title=title,
        source_type=source_type,
        metadata=metadata,
    )
    alert = session.scalar(select(Alert).where(Alert.fingerprint == fingerprint))
    if alert is None:
        alert = Alert(
            repository_id=repository_id,
            title=title,
            description=description,
            severity=severity,
            risk_score=risk_score,
            source_type=source_type,
            metadata_json=metadata,
            fingerprint=fingerprint,
        )
        session.add(alert)
    else:
        alert.description = description
        alert.severity = severity
        alert.risk_score = risk_score
        alert.metadata_json = metadata
        if alert.status == AlertStatus.RESOLVED.value:
            alert.status = AlertStatus.OPEN.value
    session.flush()
    return alert


def build_alert_fingerprint(
    *,
    repository_id: int | None,
    title: str,
    source_type: str,
    metadata: dict,
) -> str:
    """Build the deterministic alert fingerprint used for dedupe and stale-alert cleanup."""

    return sha256_text(
        stable_json_dumps(
            {
                "repository_id": repository_id,
                "title": title,
                "source_type": source_type,
                "metadata": _stable_fingerprint_metadata(source_type, metadata),
            }
        )
    )


def _stable_fingerprint_metadata(source_type: str, metadata: dict) -> dict:
    """
    Keep alert fingerprints tied to the finding identity, not to scan-run noise.

    Why this exists:
    Secret history scans can see the same leaked line in many commits. If the commit SHA is part of
    the alert fingerprint, repeated full scans create thousands of open "new" critical alerts for
    one operator action. The commit is still stored in alert metadata and description for triage,
    but the dedupe key stays focused on the actionable finding.
    """

    if source_type in {"secret_scanner", "homeassistant_secret"}:
        return {
            "file_path": metadata.get("file_path", ""),
            "line_number": metadata.get("line_number", ""),
            "detector": metadata.get("detector", ""),
            "excerpt": metadata.get("excerpt", ""),
            "content_source": metadata.get("content_source", ""),
        }
    if source_type in {"container_scanner", "unraid_container"}:
        return {
            "target": metadata.get("target") or metadata.get("image_ref") or "",
            "vulnerability_id": metadata.get("vulnerability_id", ""),
            "package_name": metadata.get("package_name", ""),
            "installed_version": metadata.get("installed_version", ""),
        }
    if source_type in {"dependency_vulnerability", "ai_correlation"}:
        return {
            "dependency": metadata.get("dependency", ""),
            "version": metadata.get("version", ""),
            "manifest_path": metadata.get("manifest_path", ""),
            "vulnerability": metadata.get("vulnerability", ""),
            "source_url": metadata.get("source_url", ""),
            "attack_type": metadata.get("attack_type", ""),
        }
    return metadata


def resolve_stale_alerts(
    session: Session,
    *,
    repository_id: int,
    source_types: list[str],
    active_fingerprints: set[str],
) -> int:
    """
    Resolve active alerts from prior scan runs that were not seen in the current run.

    Why this exists:
    Without explicit resolution, a repository keeps historical findings forever even when the
    dependency, secret, or container issue is gone. That inflates open-alert counts and distorts
    repository risk scores.
    """

    if not source_types:
        return 0

    resolved_count = 0
    alerts = session.scalars(
        select(Alert).where(
            Alert.repository_id == repository_id,
            Alert.source_type.in_(source_types),
            Alert.status != AlertStatus.RESOLVED.value,
        )
    ).all()
    for alert in alerts:
        if alert.fingerprint in active_fingerprints:
            continue
        alert.status = AlertStatus.RESOLVED.value
        resolved_count += 1
    session.flush()
    return resolved_count


def report_counts(session: Session) -> dict[str, int]:
    """Return the basic counters used by dashboards and health reporting."""

    return {
        "repositories": session.scalar(select(func.count(Repository.id))) or 0,
        "dependencies": session.scalar(select(func.count(Dependency.id))) or 0,
        "vulnerabilities": session.scalar(select(func.count(Vulnerability.id))) or 0,
        "alerts": session.scalar(select(func.count(Alert.id))) or 0,
    }
