"""
Purpose: Centralize the most common database write/read operations for scanners and services.
Input/Output: Accepts ORM sessions plus DTOs and returns ORM entities ready for later processing.
Important invariants: Repeated scans should overwrite ephemeral scan data instead of duplicating it;
alert fingerprints remain globally unique to prevent notification storms.
Debugging: If the UI shows duplicates or stale findings, start here and verify replacement logic.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.utils import sha256_text, stable_json_dumps
from app.models.entities import (
    Alert,
    AlertStatus,
    Dependency,
    DependencyVulnerability,
    Repository,
    ScanResult,
    ThreatArticle,
    Vulnerability,
)
from app.models.schemas import DependencyRecord, ThreatArticleRecord, VulnerabilityRecord

LOGGER = logging.getLogger(__name__)


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

    orm_dependencies: list[Dependency] = []
    for dependency in dependencies:
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
                "metadata": metadata,
            }
        )
    )


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
