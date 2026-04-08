"""
Purpose: Build aggregated reports for the API and dashboard from persisted scan data.
Input/Output: Reads the database and returns `ReportOut` summary objects.
Important invariants: Reporting should stay read-only and deterministic so it is safe for repeated
dashboard refreshes; latest-version lookups are best-effort enrichments and must never break the
main report if an upstream registry is slow or temporarily unavailable.
Debugging: If a dashboard card looks wrong, compare the raw query result with this aggregation code.
"""

from __future__ import annotations

from datetime import UTC, datetime
from packaging.version import InvalidVersion, Version

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, selectinload

from app.models.entities import Alert, Dependency, DependencyVulnerability, Repository, Vulnerability
from app.models.schemas import AlertOut, DependencyInsightOut, ReportOut, SystemInventoryOut
from app.services.matching import normalize_version
from app.services.version_catalog import LatestVersionRecord, VersionCatalogService

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
DEFAULT_VERSION_CATALOG = VersionCatalogService()


class ReportingService:
    """Read-model builder for reports and dashboards."""

    def __init__(self, version_catalog: VersionCatalogService | None = None) -> None:
        self.version_catalog = version_catalog or DEFAULT_VERSION_CATALOG

    def build_report(self, session: Session) -> ReportOut:
        """Aggregate the main metrics needed by operators."""

        repository_count = session.scalar(select(func.count(Repository.id))) or 0
        dependency_count = session.scalar(select(func.count(Dependency.id))) or 0
        vulnerability_count = session.scalar(select(func.count(Vulnerability.id))) or 0
        alert_count = session.scalar(select(func.count(Alert.id))) or 0
        critical_alert_count = (
            session.scalar(select(func.count(Alert.id)).where(Alert.severity == "critical")) or 0
        )

        repository_risk = [
            {"full_name": repository.full_name, "source_type": repository.source_type, "risk_score": repository.risk_score}
            for repository in session.scalars(
                select(Repository).order_by(desc(Repository.risk_score)).limit(10)
            )
        ]

        recent_alerts = [
            AlertOut.model_validate(alert)
            for alert in session.scalars(select(Alert).order_by(desc(Alert.created_at)).limit(10))
        ]

        top_vulnerabilities = [
            {
                "source_identifier": source_identifier,
                "package_name": package_name,
                "severity": severity,
                "affected_dependencies": affected_dependencies,
            }
            for source_identifier, package_name, severity, affected_dependencies in session.execute(
                select(
                    Vulnerability.source_identifier,
                    Vulnerability.package_name,
                    Vulnerability.severity,
                    func.count(DependencyVulnerability.id).label("affected_dependencies"),
                )
                .join(DependencyVulnerability, DependencyVulnerability.vulnerability_id == Vulnerability.id)
                .group_by(Vulnerability.id)
                .order_by(desc("affected_dependencies"))
                .limit(10)
            )
        ]

        return ReportOut(
            generated_at=datetime.now(UTC),
            repository_count=repository_count,
            dependency_count=dependency_count,
            vulnerability_count=vulnerability_count,
            alert_count=alert_count,
            critical_alert_count=critical_alert_count,
            repository_risk=repository_risk,
            recent_alerts=recent_alerts,
            top_vulnerabilities=top_vulnerabilities,
        )

    def build_system_inventory(self, session: Session) -> list[SystemInventoryOut]:
        """Return all tracked systems with expandable dependency detail for the dashboard."""

        repositories = session.scalars(
            select(Repository)
            .options(
                selectinload(Repository.dependencies)
                .selectinload(Dependency.vulnerability_links)
                .selectinload(DependencyVulnerability.vulnerability),
                selectinload(Repository.alerts),
            )
            .order_by(desc(Repository.risk_score), Repository.full_name)
        ).all()

        systems: list[SystemInventoryOut] = []
        for repository in repositories:
            dependencies = [
                self._build_dependency_insight(dependency)
                for dependency in sorted(
                    repository.dependencies,
                    key=lambda item: (
                        -self._dependency_risk_score(item),
                        item.package_name.lower(),
                        item.manifest_path.lower(),
                    ),
                )
            ]
            vulnerable_dependency_count = len(
                [dependency for dependency in dependencies if dependency.risk_score > 0]
            )
            open_alert_count = len(
                [alert for alert in repository.alerts if alert.status != "resolved"]
            )
            systems.append(
                SystemInventoryOut(
                    id=repository.id,
                    owner=repository.owner,
                    name=repository.name,
                    full_name=repository.full_name,
                    display_name=self._build_display_name(repository),
                    source_type=repository.source_type,
                    risk_score=repository.risk_score,
                    dependency_count=len(dependencies),
                    vulnerable_dependency_count=vulnerable_dependency_count,
                    open_alert_count=open_alert_count,
                    last_scanned_at=repository.last_scanned_at,
                    summary=self._build_system_summary(repository),
                    dependencies=dependencies,
                )
            )
        return systems

    def _build_dependency_insight(self, dependency: Dependency) -> DependencyInsightOut:
        """Transform one ORM dependency into a dashboard-friendly row."""

        vulnerabilities = [
            link.vulnerability
            for link in dependency.vulnerability_links
            if link.vulnerability is not None
        ]
        latest_version = self.version_catalog.resolve_latest_version(
            dependency.ecosystem,
            dependency.package_name,
        )
        risk_severity = self._highest_vulnerability_severity(vulnerabilities)
        risk_score = self._dependency_risk_score(dependency)
        return DependencyInsightOut(
            package_name=dependency.package_name,
            ecosystem=dependency.ecosystem,
            manifest_path=dependency.manifest_path,
            detected_version=dependency.version,
            latest_version=latest_version.latest_version,
            latest_version_status=self._classify_version_status(
                dependency.version,
                latest_version,
            ),
            latest_version_source=latest_version.source,
            risk_severity=risk_severity,
            risk_score=risk_score,
            vulnerability_ids=[vulnerability.source_identifier for vulnerability in vulnerabilities],
        )

    def _build_display_name(self, repository: Repository) -> str:
        """Prefer friendly names from metadata when available, otherwise fall back to full_name."""

        metadata = repository.metadata_json or {}
        for key in ("title", "location_name", "domain", "container_name"):
            if metadata.get(key):
                return str(metadata[key])
        return repository.full_name

    def _build_system_summary(self, repository: Repository) -> str:
        """Create a one-line summary that helps operators orient quickly."""

        metadata = repository.metadata_json or {}
        summary_bits = [repository.source_type]
        if metadata.get("homeassistant_version"):
            summary_bits.append(f"Home Assistant {metadata['homeassistant_version']}")
        if metadata.get("time_zone"):
            summary_bits.append(f"TZ {metadata['time_zone']}")
        if metadata.get("image_ref"):
            summary_bits.append(str(metadata["image_ref"]))
        if repository.local_path:
            summary_bits.append(repository.local_path)
        return " | ".join(summary_bits)

    def _highest_vulnerability_severity(self, vulnerabilities: list[Vulnerability]) -> str:
        """Return the strongest severity across all linked vulnerabilities."""

        if not vulnerabilities:
            return "none"
        return max(
            (str(vulnerability.severity).lower() for vulnerability in vulnerabilities),
            key=lambda severity: SEVERITY_ORDER.get(severity, 0),
        )

    def _dependency_risk_score(self, dependency: Dependency) -> float:
        """Return the highest stored risk score for one dependency."""

        return max((float(link.risk_score) for link in dependency.vulnerability_links), default=0.0)

    def _classify_version_status(
        self,
        detected_version: str,
        latest_version: LatestVersionRecord,
    ) -> str:
        """Classify whether a dependency appears current, outdated, constrained, or unknown."""

        if not latest_version.latest_version:
            return "unknown"

        stripped_version = detected_version.strip()
        if not stripped_version or stripped_version == "unspecified":
            return "unknown"
        if stripped_version.startswith(("^", "~", "<", ">", "!")):
            return "constraint"
        normalized_detected = normalize_version(stripped_version)
        normalized_latest = normalize_version(latest_version.latest_version)
        try:
            if Version(normalized_detected) < Version(normalized_latest):
                return "outdated"
            return "current"
        except InvalidVersion:
            return "outdated" if normalized_detected != normalized_latest else "current"
