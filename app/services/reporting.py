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
from typing import Any
from packaging.version import InvalidVersion, Version

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, selectinload

from app.models.entities import (
    Alert,
    Dependency,
    DependencyVulnerability,
    Repository,
    ScanResult,
    Vulnerability,
)
from app.models.schemas import (
    AlertOut,
    DependencyInsightOut,
    ReportOut,
    RuntimeFindingOut,
    SystemInventoryOut,
)
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
        active_alert_filter = Alert.status != "resolved"
        alert_count = session.scalar(select(func.count(Alert.id)).where(active_alert_filter)) or 0
        critical_alert_count = (
            session.scalar(
                select(func.count(Alert.id)).where(
                    active_alert_filter,
                    Alert.severity == "critical",
                )
            )
            or 0
        )

        repository_risk = [
            {"full_name": repository.full_name, "source_type": repository.source_type, "risk_score": repository.risk_score}
            for repository in session.scalars(
                select(Repository).order_by(desc(Repository.risk_score)).limit(10)
            )
        ]

        recent_alerts = [
            AlertOut.model_validate(alert)
            for alert in session.scalars(
                select(Alert)
                .where(active_alert_filter)
                .order_by(desc(Alert.updated_at))
                .limit(10)
            )
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

        repositories = self._load_repositories_with_inventory(session)
        return [self._build_system_entry(repository) for repository in repositories]

    def build_platform_debug_export(self, session: Session) -> dict[str, Any]:
        """Return a compact structured export that operators can paste into Codex for diagnosis."""

        report = self.build_report(session)
        systems = self.build_system_inventory(session)
        suspicious_systems = [
            self._build_debug_system_entry(system)
            for system in systems
            if system.open_alert_count > 0
            or system.vulnerable_dependency_count > 0
            or any(dependency.was_compromised for dependency in system.dependencies)
            or bool(system.runtime_findings)
        ]
        suspicious_names = {entry["full_name"] for entry in suspicious_systems}
        healthy_systems = [
            {
                "full_name": system.full_name,
                "source_type": system.source_type,
                "dependency_count": system.dependency_count,
                "last_scanned_at": system.last_scanned_at,
            }
            for system in systems
            if system.full_name not in suspicious_names
        ]

        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "report": report.model_dump(mode="json"),
            "diagnostics": {
                "suspicious_system_count": len(suspicious_systems),
                "healthy_system_count": len(healthy_systems),
            },
            "scheduler": self._build_scheduler_health(session),
            "suspicious_systems": suspicious_systems,
            "healthy_systems": healthy_systems,
        }

    def build_system_debug_export(self, session: Session, repository_id: int) -> dict[str, Any]:
        """Return a structured snapshot for one selected system including alerts and scan stages."""

        repository = self._load_repository_with_inventory(session, repository_id)
        system = self._build_system_entry(repository)
        recent_alerts = [
            {
                "title": alert.title,
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "status": alert.status,
                "source_type": alert.source_type,
                "created_at": alert.created_at,
                "metadata": alert.metadata_json,
            }
            for alert in sorted(repository.alerts, key=lambda item: item.created_at, reverse=True)[:20]
        ]
        recent_scan_results = [
            {
                "scanner_name": result.scanner_name,
                "status": result.status,
                "findings_count": result.findings_count,
                "started_at": result.started_at,
                "completed_at": result.completed_at,
                "details": result.details_json,
            }
            for result in sorted(
                repository.scan_results,
                key=lambda item: item.started_at or datetime.min.replace(tzinfo=UTC),
                reverse=True,
            )[:20]
        ]

        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "system": system.model_dump(mode="json"),
            "recent_alerts": recent_alerts,
            "recent_scan_results": recent_scan_results,
            "scheduler": self._build_scheduler_health(session),
        }

    def build_codex_remediation_prompt(self, session: Session, repository_id: int) -> str:
        """Generate a ready-to-paste Codex prompt for one risky system or repository."""

        repository = self._load_repository_with_inventory(session, repository_id)
        system = self._build_system_entry(repository)

        if (
            system.vulnerable_dependency_count == 0
            and system.open_alert_count == 0
            and not system.runtime_findings
        ):
            findings_block = "- There are currently no high-signal findings for this system.\n"
        else:
            risky_dependencies = [
                dependency
                for dependency in system.dependencies
                if dependency.risk_score > 0 or dependency.was_compromised
            ][:20]
            findings_lines = []
            for dependency in risky_dependencies:
                findings_lines.append(
                    "\n".join(
                        [
                            f"- Package: {dependency.package_name}",
                            f"  Ecosystem: {dependency.ecosystem}",
                            f"  Manifest: {dependency.manifest_path}",
                            f"  Current version: {dependency.detected_version}",
                            f"  Latest known version: {dependency.latest_version or 'unknown'}",
                            f"  Latest version published at: {dependency.latest_version_published_at or 'unknown'}",
                            f"  Last checked at: {dependency.detected_version_checked_at or 'unknown'}",
                            f"  Risk severity: {dependency.risk_severity}",
                            f"  Risk score: {dependency.risk_score}",
                            f"  Vulnerabilities: {', '.join(dependency.vulnerability_ids) or 'none listed'}",
                            f"  Previously compromised: {'yes' if dependency.was_compromised else 'no'}",
                            f"  Compromise signal: {dependency.compromised_signal or 'none'}",
                        ]
                    )
                )
            for finding in system.runtime_findings[:20]:
                findings_lines.append(
                    "\n".join(
                        [
                            f"- Runtime finding: {finding.title}",
                            f"  Source type: {finding.source_type}",
                            f"  Vulnerability: {finding.vulnerability_id or 'n/a'}",
                            f"  Package: {finding.package_name or 'n/a'}",
                            f"  Installed version: {finding.installed_version or 'n/a'}",
                            f"  Fix version: {finding.fix_version or 'unknown'}",
                            f"  Severity: {finding.severity}",
                            f"  Risk score: {finding.risk_score}",
                            f"  Target: {finding.target or 'n/a'}",
                            f"  Last seen at: {finding.last_seen_at or 'unknown'}",
                            f"  Description: {finding.description or 'n/a'}",
                        ]
                    )
                )
            findings_block = "\n\n".join(findings_lines) + "\n"

        return (
            "You are Codex acting as a senior DevSecOps engineer and secure software maintainer.\n\n"
            f"Please review and remediate security issues for the following system:\n"
            f"- System: {system.full_name}\n"
            f"- Display name: {system.display_name}\n"
            f"- Source type: {system.source_type}\n"
            f"- Risk score: {system.risk_score}\n"
            f"- Last scanned at: {system.last_scanned_at or 'unknown'}\n"
            f"- Summary: {system.summary or 'n/a'}\n\n"
            "Findings to address:\n"
            f"{findings_block}\n"
            "Tasks:\n"
            "- Inspect the relevant manifests, lockfiles, Dockerfiles, or integration metadata.\n"
            "- Update or pin safe dependency versions where possible.\n"
            "- Remove or replace malicious/compromised packages immediately if any are flagged.\n"
            "- Preserve expected behavior and add or run tests where appropriate.\n"
            "- Summarize what changed, what remains risky, and what should be monitored next.\n"
        )

    def _build_dependency_insight(
        self,
        dependency: Dependency,
        compromised_signals: dict[tuple[str, str], str],
    ) -> DependencyInsightOut:
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
        compromised_signal = self._detect_compromised_signal(
            dependency,
            vulnerabilities,
            compromised_signals,
        )
        return DependencyInsightOut(
            package_name=dependency.package_name,
            ecosystem=dependency.ecosystem,
            manifest_path=dependency.manifest_path,
            detected_version=dependency.version,
            detected_version_checked_at=dependency.updated_at,
            latest_version=latest_version.latest_version,
            latest_version_published_at=latest_version.released_at,
            latest_version_status=self._classify_version_status(
                dependency.version,
                latest_version,
            ),
            latest_version_source=latest_version.source,
            was_compromised=bool(compromised_signal),
            compromised_signal=compromised_signal,
            risk_severity=risk_severity,
            risk_score=risk_score,
            vulnerability_ids=[vulnerability.source_identifier for vulnerability in vulnerabilities],
        )

    def _build_system_entry(self, repository: Repository) -> SystemInventoryOut:
        """Build one system inventory entry from a repository-like ORM object."""

        compromised_signals = self._build_compromised_signal_index(repository.alerts)
        dependencies = [
            self._build_dependency_insight(dependency, compromised_signals)
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
        return SystemInventoryOut(
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
            runtime_findings=self._build_runtime_findings(repository),
        )

    def _load_repositories_with_inventory(self, session: Session) -> list[Repository]:
        """Load all repositories with the relationships needed for inventory and prompt views."""

        return session.scalars(
            select(Repository)
            .options(
                selectinload(Repository.dependencies)
                .selectinload(Dependency.vulnerability_links)
                .selectinload(DependencyVulnerability.vulnerability),
                selectinload(Repository.alerts),
                selectinload(Repository.scan_results),
            )
            .order_by(desc(Repository.risk_score), Repository.full_name)
        ).all()

    def _load_repository_with_inventory(self, session: Session, repository_id: int) -> Repository:
        """Load one repository-like asset with its related findings or raise a lookup error."""

        repository = session.scalar(
            select(Repository)
            .where(Repository.id == repository_id)
            .options(
                selectinload(Repository.dependencies)
                .selectinload(Dependency.vulnerability_links)
                .selectinload(DependencyVulnerability.vulnerability),
                selectinload(Repository.alerts),
                selectinload(Repository.scan_results),
            )
        )
        if repository is None:
            raise LookupError(f"Repository/system with id={repository_id} was not found.")
        return repository

    def _build_debug_system_entry(self, system: SystemInventoryOut) -> dict[str, Any]:
        """Trim a system entry to the most useful fields for operator debugging exports."""

        flagged_dependencies = [
            dependency.model_dump(mode="json")
            for dependency in system.dependencies
            if dependency.risk_score > 0
            or dependency.was_compromised
            or dependency.latest_version_status in {"outdated", "constraint"}
        ][:25]
        return {
            "id": system.id,
            "full_name": system.full_name,
            "display_name": system.display_name,
            "source_type": system.source_type,
            "risk_score": system.risk_score,
            "dependency_count": system.dependency_count,
            "vulnerable_dependency_count": system.vulnerable_dependency_count,
            "open_alert_count": system.open_alert_count,
            "last_scanned_at": system.last_scanned_at,
            "summary": system.summary,
            "flagged_dependencies": flagged_dependencies,
            "runtime_findings": [finding.model_dump(mode="json") for finding in system.runtime_findings[:25]],
        }

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
        if metadata.get("image"):
            summary_bits.append(str(metadata["image"]))
        if metadata.get("homeassistant_base_url"):
            summary_bits.append(str(metadata["homeassistant_base_url"]))
        if repository.local_path:
            summary_bits.append(repository.local_path)
        return " | ".join(summary_bits)

    def _build_runtime_findings(self, repository: Repository) -> list[RuntimeFindingOut]:
        """
        Convert non-dependency alerts into dashboard-visible findings.

        Why this exists:
        Container image CVEs and secret-scanner matches are stored as alerts instead of dependency
        links. Without surfacing them explicitly, systems can show hundreds of open alerts while the
        accordion body stays almost empty.
        """

        findings: list[RuntimeFindingOut] = []
        for alert in sorted(
            repository.alerts,
            key=lambda item: (item.risk_score, item.updated_at),
            reverse=True,
        ):
            if alert.status == "resolved":
                continue
            if alert.source_type in {"dependency_vulnerability", "ai_correlation"}:
                continue
            metadata = alert.metadata_json or {}
            findings.append(
                RuntimeFindingOut(
                    title=alert.title,
                    source_type=alert.source_type,
                    severity=alert.severity,
                    risk_score=alert.risk_score,
                    vulnerability_id=str(
                        metadata.get("vulnerability_id")
                        or metadata.get("detector")
                        or ""
                    ),
                    package_name=str(metadata.get("package_name") or ""),
                    installed_version=str(metadata.get("installed_version") or ""),
                    fix_version=metadata.get("fix_version"),
                    target=str(
                        metadata.get("target")
                        or metadata.get("file_path")
                        or metadata.get("source_url")
                        or ""
                    ),
                    description=str(metadata.get("description") or alert.description or ""),
                    last_seen_at=alert.updated_at,
                )
            )
        return findings[:25]

    def _build_scheduler_health(self, session: Session) -> dict[str, dict[str, Any]]:
        """Summarize the most recent recurring job activity from stored scan results."""

        now = datetime.now(UTC)
        job_scanners = {
            "repo_scan": {
                "scanner_names": {
                    "dependency_extractor",
                    "secret_scanner",
                    "container_scanner",
                    "unraid_container_scanner",
                    "homeassistant_dependency_scan",
                },
                "expected_hours": 24,
            },
            "threat_feed": {
                "scanner_names": {"threat_intelligence"},
                "expected_hours": 6,
            },
            "ai_analysis": {
                "scanner_names": {"ai_threat_extraction"},
                "expected_hours": 24 * 30,
            },
        }

        scheduler_health: dict[str, dict[str, Any]] = {}
        scan_results = session.scalars(select(ScanResult).order_by(desc(ScanResult.completed_at))).all()
        for job_name, config in job_scanners.items():
            relevant_results = [
                result
                for result in scan_results
                if result.scanner_name in config["scanner_names"]
            ]
            latest_result = relevant_results[0] if relevant_results else None
            latest_completed_at = latest_result.completed_at if latest_result else None
            overdue = True
            if latest_completed_at is not None:
                overdue = (now - latest_completed_at).total_seconds() > config["expected_hours"] * 3600
            scheduler_health[job_name] = {
                "last_completed_at": latest_completed_at.isoformat() if latest_completed_at else None,
                "last_status": latest_result.status if latest_result else "never_ran",
                "expected_interval_hours": config["expected_hours"],
                "overdue": overdue,
            }
        return scheduler_health

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

    def _build_compromised_signal_index(
        self,
        alerts: list[Alert],
    ) -> dict[tuple[str, str], str]:
        """Map dependency identifiers to compromise signals derived from past alerts."""

        signals: dict[tuple[str, str], str] = {}
        for alert in alerts:
            metadata = alert.metadata_json or {}
            dependency_name = str(metadata.get("dependency", "")).strip()
            dependency_version = str(metadata.get("version", "")).strip()
            if not dependency_name:
                continue
            if alert.source_type == "ai_correlation":
                signal = str(metadata.get("attack_type") or "ai_correlation")
                signals[(dependency_name, dependency_version)] = signal
                signals.setdefault((dependency_name, ""), signal)
        return signals

    def _detect_compromised_signal(
        self,
        dependency: Dependency,
        vulnerabilities: list[Vulnerability],
        compromised_signals: dict[tuple[str, str], str],
    ) -> str:
        """Return a readable compromise marker when a package was flagged as malicious before."""

        for vulnerability in vulnerabilities:
            if vulnerability.malicious_package:
                return f"malicious_package:{vulnerability.source_identifier}"

        exact_key = (dependency.package_name, dependency.version)
        if exact_key in compromised_signals:
            return compromised_signals[exact_key]

        package_only_key = (dependency.package_name, "")
        return compromised_signals.get(package_only_key, "")

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
