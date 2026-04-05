"""
Purpose: Build aggregated reports for the API and dashboard from persisted scan data.
Input/Output: Reads the database and returns `ReportOut` summary objects.
Important invariants: Reporting should stay read-only and deterministic so it is safe for repeated
dashboard refreshes; sorting and truncation rules are intentionally simple and transparent.
Debugging: If a dashboard card looks wrong, compare the raw query result with this aggregation code.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.entities import Alert, Dependency, DependencyVulnerability, Repository, Vulnerability
from app.models.schemas import AlertOut, ReportOut


class ReportingService:
    """Read-model builder for reports and dashboards."""

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
