"""
Purpose: Build aggregated reports for the API and dashboard from persisted scan data.
Input/Output: Reads the database and returns `ReportOut` summary objects.
Important invariants: Reporting should stay read-only and deterministic so it is safe for repeated
dashboard refreshes; latest-version lookups are best-effort enrichments and must never break the
main report if an upstream registry is slow or temporarily unavailable.
Debugging: If a dashboard card looks wrong, compare the raw query result with this aggregation code.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from packaging.version import InvalidVersion, Version
from sqlalchemy import and_, case, desc, func, literal, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
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
    DailySecurityAutomationOut,
    DependencyInsightOut,
    HighRiskDependencyUpdateOut,
    HighRiskSystemUpdateOut,
    HighRiskUpdateQueueOut,
    ReportOut,
    RuntimeFindingOut,
    SystemInventoryOut,
)
from app.services.matching import normalize_version
from app.services.version_catalog import LatestVersionRecord, VersionCatalogService

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
QUEUE_PRIORITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
DEFAULT_VERSION_CATALOG = VersionCatalogService()
DAILY_AUTOMATION_API_VERSION = "2026-07-30"


class ReportingService:
    """Read-model builder for reports and dashboards."""

    def __init__(self, version_catalog: VersionCatalogService | None = None) -> None:
        self.version_catalog = version_catalog or DEFAULT_VERSION_CATALOG
        self.settings = get_settings()

    def build_report(self, session: Session) -> ReportOut:
        """Aggregate the main metrics needed by operators."""

        included_repository_ids = self._included_repository_ids(session)
        repository_count = len(included_repository_ids)
        dependency_count = (
            session.scalar(
                select(func.count(Dependency.id)).where(Dependency.repository_id.in_(included_repository_ids))
            )
            if included_repository_ids
            else 0
        ) or 0
        vulnerability_count = (
            session.scalar(
                select(func.count(func.distinct(Vulnerability.id)))
                .join(DependencyVulnerability, DependencyVulnerability.vulnerability_id == Vulnerability.id)
                .join(Dependency, Dependency.id == DependencyVulnerability.dependency_id)
                .where(Dependency.repository_id.in_(included_repository_ids))
            )
            if included_repository_ids
            else 0
        ) or 0
        active_alert_filter = self._operator_actionable_alert_filter()
        unique_open_alerts = self._deduplicate_alerts(
            self._open_alerts(
                session.scalars(
                    select(Alert).where(
                        active_alert_filter,
                        Alert.repository_id.in_(included_repository_ids),
                    )
                ).all()
            )
            if included_repository_ids
            else []
        )
        alert_count = len(unique_open_alerts)
        critical_alert_count = len(
            [alert for alert in unique_open_alerts if alert.severity == "critical"]
        )

        repository_risk = [
            {
                "full_name": repository.full_name,
                "source_type": repository.source_type,
                "risk_score": repository.risk_score,
            }
            for repository in session.scalars(
                select(Repository)
                .where(Repository.id.in_(included_repository_ids))
                .order_by(desc(Repository.risk_score))
                .limit(10)
            )
        ]

        recent_alerts = [
            AlertOut.model_validate(alert)
            for alert in sorted(
                unique_open_alerts,
                key=lambda item: self._alert_recency_key(item),
                reverse=True,
            )
            [:10]
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
                .join(Dependency, Dependency.id == DependencyVulnerability.dependency_id)
                .where(Dependency.repository_id.in_(included_repository_ids))
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

    def build_alert_diagnostics(self, session: Session, *, limit: int = 20) -> dict[str, Any]:
        """
        Return lightweight alert counters without loading every alert row into Python.

        Why this exists:
        The dashboard inventory intentionally renders rich per-system context, but that makes it
        expensive when a legacy database contains many historical findings. These SQL summaries let
        operators verify whether a large headline number is driven by containers, dependencies, or
        scanner noise before opening the heavy accordion view.
        """

        included_repository_ids = self._included_repository_ids(session)
        actionable_filter = and_(
            self._operator_actionable_alert_filter(),
            Alert.repository_id.in_(included_repository_ids),
        )
        open_alert_rows = (
            session.scalar(
                select(func.count(Alert.id)).where(
                    Alert.status != "resolved",
                    Alert.repository_id.in_(included_repository_ids),
                )
            )
            if included_repository_ids
            else 0
        ) or 0
        actionable_rows = session.scalar(select(func.count(Alert.id)).where(actionable_filter)) or 0
        excluded_legacy_rows = max(open_alert_rows - actionable_rows, 0)

        count_label = func.count(Alert.id).label("alert_rows")
        critical_rows = func.sum(case((Alert.severity == "critical", 1), else_=0)).label("critical_rows")
        content_source = func.coalesce(
            Alert.metadata_json["content_source"].as_string(),
            literal("n/a"),
        ).label("content_source")
        finding_kind = func.coalesce(
            Alert.metadata_json["detector"].as_string(),
            Alert.metadata_json["vulnerability_id"].as_string(),
            Alert.metadata_json["package_name"].as_string(),
            literal("unknown"),
        ).label("finding_kind")

        by_source_and_severity = [
            {
                "source_type": source_type,
                "severity": severity,
                "alert_rows": alert_rows,
            }
            for source_type, severity, alert_rows in session.execute(
                select(Alert.source_type, Alert.severity, count_label)
                .where(actionable_filter)
                .group_by(Alert.source_type, Alert.severity)
                .order_by(desc("alert_rows"))
                .limit(limit)
            )
        ]
        by_finding_kind = [
            {
                "source_type": source_type,
                "severity": severity,
                "content_source": content_source_value,
                "finding_kind": finding_kind_value,
                "alert_rows": alert_rows,
            }
            for (
                source_type,
                severity,
                content_source_value,
                finding_kind_value,
                alert_rows,
            ) in session.execute(
                select(Alert.source_type, Alert.severity, content_source, finding_kind, count_label)
                .where(actionable_filter)
                .group_by(Alert.source_type, Alert.severity, content_source, finding_kind)
                .order_by(desc("alert_rows"))
                .limit(limit)
            )
        ]
        top_repositories = [
            {
                "repository_id": repository_id,
                "full_name": full_name or "unknown",
                "source_type": source_type or "unknown",
                "alert_rows": alert_rows,
                "critical_rows": critical_count or 0,
            }
            for repository_id, full_name, source_type, alert_rows, critical_count in session.execute(
                select(
                    Repository.id,
                    Repository.full_name,
                    Repository.source_type,
                    count_label,
                    critical_rows,
                )
                .join(Repository, Repository.id == Alert.repository_id, isouter=True)
                .where(actionable_filter)
                .group_by(Repository.id, Repository.full_name, Repository.source_type)
                .order_by(desc("alert_rows"))
                .limit(limit)
            )
        ]

        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "open_alert_rows": open_alert_rows,
            "operator_actionable_alert_rows": actionable_rows,
            "excluded_legacy_git_history_entropy_rows": excluded_legacy_rows,
            "by_source_and_severity": by_source_and_severity,
            "by_finding_kind": by_finding_kind,
            "top_repositories": top_repositories,
        }

    def build_system_inventory(
        self,
        session: Session,
        *,
        resolve_latest_versions: bool = True,
    ) -> list[SystemInventoryOut]:
        """Return all tracked systems with expandable dependency detail for the dashboard."""

        repositories = self._load_repositories_with_inventory(session)
        return [
            self._build_system_entry(repository, resolve_latest_versions=resolve_latest_versions)
            for repository in repositories
        ]

    def build_platform_debug_export(self, session: Session) -> dict[str, Any]:
        """Return a compact structured export that operators can paste into Codex for diagnosis."""

        report = self.build_report(session)
        systems = self.build_system_inventory(session, resolve_latest_versions=False)
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
                "started_at": self._normalize_datetime(result.started_at),
                "completed_at": self._normalize_datetime(result.completed_at),
                "details": result.details_json,
            }
            for result in sorted(
                repository.scan_results,
                key=lambda item: self._normalize_datetime(item.started_at) or datetime.min.replace(tzinfo=UTC),
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

    def build_high_risk_update_queue(
        self,
        session: Session,
        *,
        limit: int = 25,
        resolve_latest_versions: bool = True,
    ) -> HighRiskUpdateQueueOut:
        """
        Build a high-risk-first queue for Codex-managed repository updates.

        Why this exists:
        Operators need a safe "what should Codex update next?" view that includes both urgent
        security findings and normal latest-version drift. The queue is intentionally read-only and
        leaves the actual repository writes to a later Codex task with tests, CI, and PR review.
        """

        systems = self.build_system_inventory(
            session,
            resolve_latest_versions=resolve_latest_versions,
        )
        tasks = [
            task
            for system in systems
            if (task := self._build_high_risk_update_task(system)) is not None
        ]
        tasks.sort(
            key=lambda task: (
                QUEUE_PRIORITY_ORDER.get(task.priority, 0),
                task.risk_score,
                len(task.runtime_findings),
                len(task.dependencies),
                task.full_name.lower(),
            ),
            reverse=True,
        )
        limited_tasks = tasks[:limit]
        return HighRiskUpdateQueueOut(
            generated_at=datetime.now(UTC),
            task_count=len(limited_tasks),
            tasks=limited_tasks,
            guidance=[
                "Work one repository at a time and keep every change reviewable in a pull request.",
                "Prioritize compromised, critical, and high-severity findings before routine latest-version drift.",
                "Do not update only because a target version is higher; prove compatibility first.",
                "Treat constraint status as a required review of package purpose, version range, and migration impact.",
                "Run the repository's local checks and wait for CI on the pushed commit before moving on.",
                "Never include secrets in commits, logs, PR descriptions, or generated prompts.",
            ],
        )

    def build_daily_security_automation(
        self,
        session: Session,
        *,
        limit: int = 25,
        max_tasks_per_run: int = 3,
    ) -> DailySecurityAutomationOut:
        """
        Return the machine-readable runbook consumed by a recurring Codex task.

        Why this exists:
        The daily Codex automation should not scrape dashboard HTML or infer safety rules from free
        text. This endpoint gives it one stable JSON contract with queue data, guardrails, source
        endpoints, and the exact prompt it should execute.
        """

        queue = self.build_high_risk_update_queue(
            session,
            limit=limit,
            resolve_latest_versions=False,
        )
        return DailySecurityAutomationOut(
            api_version=DAILY_AUTOMATION_API_VERSION,
            generated_at=datetime.now(UTC),
            recommended_schedule="daily",
            max_tasks_per_run=max_tasks_per_run,
            queue=queue,
            guardrails=self._build_update_guardrails(),
            allowed_actions=[
                "Inspect repository manifests, lockfiles, docs, workflows, and changelogs.",
                "Create one branch and one pull request per repository or system.",
                "Update dependency constraints only after compatibility and purpose are verified.",
                "Change related config, code, migrations, tests, or lockfiles when an update requires it.",
                "Run local checks and verify CI for the exact pushed commit.",
            ],
            blocked_actions=[
                "Do not update solely because a target version is higher.",
                "Do not widen a version constraint without identifying why the constraint exists.",
                "Do not merge pull requests automatically.",
                "Do not deploy automatically.",
                "Do not use SSH, direct Docker CLI, raw HTTP, root shells, or secret values for Unraid work.",
                "Do not commit secrets, real .env files, credential logs, or private debug exports.",
            ],
            source_endpoints={
                "queue": "/automation/high-risk-updates",
                "prompt": "/automation/high-risk-updates/codex-prompt",
                "runbook": "/automation/daily-security-check",
                "scan": "/scan",
                "scan_status": "/scan-jobs/latest",
            },
            codex_prompt=self._build_daily_security_prompt(queue, max_tasks_per_run=max_tasks_per_run),
        )

    def build_high_risk_update_prompt(
        self,
        session: Session,
        *,
        limit: int = 25,
    ) -> str:
        """Generate a Codex master prompt that processes the current high-risk update queue safely."""

        queue = self.build_high_risk_update_queue(session, limit=limit)
        if not queue.tasks:
            return (
                "You are Codex working in the Feberdin GitHub environment.\n\n"
                "The security-watchdog high-risk update queue is currently empty. Do not make repository changes.\n"
                "Run or schedule a fresh security-watchdog scan first, then re-open this automation prompt if new "
                "high-risk findings or outdated dependencies appear.\n"
            )

        task_blocks = [self._format_high_risk_prompt_task(task) for task in queue.tasks]
        return (
            "You are Codex acting as a senior DevSecOps maintainer in the Feberdin GitHub environment.\n\n"
            "Goal:\n"
            "Update the repositories and tracked systems below in high-risk-first order so vulnerable, compromised, "
            "or outdated dependencies move toward the latest safe version.\n\n"
            "Operating rules:\n"
            "- Work one repository or system at a time. Do not batch unrelated repos into one commit.\n"
            "- Inspect manifests, lockfiles, Dockerfiles, workflows, and project docs before changing versions.\n"
            f"{self._format_guardrails_for_prompt(self._build_update_guardrails())}"
            "- Run local tests, type checks, linters, and builds that the repository documents.\n"
            "- Push only reviewable branches, then wait for CI for the exact pushed commit before moving on.\n"
            "- Do not commit secrets, tokens, .env files with real values, logs with credentials, or generated private "
            "debug dumps.\n"
            "- For Docker or Unraid deployments, use only the `unraid_deploy` MCP broker flow. Do not use SSH, direct "
            "Docker CLI, raw HTTP, or root shell access.\n"
            "- Stop and report clearly if a required secret, registry credential, CI login, or repository permission "
            "is missing.\n\n"
            f"Queue generated at: {queue.generated_at.isoformat()}\n"
            f"Task count: {queue.task_count}\n\n"
            "Update queue:\n"
            f"{'\n\n'.join(task_blocks)}\n\n"
            "End state expected:\n"
            "- Every changed repository has a branch, commit, PR, local check result, and CI result.\n"
            "- Remaining risks are documented with the reason they could not be fixed automatically.\n"
            "- Deployment is only planned or applied through the broker when the user explicitly requests it and the "
            "broker approval policy allows it.\n"
        )

    def _build_update_guardrails(self) -> list[str]:
        """Return the safety rules that prevent blind version-number-only updates."""

        return [
            "Do not update solely because a target version is higher. First verify package purpose, runtime "
            "compatibility, framework version, peer dependencies, engine requirements, and project configuration.",
            "Treat `constraint` status as a warning. The project currently restricts the allowed version range; "
            "identify why that range exists before changing it.",
            "For major-version updates, dev-tooling updates, framework updates, and runtime updates, read release "
            "notes or changelogs and check migration requirements.",
            "If a security fix requires a breaking upgrade, make the required config, code, migration, and test "
            "changes in the same pull request.",
            "If compatibility cannot be proven locally, do not force the update. Leave the dependency unchanged and "
            "open a PR or issue with findings, blocker details, and migration notes.",
        ]

    def _format_guardrails_for_prompt(self, guardrails: list[str]) -> str:
        """Format guardrails as prompt bullets without duplicating wording in multiple call sites."""

        return "".join(f"- {guardrail}\n" for guardrail in guardrails)

    def _build_daily_security_prompt(
        self,
        queue: HighRiskUpdateQueueOut,
        *,
        max_tasks_per_run: int,
    ) -> str:
        """Build the daily automation prompt from an already materialized queue payload."""

        task_blocks = [self._format_high_risk_prompt_task(task) for task in queue.tasks[:max_tasks_per_run]]
        queue_block = "\n\n".join(task_blocks) if task_blocks else "- No queued tasks.\n"
        return (
            "You are Codex running the daily Security Watchdog maintenance task for Feberdin.\n\n"
            "Fetch or use the Security Watchdog automation runbook at `/automation/daily-security-check` and "
            "process the current queue conservatively.\n\n"
            f"Maximum tasks this run: {max_tasks_per_run}\n"
            f"Queue generated at: {queue.generated_at.isoformat()}\n"
            f"Current task count: {queue.task_count}\n\n"
            "Required workflow:\n"
            "- If the queue is empty, report that no repository changes are needed and stop.\n"
            "- Work only on the highest-priority queued tasks listed below, one repository or system at a time.\n"
            "- For every changed repository, create a dedicated branch and pull request.\n"
            "- Run the repository's documented local checks and wait for CI for the exact pushed commit.\n"
            "- Do not merge pull requests and do not deploy automatically.\n"
            "- For Docker or Unraid deployments, only prepare notes unless the user explicitly requests deployment; "
            "then use the `unraid_deploy` MCP broker flow with plan and approval.\n\n"
            "Compatibility guardrails:\n"
            f"{self._format_guardrails_for_prompt(self._build_update_guardrails())}\n"
            "Queue slice for this run:\n"
            f"{queue_block}\n\n"
            "End with: checked tasks, branches/PRs, local checks, CI results, skipped updates with reasons, and any "
            "manual decision required.\n"
        )

    def _build_high_risk_update_task(
        self,
        system: SystemInventoryOut,
    ) -> HighRiskSystemUpdateOut | None:
        """
        Convert one system inventory entry into an automation task when action is needed.

        Why this exists:
        A system can need Codex attention because of vulnerable dependencies, runtime findings, or
        plain latest-version drift. Keeping the decision in one helper makes the route predictable
        and keeps the dashboard from reimplementing security prioritization in JavaScript.
        """

        dependencies = [
            self._build_dependency_update_entry(dependency)
            for dependency in system.dependencies
            if self._should_queue_dependency_update(dependency)
        ]
        runtime_findings = [
            finding
            for finding in system.runtime_findings
            if self._should_queue_runtime_finding(finding)
        ]

        has_high_system_risk = system.risk_score >= 70 or system.open_alert_count > 0
        if not dependencies and not runtime_findings and not has_high_system_risk:
            return None

        return HighRiskSystemUpdateOut(
            repository_id=system.id,
            full_name=system.full_name,
            display_name=system.display_name,
            source_type=system.source_type,
            risk_score=system.risk_score,
            priority=self._classify_update_priority(system, dependencies, runtime_findings),
            reason=self._build_update_reason(system, dependencies, runtime_findings),
            dependencies=dependencies[:25],
            runtime_findings=runtime_findings[:25],
        )

    def _build_dependency_update_entry(
        self,
        dependency: DependencyInsightOut,
    ) -> HighRiskDependencyUpdateOut:
        """Normalize one dependency insight into an update action for Codex."""

        return HighRiskDependencyUpdateOut(
            package_name=dependency.package_name,
            ecosystem=dependency.ecosystem,
            manifest_path=dependency.manifest_path,
            current_version=dependency.detected_version,
            target_version=dependency.latest_version,
            latest_version_status=dependency.latest_version_status,
            latest_version_source=dependency.latest_version_source,
            risk_severity=dependency.risk_severity,
            risk_score=dependency.risk_score,
            vulnerability_ids=dependency.vulnerability_ids,
            was_compromised=dependency.was_compromised,
            compromised_signal=dependency.compromised_signal,
            action=self._classify_dependency_update_action(dependency),
        )

    def _should_queue_dependency_update(self, dependency: DependencyInsightOut) -> bool:
        """Return true when a dependency needs a Codex update or security review."""

        has_security_signal = (
            dependency.risk_score > 0
            or dependency.was_compromised
            or dependency.risk_severity in {"critical", "high"}
            or bool(dependency.vulnerability_ids)
        )
        has_latest_version_drift = (
            dependency.latest_version_status in {"outdated", "constraint"}
            and dependency.latest_version is not None
        )
        return has_security_signal or has_latest_version_drift

    def _should_queue_runtime_finding(self, finding: RuntimeFindingOut) -> bool:
        """Return true when an image, secret, or runtime finding should enter the update queue."""

        return (
            finding.risk_score >= 40
            or finding.severity in {"critical", "high"}
            or bool(finding.fix_version)
        )

    def _classify_dependency_update_action(self, dependency: DependencyInsightOut) -> str:
        """Choose the safest next action for a queued dependency."""

        if dependency.was_compromised:
            return "replace_or_remove_compromised_package"
        if dependency.latest_version and dependency.latest_version_status == "constraint":
            return "review_constraint_and_update_config_if_safe"
        if dependency.latest_version and dependency.latest_version_status == "outdated":
            return "update_to_latest_known_safe_version"
        if dependency.vulnerability_ids or dependency.risk_score > 0:
            return "investigate_security_fix"
        return "review"

    def _classify_update_priority(
        self,
        system: SystemInventoryOut,
        dependencies: list[HighRiskDependencyUpdateOut],
        runtime_findings: list[RuntimeFindingOut],
    ) -> str:
        """Classify a queue item by the strongest signal across system, dependency, and runtime data."""

        if (
            system.risk_score >= 90
            or any(dependency.was_compromised for dependency in dependencies)
            or any(dependency.risk_severity == "critical" for dependency in dependencies)
            or any(finding.severity == "critical" or finding.risk_score >= 90 for finding in runtime_findings)
        ):
            return "critical"
        if (
            system.risk_score >= 70
            or system.open_alert_count > 0
            or any(dependency.risk_severity == "high" for dependency in dependencies)
            or any(finding.severity == "high" or finding.risk_score >= 70 for finding in runtime_findings)
        ):
            return "high"
        if dependencies or runtime_findings:
            return "medium"
        return "low"

    def _build_update_reason(
        self,
        system: SystemInventoryOut,
        dependencies: list[HighRiskDependencyUpdateOut],
        runtime_findings: list[RuntimeFindingOut],
    ) -> str:
        """Create a short human-readable reason for the queue item."""

        reasons = []
        if system.risk_score >= 70:
            reasons.append(f"system risk score {system.risk_score:.1f}")
        if system.open_alert_count:
            reasons.append(f"{system.open_alert_count} open alert(s)")
        compromised_count = len([dependency for dependency in dependencies if dependency.was_compromised])
        vulnerable_count = len([dependency for dependency in dependencies if dependency.vulnerability_ids])
        outdated_count = len(
            [
                dependency
                for dependency in dependencies
                if dependency.latest_version_status in {"outdated", "constraint"}
            ]
        )
        if compromised_count:
            reasons.append(f"{compromised_count} compromised package(s)")
        if vulnerable_count:
            reasons.append(f"{vulnerable_count} vulnerable dependency update(s)")
        if outdated_count:
            reasons.append(f"{outdated_count} outdated dependency update(s)")
        if runtime_findings:
            reasons.append(f"{len(runtime_findings)} runtime/image finding(s)")
        return "; ".join(reasons) or "latest-version maintenance"

    def _format_high_risk_prompt_task(self, task: HighRiskSystemUpdateOut) -> str:
        """Format one queue task as compact plain text for a Codex prompt."""

        lines = [
            f"- System: {task.full_name}",
            f"  Display name: {task.display_name}",
            f"  Source type: {task.source_type}",
            f"  Repository/System id: {task.repository_id}",
            f"  Priority: {task.priority}",
            f"  Risk score: {task.risk_score}",
            f"  Reason: {task.reason}",
        ]

        if task.dependencies:
            lines.append("  Dependency actions:")
            for dependency in task.dependencies[:15]:
                lines.extend(
                    [
                        f"  - Package: {dependency.package_name}",
                        f"    Ecosystem: {dependency.ecosystem}",
                        f"    Manifest: {dependency.manifest_path}",
                        f"    Current version: {dependency.current_version}",
                        f"    Target version: {dependency.target_version or 'unknown'}",
                        f"    Latest status: {dependency.latest_version_status}",
                        f"    Risk severity: {dependency.risk_severity}",
                        f"    Risk score: {dependency.risk_score}",
                        f"    Vulnerabilities: {', '.join(dependency.vulnerability_ids) or 'none listed'}",
                        f"    Previously compromised: {'yes' if dependency.was_compromised else 'no'}",
                        f"    Action: {dependency.action}",
                    ]
                )

        if task.runtime_findings:
            lines.append("  Runtime or image findings:")
            for finding in task.runtime_findings[:10]:
                lines.extend(
                    [
                        f"  - Finding: {finding.title}",
                        f"    Source type: {finding.source_type}",
                        f"    Severity: {finding.severity}",
                        f"    Risk score: {finding.risk_score}",
                        f"    Package: {finding.package_name or 'n/a'}",
                        f"    Installed version: {finding.installed_version or 'n/a'}",
                        f"    Fix version: {finding.fix_version or 'unknown'}",
                        f"    Target: {finding.target or 'n/a'}",
                    ]
                )

        return "\n".join(lines)

    def _build_dependency_insight(
        self,
        dependency: Dependency,
        compromised_signals: dict[tuple[str, str], str],
        *,
        resolve_latest_version: bool = True,
    ) -> DependencyInsightOut:
        """Transform one ORM dependency into a dashboard-friendly row."""

        vulnerabilities = [
            link.vulnerability
            for link in dependency.vulnerability_links
            if link.vulnerability is not None
        ]
        latest_version = (
            self.version_catalog.resolve_latest_version(
                dependency.ecosystem,
                dependency.package_name,
            )
            if resolve_latest_version
            else LatestVersionRecord(
                latest_version=None,
                source="skipped_debug_export",
                checked_at=datetime.now(UTC),
                note="Skipped latest-version lookup to keep the debug export fast.",
            )
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
            latest_version_status=(
                self._classify_version_status(dependency.version, latest_version)
                if resolve_latest_version
                else "skipped"
            ),
            latest_version_source=latest_version.source,
            was_compromised=bool(compromised_signal),
            compromised_signal=compromised_signal,
            risk_severity=risk_severity,
            risk_score=risk_score,
            vulnerability_ids=[vulnerability.source_identifier for vulnerability in vulnerabilities],
        )

    def _build_system_entry(
        self,
        repository: Repository,
        *,
        resolve_latest_versions: bool = True,
    ) -> SystemInventoryOut:
        """Build one system inventory entry from a repository-like ORM object."""

        compromised_signals = self._build_compromised_signal_index(repository.alerts)
        dependencies = [
            self._build_dependency_insight(
                dependency,
                compromised_signals,
                resolve_latest_version=resolve_latest_versions,
            )
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
        open_alert_count = len(self._deduplicate_alerts(self._open_alerts(repository.alerts)))
        return SystemInventoryOut(
            id=repository.id,
            owner=repository.owner,
            name=repository.name,
            full_name=repository.full_name,
            display_name=self._build_display_name(repository),
            source_type=repository.source_type,
            scan_enabled=repository.scan_enabled,
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

        repositories = session.scalars(
            select(Repository)
            .options(
                selectinload(Repository.dependencies)
                .selectinload(Dependency.vulnerability_links)
                .selectinload(DependencyVulnerability.vulnerability),
                selectinload(Repository.alerts.and_(self._operator_actionable_alert_filter())),
                selectinload(Repository.scan_results),
            )
            .order_by(desc(Repository.risk_score), Repository.full_name)
        ).unique().all()
        return [
            repository
            for repository in repositories
            if self._should_include_repository(repository)
        ]

    def _included_repository_ids(self, session: Session) -> list[int]:
        """Return repository IDs that should participate in operator reports and automation queues."""

        repositories = session.scalars(select(Repository)).all()
        return [
            repository.id
            for repository in repositories
            if self._should_include_repository(repository)
        ]

    def _should_include_repository(self, repository: Repository) -> bool:
        """Apply reporting visibility rules that mirror scanner inventory selection."""

        metadata = repository.metadata_json or {}
        if not repository.scan_enabled:
            return False
        return not (
            repository.source_type == "github"
            and bool(metadata.get("fork"))
            and not self.settings.github_include_forks
        )

    def _load_repository_with_inventory(self, session: Session, repository_id: int) -> Repository:
        """Load one repository-like asset with its related findings or raise a lookup error."""

        repository = session.scalar(
            select(Repository)
            .where(Repository.id == repository_id)
            .options(
                selectinload(Repository.dependencies)
                .selectinload(Dependency.vulnerability_links)
                .selectinload(DependencyVulnerability.vulnerability),
                selectinload(Repository.alerts.and_(self._operator_actionable_alert_filter())),
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
            self._deduplicate_alerts(self._open_alerts(repository.alerts)),
            key=lambda item: self._alert_sort_key(item),
            reverse=True,
        ):
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

    def _open_alerts(self, alerts: Iterable[Alert]) -> list[Alert]:
        """Return unresolved operator-actionable alerts so grouping stays backend-agnostic."""

        return [
            alert
            for alert in alerts
            if alert.status != "resolved" and self._is_operator_actionable_alert(alert)
        ]

    def _operator_actionable_alert_filter(self) -> Any:
        """
        Return the SQL equivalent of `_is_operator_actionable_alert`.

        Why this exists:
        Filtering in Python keeps the logic backend-agnostic, but large legacy databases should not
        load low-confidence git-history entropy rows just to discard them. The explicit NULL checks
        avoid SQL three-valued logic accidentally hiding container or dependency alerts that do not
        carry secret-scanner metadata.
        """

        content_source = Alert.metadata_json["content_source"].as_string()
        detector = Alert.metadata_json["detector"].as_string()
        return and_(
            Alert.status != "resolved",
            or_(
                Alert.source_type.not_in(["secret_scanner", "homeassistant_secret"]),
                content_source.is_(None),
                content_source != "git_history",
                detector.is_(None),
                detector != "high_entropy",
            ),
        )

    def _is_operator_actionable_alert(self, alert: Alert) -> bool:
        """
        Exclude legacy low-confidence noise from operator counts.

        Why this exists:
        Earlier releases treated entropy-only findings in full git history as critical alerts. Large
        public forks can produce tens of thousands of these rows, even though they are not confirmed
        current secrets and are not useful as one alert per historical line. Regex/signature-based
        history findings still count because they carry stronger evidence.
        """

        metadata = alert.metadata_json or {}
        return not (
            alert.source_type in {"secret_scanner", "homeassistant_secret"}
            and metadata.get("content_source") == "git_history"
            and metadata.get("detector") == "high_entropy"
        )

    def _deduplicate_alerts(self, alerts: Iterable[Alert]) -> list[Alert]:
        """
        Collapse legacy duplicate alert rows into one operator-facing finding.

        Why this exists:
        Older scans included noisy metadata such as git-history commit SHA in fingerprints. The
        database can therefore contain many open rows for one actionable finding. Reporting should
        answer "how many findings need work?" instead of "how many duplicate rows exist?".
        """

        best_by_identity: dict[tuple[Any, ...], Alert] = {}
        for alert in alerts:
            identity = self._alert_identity(alert)
            current = best_by_identity.get(identity)
            if current is None or self._alert_sort_key(alert) > self._alert_sort_key(current):
                best_by_identity[identity] = alert
        return list(best_by_identity.values())

    def _alert_identity(self, alert: Alert) -> tuple[Any, ...]:
        """Return the stable finding identity used by report-level deduplication."""

        metadata = alert.metadata_json or {}
        if alert.source_type in {"secret_scanner", "homeassistant_secret"}:
            return (
                alert.repository_id,
                alert.source_type,
                alert.title,
                metadata.get("file_path", ""),
                metadata.get("line_number", ""),
                metadata.get("detector", ""),
                metadata.get("excerpt", ""),
                metadata.get("content_source", ""),
            )
        if alert.source_type in {"container_scanner", "unraid_container"}:
            return (
                alert.repository_id,
                alert.source_type,
                alert.title,
                metadata.get("target") or metadata.get("image_ref") or "",
                metadata.get("vulnerability_id", ""),
                metadata.get("package_name", ""),
                metadata.get("installed_version", ""),
            )
        if alert.source_type in {"dependency_vulnerability", "ai_correlation"}:
            return (
                alert.repository_id,
                alert.source_type,
                alert.title,
                metadata.get("dependency", ""),
                metadata.get("version", ""),
                metadata.get("manifest_path", ""),
                metadata.get("vulnerability", ""),
                metadata.get("source_url", ""),
                metadata.get("attack_type", ""),
            )
        return (alert.repository_id, alert.source_type, alert.fingerprint)

    def _alert_sort_key(self, alert: Alert) -> tuple[float, datetime, int]:
        """Prefer the newest high-risk row when duplicate alert rows exist."""

        updated_at = self._normalize_datetime(alert.updated_at) or datetime.min.replace(tzinfo=UTC)
        return (alert.risk_score, updated_at, alert.id or 0)

    def _alert_recency_key(self, alert: Alert) -> tuple[datetime, int]:
        """Sort alert summaries by the latest persisted update timestamp."""

        updated_at = self._normalize_datetime(alert.updated_at) or datetime.min.replace(tzinfo=UTC)
        return (updated_at, alert.id or 0)

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
            latest_completed_at = (
                self._normalize_datetime(latest_result.completed_at)
                if latest_result
                else None
            )
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

    def _normalize_datetime(self, value: datetime | None) -> datetime | None:
        """
        Normalize timestamps to timezone-aware UTC values.

        Why this exists:
        SQLite commonly returns naive datetime objects even when the model column is declared with
        `timezone=True`. Reporting now mixes persisted scan timestamps with `datetime.now(UTC)`, so
        we normalize eagerly to avoid crashes in exports and debug views.
        """

        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

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
