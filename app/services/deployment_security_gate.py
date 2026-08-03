"""
Purpose: Decide whether one exact Git deployment candidate has sufficient security evidence.
Input/Output: Reads persisted aggregate scans and unresolved alerts, then returns a fail-closed API
decision with actionable blockers for the Deployment Broker.
Important invariants: Only a fresh successful scan of the exact 40-character commit can allow a
deployment; HIGH/CRITICAL alerts remain blocking until resolved; secret excerpts are never returned.
Debugging: Use the response request ID, reason codes, and `scan_results` row ID to inspect a denial.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.entities import Alert, AlertStatus, Repository, ScanResult
from app.models.schemas import (
    DeploymentSecurityGateBlockerOut,
    DeploymentSecurityGateEvidenceOut,
    DeploymentSecurityGatePolicyOut,
    DeploymentSecurityGateRequest,
    DeploymentSecurityGateResponse,
    DeploymentSecurityGateSummaryOut,
)

DEPLOYMENT_GATE_API_VERSION = "2026-08-03"
BLOCKED_SEVERITIES = ("critical", "high")
UNRESOLVED_STATUSES = (AlertStatus.OPEN.value, AlertStatus.ACKNOWLEDGED.value)
SAFE_ALERT_CONTEXT_KEYS = (
    "vulnerability_id",
    "source_identifier",
    "package_name",
    "ecosystem",
    "installed_version",
    "fix_version",
    "target",
    "manifest_path",
    "detector",
    "file_path",
    "line_number",
    "content_source",
    "commit_sha",
)


class DeploymentSecurityGateService:
    """Evaluate exact-commit scan evidence and active security findings."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def evaluate(
        self,
        session: Session,
        request: DeploymentSecurityGateRequest,
    ) -> DeploymentSecurityGateResponse:
        """
        Return `allow`, `deny`, or `indeterminate` without performing a deployment.

        Example:
        A fresh successful scan for commit `abc...` with no unresolved HIGH/CRITICAL alerts returns
        `allow`. The same scan requested for commit `def...` returns `indeterminate` and a
        `SCANNED_COMMIT_MISMATCH` blocker, even if the repository currently has no alerts.
        """

        checked_at = datetime.now(UTC)
        evidence_blockers: list[DeploymentSecurityGateBlockerOut] = []
        warnings: list[str] = []

        repository = session.scalar(
            select(Repository).where(Repository.full_name == request.repository_full_name)
        )
        evidence: DeploymentSecurityGateEvidenceOut | None = None

        if repository is None:
            evidence_blockers.append(
                self._evidence_blocker(
                    code="REPOSITORY_NOT_SCANNED",
                    title="Repository is not present in the security inventory",
                    remediation=(
                        "Run a targeted Security Watchdog scan for this repository and commit, "
                        "then retry the deployment gate."
                    ),
                )
            )
            security_counts = {"critical": 0, "high": 0}
            security_blockers: list[DeploymentSecurityGateBlockerOut] = []
        else:
            if repository.source_type != "github":
                evidence_blockers.append(
                    self._evidence_blocker(
                        code="UNSUPPORTED_REPOSITORY_SOURCE",
                        title="Deployment gate requires a GitHub repository scan",
                        remediation=(
                            "Register and scan the GitHub source repository instead of a synthetic "
                            "runtime asset."
                        ),
                    )
                )
            if repository.archived:
                evidence_blockers.append(
                    self._evidence_blocker(
                        code="REPOSITORY_ARCHIVED",
                        title="Repository is archived",
                        remediation="Unarchive and rescan the repository or cancel the deployment.",
                    )
                )

            latest_scan = session.scalar(
                select(ScanResult)
                .where(
                    ScanResult.repository_id == repository.id,
                    ScanResult.scanner_name == "repository_asset_scan",
                )
                .order_by(desc(ScanResult.completed_at), desc(ScanResult.id))
                .limit(1)
            )
            evidence, scan_blockers = self._evaluate_scan_evidence(
                latest_scan=latest_scan,
                requested_commit_sha=request.commit_sha,
                checked_at=checked_at,
            )
            evidence_blockers.extend(scan_blockers)
            security_counts = self._count_security_blockers(session, repository.id)
            remaining_slots = max(
                self.settings.deployment_gate_max_blockers - len(evidence_blockers),
                0,
            )
            security_blockers = self._load_security_blockers(
                session,
                repository.id,
                limit=remaining_slots,
            )

        security_blocker_count = sum(security_counts.values())
        blocker_count = len(evidence_blockers) + security_blocker_count
        blockers = [*evidence_blockers, *security_blockers]
        results_truncated = blocker_count > len(blockers)
        if results_truncated:
            warnings.append(
                "The blocker list is truncated; use Security Watchdog alert APIs for the complete set."
            )

        if evidence_blockers:
            decision = "indeterminate"
        elif security_blocker_count:
            decision = "deny"
        else:
            decision = "allow"

        reason_codes = self._unique_codes(blockers)
        if decision == "allow":
            reason_codes = ["SECURITY_POLICY_SATISFIED"]

        return DeploymentSecurityGateResponse(
            api_version=DEPLOYMENT_GATE_API_VERSION,
            request_id=str(uuid4()),
            checked_at=checked_at,
            decision=decision,
            deploy_allowed=decision == "allow",
            reason_codes=reason_codes,
            stack_name=request.stack_name,
            repository_full_name=request.repository_full_name,
            requested_commit_sha=request.commit_sha,
            compose_file=request.compose_file,
            policy=DeploymentSecurityGatePolicyOut(
                max_scan_age_hours=self.settings.deployment_gate_max_scan_age_hours,
                blocked_severities=list(BLOCKED_SEVERITIES),
                unresolved_statuses=list(UNRESOLVED_STATUSES),
                max_returned_blockers=self.settings.deployment_gate_max_blockers,
            ),
            evidence=evidence,
            summary=DeploymentSecurityGateSummaryOut(
                blocker_count=blocker_count,
                returned_blocker_count=len(blockers),
                critical_count=security_counts["critical"],
                high_count=security_counts["high"],
                evidence_blocker_count=len(evidence_blockers),
                results_truncated=results_truncated,
            ),
            blockers=blockers,
            warnings=warnings,
        )

    def _evaluate_scan_evidence(
        self,
        *,
        latest_scan: ScanResult | None,
        requested_commit_sha: str,
        checked_at: datetime,
    ) -> tuple[
        DeploymentSecurityGateEvidenceOut | None,
        list[DeploymentSecurityGateBlockerOut],
    ]:
        """Validate aggregate scan success, age, and exact commit provenance."""

        if latest_scan is None:
            return None, [
                self._evidence_blocker(
                    code="NO_AGGREGATE_SCAN_EVIDENCE",
                    title="No completed repository security scan is available",
                    remediation="Run a targeted scan for the requested commit and retry.",
                )
            ]

        completed_at = self._as_utc(latest_scan.completed_at)
        scanned_commit_sha = self._normalize_stored_commit_sha(
            latest_scan.details_json.get("commit_sha")
        )
        age_hours = (
            max((checked_at - completed_at).total_seconds(), 0.0) / 3600
            if completed_at
            else None
        )
        evidence = DeploymentSecurityGateEvidenceOut(
            scan_result_id=latest_scan.id,
            scanner_name=latest_scan.scanner_name,
            status=latest_scan.status,
            scanned_commit_sha=scanned_commit_sha,
            completed_at=completed_at,
            age_hours=round(age_hours, 3) if age_hours is not None else None,
            commit_matches=scanned_commit_sha == requested_commit_sha,
        )
        blockers: list[DeploymentSecurityGateBlockerOut] = []

        if latest_scan.status != "success":
            blockers.append(
                self._evidence_blocker(
                    code="LATEST_SCAN_FAILED",
                    title="Latest repository security scan did not complete successfully",
                    remediation="Fix the failed scanner stage, rerun the scan, and retry deployment.",
                )
            )
        if completed_at is None:
            blockers.append(
                self._evidence_blocker(
                    code="SCAN_COMPLETION_MISSING",
                    title="Security scan has no completion timestamp",
                    remediation="Rerun the repository scan to produce complete audit evidence.",
                )
            )
        elif completed_at > checked_at + timedelta(minutes=5):
            blockers.append(
                self._evidence_blocker(
                    code="SCAN_TIMESTAMP_IN_FUTURE",
                    title="Security scan completion time is implausibly far in the future",
                    remediation="Correct clock synchronization, rerun the scan, and retry deployment.",
                )
            )
        elif age_hours is not None and age_hours > self.settings.deployment_gate_max_scan_age_hours:
            blockers.append(
                self._evidence_blocker(
                    code="SCAN_EVIDENCE_STALE",
                    title="Security scan evidence is older than the allowed policy window",
                    remediation="Run a fresh targeted scan for the requested commit.",
                    context={"age_hours": round(age_hours, 3)},
                )
            )
        if scanned_commit_sha is None:
            blockers.append(
                self._evidence_blocker(
                    code="SCANNED_COMMIT_MISSING",
                    title="Security scan is not bound to a full Git commit SHA",
                    remediation="Rerun the scan with commit-aware Security Watchdog code.",
                )
            )
        elif scanned_commit_sha != requested_commit_sha:
            blockers.append(
                self._evidence_blocker(
                    code="SCANNED_COMMIT_MISMATCH",
                    title="Security evidence belongs to a different Git commit",
                    remediation="Scan the exact requested commit and retry deployment.",
                    context={"scanned_commit_sha": scanned_commit_sha},
                )
            )

        return evidence, blockers

    def _count_security_blockers(self, session: Session, repository_id: int) -> dict[str, int]:
        """Count every unresolved HIGH/CRITICAL alert without loading large result sets."""

        rows = session.execute(
            select(func.lower(Alert.severity), func.count(Alert.id))
            .where(
                Alert.repository_id == repository_id,
                Alert.status.in_(UNRESOLVED_STATUSES),
                func.lower(Alert.severity).in_(BLOCKED_SEVERITIES),
            )
            .group_by(func.lower(Alert.severity))
        ).all()
        counts = {"critical": 0, "high": 0}
        for severity, count in rows:
            if severity in counts:
                counts[severity] = int(count)
        return counts

    def _load_security_blockers(
        self,
        session: Session,
        repository_id: int,
        *,
        limit: int,
    ) -> list[DeploymentSecurityGateBlockerOut]:
        """Load a bounded, secret-safe list of actionable security findings."""

        if limit <= 0:
            return []
        alerts = session.scalars(
            select(Alert)
            .where(
                Alert.repository_id == repository_id,
                Alert.status.in_(UNRESOLVED_STATUSES),
                func.lower(Alert.severity).in_(BLOCKED_SEVERITIES),
            )
            .order_by(
                desc(func.lower(Alert.severity) == "critical"),
                desc(Alert.risk_score),
                desc(Alert.updated_at),
            )
            .limit(limit)
        ).all()
        return [self._alert_blocker(alert) for alert in alerts]

    def _alert_blocker(self, alert: Alert) -> DeploymentSecurityGateBlockerOut:
        """Map an alert to a bounded response without exposing secret excerpts or raw payloads."""

        context = {}
        for key in SAFE_ALERT_CONTEXT_KEYS:
            if key not in alert.metadata_json:
                continue
            value = alert.metadata_json[key]
            if value is None or isinstance(value, (str, int, float, bool)):
                context[key] = self._bounded_scalar(value)
        return DeploymentSecurityGateBlockerOut(
            code=f"UNRESOLVED_{alert.severity.upper()}_ALERT",
            finding_id=f"alert:{alert.id}",
            severity=alert.severity.lower(),
            title=alert.title,
            source_type=alert.source_type,
            remediation=self._remediation_for_alert(alert),
            context=context,
        )

    def _remediation_for_alert(self, alert: Alert) -> str:
        """Return source-specific next steps without embedding untrusted alert descriptions."""

        if alert.source_type == "secret_scanner":
            return (
                "Remove the credential from code and Git history, rotate it through the secure "
                "secret flow, rerun the scan, and confirm the alert resolves."
            )
        fix_version = self._bounded_scalar(alert.metadata_json.get("fix_version"), max_length=128)
        if fix_version:
            return (
                f"Validate compatibility with fix version {fix_version}, update the affected "
                "dependency or image, run tests, and rescan."
            )
        if alert.source_type in {"container_scanner", "unraid_container"}:
            return "Rebuild from a supported patched base image, validate the stack, and rescan."
        return (
            "Review the linked finding, apply a compatible security fix, run the repository tests, "
            "and rescan the exact commit."
        )

    def _evidence_blocker(
        self,
        *,
        code: str,
        title: str,
        remediation: str,
        context: dict[str, Any] | None = None,
    ) -> DeploymentSecurityGateBlockerOut:
        """Build one policy/evidence blocker with a stable machine-readable code."""

        return DeploymentSecurityGateBlockerOut(
            code=code,
            finding_id=f"evidence:{code.lower()}",
            severity="error",
            title=title,
            source_type="deployment_security_gate",
            remediation=remediation,
            context=context or {},
        )

    def _as_utc(self, value: datetime | None) -> datetime | None:
        """Normalize SQLite-naive and PostgreSQL-aware timestamps for age calculations."""

        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def _normalize_stored_commit_sha(self, value: Any) -> str | None:
        """Return only a valid full SHA from persisted, potentially legacy scan metadata."""

        commit_sha = str(value or "").lower()
        if len(commit_sha) != 40 or any(
            character not in "0123456789abcdef" for character in commit_sha
        ):
            return None
        return commit_sha

    def _bounded_scalar(self, value: Any, *, max_length: int = 512) -> Any:
        """Bound string metadata so corrupted scanner payloads cannot inflate Broker responses."""

        if isinstance(value, str):
            return value[:max_length]
        return value

    def _unique_codes(self, blockers: list[DeploymentSecurityGateBlockerOut]) -> list[str]:
        """Return reason codes in response order without duplicates."""

        return list(dict.fromkeys(blocker.code for blocker in blockers))
