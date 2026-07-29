"""
Purpose: Render persisted security-watchdog alerts as SARIF 2.1.0 JSON.
Input/Output: Reads alert rows from the database and returns a GitHub Code Scanning compatible
dictionary without writing files or contacting external services.
Important invariants: SARIF output must be deterministic, avoid leaking raw secrets, and include
enough location/evidence metadata for operators to triage findings.
Debugging: If a finding points to the wrong file, inspect the alert metadata fields used by
`_build_location`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from app.core.security import mask_sensitive_values
from app.models.entities import Alert, AlertStatus

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "security-watchdog"
TOOL_INFORMATION_URI = "https://github.com/Feberdin/security-watchdog"

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

SOURCE_TYPE_RULE_DESCRIPTIONS = {
    "ai_correlation": "AI-extracted threat intelligence matched an installed dependency.",
    "container_scanner": "Container image or Dockerfile scanner reported a finding.",
    "dependency_vulnerability": "A dependency matched a known vulnerability or advisory.",
    "homeassistant_secret": "A Home Assistant integration scan found a likely secret.",
    "secret_scanner": "Repository content or git history contains a likely secret.",
    "unraid_container": "An Unraid runtime container image scan reported a finding.",
}


class SarifReportingService:
    """Build a SARIF view from existing operator alerts."""

    def build_report(
        self,
        session: Session,
        *,
        include_resolved: bool = False,
        limit: int = 500,
    ) -> dict[str, Any]:
        """
        Build a SARIF 2.1.0 document from persisted alerts.

        Why this exists:
        The dashboard is useful for humans, but SARIF lets the same findings flow into security
        review tools without duplicating scan logic or introducing another persistence path.
        """

        alerts = self._load_alerts(session, include_resolved=include_resolved, limit=limit)
        rules = {self._rule_id(alert): self._build_rule(alert) for alert in alerts}
        return {
            "version": SARIF_VERSION,
            "$schema": SARIF_SCHEMA_URL,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL_NAME,
                            "informationUri": TOOL_INFORMATION_URI,
                            "rules": [rules[rule_id] for rule_id in sorted(rules)],
                        },
                    },
                    "results": [self._build_result(alert) for alert in alerts],
                    "properties": {
                        "generatedAt": datetime.now(UTC).isoformat(),
                        "includeResolved": include_resolved,
                        "alertLimit": limit,
                    },
                }
            ],
        }

    def _load_alerts(
        self,
        session: Session,
        *,
        include_resolved: bool,
        limit: int,
    ) -> list[Alert]:
        """Load newest alerts with repository context and optional resolved filtering."""

        query = (
            select(Alert)
            .options(selectinload(Alert.repository))
            .order_by(desc(Alert.updated_at), desc(Alert.id))
            .limit(limit)
        )
        if not include_resolved:
            query = query.where(Alert.status != AlertStatus.RESOLVED.value)
        return list(session.scalars(query).all())

    def _build_rule(self, alert: Alert) -> dict[str, Any]:
        """Create one SARIF rule for an alert source type."""

        rule_id = self._rule_id(alert)
        description = SOURCE_TYPE_RULE_DESCRIPTIONS.get(
            alert.source_type,
            f"security-watchdog alert from {alert.source_type}.",
        )
        return {
            "id": rule_id,
            "name": alert.source_type,
            "shortDescription": {"text": description},
            "properties": {
                "sourceType": alert.source_type,
            },
        }

    def _build_result(self, alert: Alert) -> dict[str, Any]:
        """Create one SARIF result with a stable fingerprint and masked metadata."""

        repository = alert.repository
        result: dict[str, Any] = {
            "ruleId": self._rule_id(alert),
            "level": SEVERITY_TO_SARIF_LEVEL.get(alert.severity, "warning"),
            "message": {"text": self._message_text(alert)},
            "locations": [self._build_location(alert)],
            "partialFingerprints": {
                "security-watchdog-alert": alert.fingerprint,
            },
            "properties": {
                "alertId": alert.id,
                "severity": alert.severity,
                "riskScore": alert.risk_score,
                "status": alert.status,
                "sourceType": alert.source_type,
                "repository": repository.full_name if repository else "",
                "metadata": mask_sensitive_values(alert.metadata_json or {}),
            },
        }
        return result

    def _build_location(self, alert: Alert) -> dict[str, Any]:
        """
        Resolve the best SARIF location from alert metadata.

        Example input/output:
        `{"file_path": "app/config.py", "line_number": 12}` becomes an artifact URI of
        `app/config.py` with `region.startLine` set to `12`.
        """

        metadata = alert.metadata_json or {}
        repository = alert.repository
        uri = (
            metadata.get("file_path")
            or metadata.get("manifest_path")
            or metadata.get("target")
            or metadata.get("image_ref")
            or (repository.full_name if repository else TOOL_NAME)
        )
        physical_location: dict[str, Any] = {
            "artifactLocation": {
                "uri": str(uri),
            }
        }
        line_number = self._positive_int(metadata.get("line_number"))
        if line_number is not None:
            physical_location["region"] = {"startLine": line_number}
        return {"physicalLocation": physical_location}

    def _message_text(self, alert: Alert) -> str:
        """Keep SARIF messages readable while preserving the operator-facing alert title."""

        if alert.description:
            return f"{alert.title}: {alert.description}"
        return alert.title

    def _rule_id(self, alert: Alert) -> str:
        """Return a stable rule ID per alert source type."""

        return f"{TOOL_NAME}.{alert.source_type}"

    def _positive_int(self, value: Any) -> int | None:
        """Parse optional line numbers defensively from JSON metadata."""

        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None
        return parsed if parsed > 0 else None
