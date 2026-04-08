"""
Purpose: Define the typed API contracts and internal DTOs used between modules.
Input/Output: Converts ORM entities and scan outputs into validated Pydantic models.
Important invariants: External interfaces should remain stable even if internal storage changes; API
responses should expose enough context for debugging without leaking secrets.
Debugging: If validation fails, inspect the exact schema involved because it usually points directly
to an unexpected field shape from a scanner or external API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RepositoryOut(BaseModel):
    """Repository summary used by the API and dashboard."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    source_type: str
    owner: str
    name: str
    full_name: str
    default_branch: str
    archived: bool
    local_path: str
    last_scanned_at: datetime | None
    risk_score: float


class DependencyRecord(BaseModel):
    """Normalized dependency extracted from a manifest."""

    package_name: str
    version: str
    ecosystem: str
    manifest_path: str
    group_name: str | None = None
    direct_dependency: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityRecord(BaseModel):
    """Vulnerability DTO used during correlation."""

    source: str
    source_identifier: str
    package_name: str
    ecosystem: str
    summary: str
    severity: str
    cvss_score: float | None = None
    kev: bool = False
    exploit_available: bool = False
    malicious_package: bool = False
    affected_versions: list[str] = Field(default_factory=list)
    reference_urls: list[str] = Field(default_factory=list)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class RiskScore(BaseModel):
    """Explainable risk score used in alerts and reports."""

    score: float
    severity: str
    reasons: list[str]


class SecretFinding(BaseModel):
    """One likely secret match from repository content."""

    file_path: str
    line_number: int
    detector: str
    excerpt: str
    entropy: float | None = None


class ContainerFinding(BaseModel):
    """One vulnerability returned by a container scanning tool."""

    tool: str
    target: str
    vulnerability_id: str
    package_name: str
    installed_version: str
    severity: str
    fix_version: str | None = None
    description: str = ""


class ThreatArticleRecord(BaseModel):
    """Normalized threat intelligence record before persistence."""

    source_type: str
    title: str
    source_url: str
    published_at: datetime | None = None
    raw_content: str
    normalized_text: str
    tags: list[str] = Field(default_factory=list)


class AIExtractedThreatRecord(BaseModel):
    """Structured threat extracted from unstructured article text."""

    package_name: str
    ecosystem: str
    affected_versions: list[str] = Field(default_factory=list)
    attack_type: str
    confidence_score: float
    source_url: str
    summary: str = ""
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class AlertOut(BaseModel):
    """Alert representation for REST clients and the dashboard."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    repository_id: int | None
    title: str
    description: str
    severity: str
    risk_score: float
    status: str
    source_type: str
    metadata_json: dict[str, Any]
    created_at: datetime


class DependencyInsightOut(BaseModel):
    """Dashboard-friendly dependency row with version and risk context."""

    package_name: str
    ecosystem: str
    manifest_path: str
    detected_version: str
    detected_version_checked_at: datetime | None = None
    latest_version: str | None = None
    latest_version_published_at: datetime | None = None
    latest_version_status: str = "unknown"
    latest_version_source: str = ""
    was_compromised: bool = False
    compromised_signal: str = ""
    risk_severity: str = "none"
    risk_score: float = 0.0
    vulnerability_ids: list[str] = Field(default_factory=list)


class RuntimeFindingOut(BaseModel):
    """Runtime or image-level finding that is not represented as a manifest dependency row."""

    title: str
    source_type: str
    severity: str
    risk_score: float
    vulnerability_id: str = ""
    package_name: str = ""
    installed_version: str = ""
    fix_version: str | None = None
    target: str = ""
    description: str = ""
    last_seen_at: datetime | None = None


class SystemInventoryOut(BaseModel):
    """One scanned system or asset plus its expandable dependency inventory."""

    id: int
    owner: str
    name: str
    full_name: str
    display_name: str
    source_type: str
    risk_score: float
    dependency_count: int
    vulnerable_dependency_count: int
    open_alert_count: int
    last_scanned_at: datetime | None
    summary: str = ""
    dependencies: list[DependencyInsightOut] = Field(default_factory=list)
    runtime_findings: list[RuntimeFindingOut] = Field(default_factory=list)


class CodexPromptOut(BaseModel):
    """Reusable Codex prompt response for remediation actions in the dashboard."""

    title: str
    prompt: str


class ScanRequest(BaseModel):
    """Manual trigger parameters for `/scan`."""

    repository_full_name: str | None = None
    include_archived: bool = False
    force: bool = False


class ScanResponse(BaseModel):
    """Small acknowledgement returned after a scan request."""

    message: str
    repository_count: int
    alert_count: int


class ReportOut(BaseModel):
    """Aggregated report shown by API consumers and the dashboard."""

    generated_at: datetime
    repository_count: int
    dependency_count: int
    vulnerability_count: int
    alert_count: int
    critical_alert_count: int
    repository_risk: list[dict[str, Any]]
    recent_alerts: list[AlertOut]
    top_vulnerabilities: list[dict[str, Any]]
