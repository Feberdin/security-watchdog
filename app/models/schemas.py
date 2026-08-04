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
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ScanSource = Literal["github", "unraid", "homeassistant"]
DEFAULT_SCAN_SOURCES: tuple[ScanSource, ...] = ("github", "unraid", "homeassistant")
ScanPurpose = Literal["manual", "pre_deploy"]


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
    scan_enabled: bool = True
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
    content_source: str = "working_tree"
    commit_sha: str | None = None


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


class RemediationPlanOut(BaseModel):
    """Policy decision that tells Codex whether it may propose code changes for a system."""

    ownership: str = "unknown"
    mode: str = "advisory_only"
    target: str = ""
    source_repository: str | None = None
    issue_recommended: bool = False
    pull_request_allowed: bool = False
    scan_exclusion_recommended: bool = False
    summary: str = "Unbekannter Ursprung: nur Advisory, keine automatische Änderung."
    guidance: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)


class SystemLinkedAssetOut(BaseModel):
    """One raw scanned asset that is displayed as part of a grouped system."""

    id: int
    full_name: str
    display_name: str
    source_type: str
    scan_enabled: bool = True
    risk_score: float = 0.0
    open_alert_count: int = 0
    last_scanned_at: datetime | None = None
    summary: str = ""


class SystemInventoryOut(BaseModel):
    """One scanned system or asset plus its expandable dependency inventory."""

    id: int
    owner: str
    name: str
    full_name: str
    display_name: str
    source_type: str
    source_types: list[str] = Field(default_factory=list)
    scan_enabled: bool = True
    risk_score: float
    dependency_count: int
    vulnerable_dependency_count: int
    open_alert_count: int
    last_scanned_at: datetime | None
    summary: str = ""
    dependencies: list[DependencyInsightOut] = Field(default_factory=list)
    runtime_findings: list[RuntimeFindingOut] = Field(default_factory=list)
    linked_assets: list[SystemLinkedAssetOut] = Field(default_factory=list)
    remediation: RemediationPlanOut = Field(default_factory=RemediationPlanOut)


class HighRiskDependencyUpdateOut(BaseModel):
    """One dependency update candidate for the Codex high-risk update queue."""

    package_name: str
    ecosystem: str
    manifest_path: str
    current_version: str
    target_version: str | None = None
    latest_version_status: str = "unknown"
    latest_version_source: str = ""
    risk_severity: str = "none"
    risk_score: float = 0.0
    vulnerability_ids: list[str] = Field(default_factory=list)
    was_compromised: bool = False
    compromised_signal: str = ""
    action: str = "review"


class HighRiskSystemUpdateOut(BaseModel):
    """One repository or runtime system that Codex should update or investigate."""

    repository_id: int
    full_name: str
    display_name: str
    source_type: str
    risk_score: float
    priority: str
    reason: str
    remediation: RemediationPlanOut = Field(default_factory=RemediationPlanOut)
    dependencies: list[HighRiskDependencyUpdateOut] = Field(default_factory=list)
    runtime_findings: list[RuntimeFindingOut] = Field(default_factory=list)


class HighRiskUpdateQueueOut(BaseModel):
    """Prioritized update queue used by the dashboard and Codex automation prompt."""

    generated_at: datetime
    task_count: int
    tasks: list[HighRiskSystemUpdateOut] = Field(default_factory=list)
    guidance: list[str] = Field(default_factory=list)


class DailySecurityAutomationOut(BaseModel):
    """Machine-readable runbook for the daily Codex security update automation."""

    api_version: str
    generated_at: datetime
    recommended_schedule: str
    max_tasks_per_run: int
    queue: HighRiskUpdateQueueOut
    guardrails: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    source_endpoints: dict[str, str] = Field(default_factory=dict)
    codex_prompt: str


class DeploymentSecurityGateRequest(BaseModel):
    """Deployment candidate identity supplied by the Deployment Broker."""

    api_version: Literal["2026-08-03"] = "2026-08-03"
    stack_name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    repository_full_name: str = Field(
        min_length=3,
        max_length=255,
        pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
    )
    commit_sha: str = Field(min_length=40, max_length=40, pattern=r"^[0-9a-fA-F]{40}$")
    compose_file: str = Field(default="docker-compose.yml", min_length=1, max_length=512)

    @field_validator("commit_sha")
    @classmethod
    def normalize_commit_sha(cls, value: str) -> str:
        """Normalize full Git SHAs so comparisons are deterministic."""

        return value.lower()

    @field_validator("compose_file")
    @classmethod
    def validate_compose_file(cls, value: str) -> str:
        """Reject absolute or parent-traversing paths before they enter audit records."""

        normalized = value.strip().replace("\\", "/")
        if normalized.startswith("/") or ".." in normalized.split("/"):
            raise ValueError("compose_file must be a repository-relative path without '..'")
        return normalized


class DeploymentSecurityGatePolicyOut(BaseModel):
    """Server-controlled policy values used for one deployment decision."""

    max_scan_age_hours: int
    blocked_severities: list[str]
    unresolved_statuses: list[str]
    max_returned_blockers: int


class DeploymentSecurityGateEvidenceOut(BaseModel):
    """Commit-bound aggregate scan evidence used by the deployment gate."""

    scan_result_id: int
    scanner_name: str
    status: str
    scanned_commit_sha: str | None = None
    completed_at: datetime | None = None
    age_hours: float | None = None
    commit_matches: bool = False


class DeploymentSecurityGateBlockerOut(BaseModel):
    """One actionable reason why a deployment must not continue."""

    code: str
    finding_id: str
    severity: str
    title: str
    source_type: str
    remediation: str
    context: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class DeploymentSecurityGateSummaryOut(BaseModel):
    """Compact blocker counts for broker policy and audit logs."""

    blocker_count: int
    returned_blocker_count: int
    critical_count: int
    high_count: int
    evidence_blocker_count: int
    results_truncated: bool


class DeploymentSecurityGateResponse(BaseModel):
    """Fail-closed deployment decision returned to the Deployment Broker."""

    api_version: str
    request_id: str
    checked_at: datetime
    decision: Literal["allow", "deny", "indeterminate"]
    deploy_allowed: bool
    reason_codes: list[str]
    stack_name: str
    repository_full_name: str
    requested_commit_sha: str
    compose_file: str
    policy: DeploymentSecurityGatePolicyOut
    evidence: DeploymentSecurityGateEvidenceOut | None = None
    summary: DeploymentSecurityGateSummaryOut
    blockers: list[DeploymentSecurityGateBlockerOut] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class DeploymentGateStatusOut(BaseModel):
    """Dashboard-safe gate status plus the next operator action."""

    gate: DeploymentSecurityGateResponse
    recommended_action: str
    can_queue_pre_deploy_scan: bool


class CodexPromptOut(BaseModel):
    """Reusable Codex prompt response for remediation actions in the dashboard."""

    title: str
    prompt: str


class ScanRequest(BaseModel):
    """Manual trigger parameters for `/scan`."""

    repository_full_name: str | None = None
    include_archived: bool = False
    force: bool = False
    scan_sources: list[ScanSource] = Field(default_factory=lambda: list(DEFAULT_SCAN_SOURCES))
    priority: int = Field(default=0, ge=0, le=100)
    pause_active: bool = False
    purpose: ScanPurpose = "manual"
    target_commit_sha: str | None = Field(default=None, min_length=40, max_length=40)
    refresh_image_cache: bool = False

    @field_validator("repository_full_name")
    @classmethod
    def normalize_repository_full_name(cls, value: str | None) -> str | None:
        """Treat blank UI values as an estate-wide scan instead of a broken exact target."""

        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("scan_sources")
    @classmethod
    def validate_scan_sources(cls, value: list[ScanSource]) -> list[ScanSource]:
        """Keep scan selection explicit, non-empty, and deterministic for persistence."""

        deduplicated = list(dict.fromkeys(value))
        if not deduplicated:
            raise ValueError("scan_sources must contain at least one source")
        return deduplicated

    @field_validator("target_commit_sha")
    @classmethod
    def normalize_target_commit_sha(cls, value: str | None) -> str | None:
        """Accept only full hexadecimal SHAs for commit-bound pre-deploy scans."""

        if value is None:
            return None
        normalized = value.strip().lower()
        if len(normalized) != 40 or any(character not in "0123456789abcdef" for character in normalized):
            raise ValueError("target_commit_sha must be a full 40-character hexadecimal commit SHA")
        return normalized


class RepositoryScanSettingsRequest(BaseModel):
    """Operator-controlled repository scan visibility update."""

    scan_enabled: bool


class RepositoryBulkScanSettingsRequest(BaseModel):
    """Bulk scan visibility update for repository-like assets."""

    repository_ids: list[int] = Field(min_length=1, max_length=500)
    scan_enabled: bool

    @field_validator("repository_ids")
    @classmethod
    def validate_repository_ids(cls, value: list[int]) -> list[int]:
        """Deduplicate positive IDs while preserving the selected order."""

        deduplicated = list(dict.fromkeys(value))
        if any(repository_id <= 0 for repository_id in deduplicated):
            raise ValueError("repository_ids must contain only positive IDs")
        return deduplicated


class PreDeployScanRequest(BaseModel):
    """Queue a focused repository scan that can satisfy the deployment gate."""

    stack_name: str = Field(default="security-watchdog", min_length=1, max_length=128)
    repository_full_name: str = Field(min_length=3, max_length=255)
    commit_sha: str = Field(min_length=40, max_length=40)
    compose_file: str = Field(default="docker-compose.yml", min_length=1, max_length=512)
    pause_active: bool = True

    @field_validator("commit_sha")
    @classmethod
    def normalize_commit_sha(cls, value: str) -> str:
        """Normalize full Git SHAs before they enter queue metadata."""

        normalized = value.strip().lower()
        if len(normalized) != 40 or any(character not in "0123456789abcdef" for character in normalized):
            raise ValueError("commit_sha must be a full 40-character hexadecimal commit SHA")
        return normalized


class ScanResponse(BaseModel):
    """Small acknowledgement returned after a scan request."""

    message: str
    repository_count: int
    alert_count: int
    failed_system_count: int = 0


class ScanAcceptedResponse(BaseModel):
    """Acknowledgement returned when a manual scan was queued successfully."""

    message: str
    job_id: int
    status: str
    status_url: str


class ScanProgressUpdate(BaseModel):
    """Validated internal progress update emitted by the scan orchestrator."""

    phase: str = Field(min_length=1, max_length=50)
    message: str = Field(min_length=1, max_length=1000)
    level: Literal["info", "warning", "error"] = "info"
    current: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)
    percent: float = Field(default=0.0, ge=0.0, le=100.0)


class ManualScanProgressEventOut(ScanProgressUpdate):
    """One timestamped progress line returned to dashboard clients."""

    created_at: datetime


class ManualScanProgressOut(BaseModel):
    """Current progress snapshot plus a small chronological operator log."""

    phase: str
    message: str
    current: int = 0
    total: int = 0
    percent: float = Field(default=0.0, ge=0.0, le=100.0)
    events: list[ManualScanProgressEventOut] = Field(default_factory=list)


class ManualScanJobOut(BaseModel):
    """API-friendly view of one manual scan job and its current lifecycle state."""

    id: int
    status: str
    message: str
    repository_full_name: str | None = None
    include_archived: bool
    force: bool
    scan_sources: list[ScanSource] = Field(default_factory=lambda: list(DEFAULT_SCAN_SOURCES))
    cancel_requested: bool = False
    pause_requested: bool = False
    priority: int = 0
    purpose: ScanPurpose = "manual"
    target_commit_sha: str | None = None
    refresh_image_cache: bool = False
    requested_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    repository_count: int = 0
    alert_count: int = 0
    failed_system_count: int = 0
    error_message: str | None = None
    progress: ManualScanProgressOut


class ManualScanQueuePositionOut(BaseModel):
    """One ordered entry in the manual scan queue."""

    position: int
    job: ManualScanJobOut


class ManualScanQueueOverviewOut(BaseModel):
    """Current/queued manual scan worklist, sorted by priority."""

    generated_at: datetime
    current: ManualScanJobOut | None = None
    queue: list[ManualScanQueuePositionOut] = Field(default_factory=list)
    next_job: ManualScanJobOut | None = None


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
