"""
Purpose: Decide whether a risky system can be remediated by Codex or should stay advisory-only.
Input/Output: Accepts stored repository/container metadata and returns a small remediation policy
object for API responses, dashboard labels, and Codex prompts.
Important invariants: Classification must fail closed; unknown or external ownership must never be
presented as safe for automatic pull-request changes.
Debugging: Compare the returned `mode`, `source_repository`, and `guidance` fields with the stored
repository `metadata` JSON when a dashboard button suggests the wrong action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from app.core.config import Settings, get_settings


@dataclass(frozen=True)
class RemediationPlan:
    """Backend-owned policy for Codex remediation prompts and queues."""

    ownership: str
    mode: str
    target: str
    summary: str
    source_repository: str | None = None
    issue_recommended: bool = False
    pull_request_allowed: bool = False
    scan_exclusion_recommended: bool = False
    guidance: list[str] = field(default_factory=list)
    allowed_actions: list[str] = field(default_factory=list)
    blocked_actions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RepositoryIdentity:
    """Small repository-like input that keeps this service independent from SQLAlchemy imports."""

    source_type: str
    owner: str
    name: str
    full_name: str
    clone_url: str | None
    metadata: dict[str, Any]


class RemediationPlanner:
    """Classify assets into managed-fix, advisory, or scan-exclusion remediation channels."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.managed_github_owners = {
            owner.strip().lower()
            for owner in self.settings.managed_github_owners
            if owner.strip()
        }
        self.managed_container_namespaces = {
            namespace.strip().lower()
            for namespace in self.settings.managed_container_namespaces
            if namespace.strip()
        }

    def classify(self, identity: RepositoryIdentity) -> RemediationPlan:
        """
        Return the safest remediation channel for one tracked asset.

        Example:
        `Feberdin/security-watchdog` becomes `managed_fix`, while a fork such as `Feberdin/core`
        becomes `exclude_recommended` because changes belong upstream and the operator already
        treats that fork as not relevant for active remediation.
        """

        if identity.source_type == "github":
            return self._classify_github(identity)
        if identity.source_type.startswith("unraid"):
            return self._classify_unraid_container(identity)
        if identity.source_type.startswith("homeassistant"):
            return self._classify_homeassistant(identity)
        return self._unknown_plan(identity)

    def _classify_github(self, identity: RepositoryIdentity) -> RemediationPlan:
        """Classify a GitHub repository using owner and fork metadata."""

        owner_is_managed = self._is_managed_github_owner(identity.owner)
        is_fork = bool(identity.metadata.get("fork"))
        if owner_is_managed and not is_fork:
            return RemediationPlan(
                ownership="owned",
                mode="managed_fix",
                target=identity.full_name,
                source_repository=identity.full_name,
                issue_recommended=True,
                pull_request_allowed=True,
                summary="Eigenes Repository: Codex darf Issue und PR-Vorschlag vorbereiten.",
                guidance=[
                    "Erzeuge eine dedizierte Branch/PR nur in diesem Repository.",
                    "Führe lokale Checks und CI für den exakten Commit aus.",
                    "Nutze Issues für Nachverfolgung, wenn der Fix nicht in einem Lauf fertig wird.",
                ],
                allowed_actions=[
                    "create_issue",
                    "create_branch",
                    "propose_pull_request",
                    "update_code_with_tests",
                ],
                blocked_actions=[
                    "merge_without_review",
                    "deploy_without_broker_gate",
                    "commit_secrets",
                ],
            )
        if owner_is_managed and is_fork:
            return RemediationPlan(
                ownership="fork",
                mode="exclude_recommended",
                target=identity.full_name,
                source_repository=self._github_parent_full_name(identity.metadata),
                issue_recommended=False,
                pull_request_allowed=False,
                scan_exclusion_recommended=True,
                summary="Fork in deinem Namespace: standardmäßig ausschließen oder nur Upstream beobachten.",
                guidance=[
                    "Keine automatische PR gegen den Fork erzeugen, solange er nicht aktiv gepflegt wird.",
                    "Wenn der Fork relevant wird, zuerst bewusst wieder für Scans aktivieren.",
                    "Für Upstream-Probleme einen Advisory-Text statt lokaler Codeänderungen erzeugen.",
                ],
                allowed_actions=[
                    "create_advisory_prompt",
                    "recommend_scan_exclusion",
                    "prepare_upstream_issue_text",
                ],
                blocked_actions=[
                    "propose_pull_request_without_active_ownership",
                    "change_homeassistant_upstream_fork_by_default",
                    "commit_secrets",
                ],
            )
        return RemediationPlan(
            ownership="external",
            mode="advisory_only",
            target=identity.full_name,
            source_repository=identity.full_name,
            issue_recommended=True,
            pull_request_allowed=False,
            summary="Externes Repository: nur Advisory oder Upstream-Issue-Text erzeugen.",
            guidance=[
                "Keine Schreibaktionen gegen fremde Repositories ausführen.",
                "Erzeuge einen klaren Issue-Text mit betroffenen Versionen, Fix-Hinweisen und Reproduktionskontext.",
                "Wenn du das Projekt nicht mehr nutzt, markiere es als Scan-Ausschlusskandidat.",
            ],
            allowed_actions=[
                "create_advisory_prompt",
                "prepare_upstream_issue_text",
                "recommend_replacement_or_pin",
            ],
            blocked_actions=[
                "create_branch",
                "propose_pull_request",
                "deploy_without_ownership",
                "commit_secrets",
            ],
        )

    def _classify_unraid_container(self, identity: RepositoryIdentity) -> RemediationPlan:
        """Classify a runtime container by image namespace and optional OCI source labels."""

        image_ref = self._image_reference(identity)
        source_repository = self._source_repository_from_metadata(identity.metadata)
        if source_repository and self._repository_full_name_is_managed(source_repository):
            return RemediationPlan(
                ownership="owned_image",
                mode="managed_fix",
                target=image_ref or identity.full_name,
                source_repository=source_repository,
                issue_recommended=True,
                pull_request_allowed=True,
                summary="Eigenes Container-Image mit Source-Repo: Codex darf dort Issue/PR vorbereiten.",
                guidance=[
                    "Behebe CVEs im Source-Repo des Images, nicht direkt am laufenden Container.",
                    "Aktualisiere Base-Image, Scanner-Binaries oder Lockfiles mit Tests und neuem Image-Build.",
                    "Deploy erst nach grünem Image-Publish und Security-Gate über den Broker planen.",
                ],
                allowed_actions=[
                    "create_issue",
                    "create_branch",
                    "propose_pull_request",
                    "update_dockerfile_or_lockfiles",
                    "verify_image_build",
                ],
                blocked_actions=[
                    "patch_running_container",
                    "docker_exec_or_shell_fix",
                    "deploy_without_broker_gate",
                    "commit_secrets",
                ],
            )
        if image_ref and self._image_ref_is_managed(image_ref):
            return RemediationPlan(
                ownership="owned_image",
                mode="source_mapping_required",
                target=image_ref,
                source_repository=None,
                issue_recommended=True,
                pull_request_allowed=False,
                summary="Eigenes Image ohne klares Source-Repo: erst Source-Zuordnung herstellen.",
                guidance=[
                    "Prüfe OCI-Labels wie `org.opencontainers.image.source` oder mappe das Image manuell.",
                    "Erzeuge ein Issue im passenden Source-Repo erst nach eindeutiger Zuordnung.",
                    "Bis dahin keine automatische Codeänderung vorschlagen.",
                ],
                allowed_actions=[
                    "create_mapping_prompt",
                    "prepare_issue_after_source_mapping",
                    "recommend_oci_source_label",
                ],
                blocked_actions=[
                    "guess_source_repository",
                    "propose_pull_request_without_source_mapping",
                    "patch_running_container",
                    "commit_secrets",
                ],
            )
        return RemediationPlan(
            ownership="external",
            mode="advisory_only",
            target=image_ref or identity.full_name,
            source_repository=source_repository,
            issue_recommended=False,
            pull_request_allowed=False,
            summary="Fremdes Container-Image: Update, Ersatz, Pinning oder Upstream-Meldung prüfen.",
            guidance=[
                "Keine PR gegen fremde Images oder unbekannte Source-Repositories erzeugen.",
                "Prüfe, ob ein neuer Image-Tag oder Digest die CVEs behebt.",
                "Wenn kein Fix verfügbar ist, erstelle einen Advisory-Text für Upstream oder plane einen Image-Ersatz.",
            ],
            allowed_actions=[
                "create_advisory_prompt",
                "recommend_image_update",
                "recommend_replacement_or_pin",
                "prepare_upstream_issue_text",
            ],
            blocked_actions=[
                "patch_running_container",
                "create_branch",
                "propose_pull_request",
                "commit_secrets",
            ],
        )

    def _classify_homeassistant(self, identity: RepositoryIdentity) -> RemediationPlan:
        """Classify Home Assistant assets using any source repository metadata when available."""

        source_repository = self._source_repository_from_metadata(identity.metadata)
        if source_repository and self._repository_full_name_is_managed(source_repository):
            return RemediationPlan(
                ownership="owned",
                mode="managed_fix",
                target=identity.full_name,
                source_repository=source_repository,
                issue_recommended=True,
                pull_request_allowed=True,
                summary="Eigene Home-Assistant-Integration: Codex darf Issue/PR vorbereiten.",
                guidance=[
                    "Ändere nur das zugeordnete Integrations-Repository.",
                    "Führe Hassfest oder die dokumentierten lokalen Checks aus.",
                    "Keine Home-Assistant-Core-Forks automatisch sanieren.",
                ],
                allowed_actions=["create_issue", "create_branch", "propose_pull_request", "run_hassfest"],
                blocked_actions=["change_homeassistant_core_fork_by_default", "commit_secrets"],
            )
        return RemediationPlan(
            ownership="external",
            mode="advisory_only",
            target=identity.full_name,
            source_repository=source_repository,
            issue_recommended=False,
            pull_request_allowed=False,
            summary="Home-Assistant-Asset ohne eigene Source-Zuordnung: nur Advisory.",
            guidance=[
                "Keine automatische Codeänderung ohne eindeutig eigenes Source-Repository.",
                "Bei fremden Integrationen Upstream-Issue-Text oder Ersatzempfehlung erzeugen.",
            ],
            allowed_actions=["create_advisory_prompt", "prepare_upstream_issue_text"],
            blocked_actions=["propose_pull_request_without_ownership", "commit_secrets"],
        )

    def _unknown_plan(self, identity: RepositoryIdentity) -> RemediationPlan:
        """Return a fail-closed plan for unsupported source types."""

        return RemediationPlan(
            ownership="unknown",
            mode="advisory_only",
            target=identity.full_name,
            summary="Unbekannter Ursprung: nur Advisory, keine automatische Änderung.",
            guidance=[
                "Ordne das System zuerst einer Quelle zu.",
                "Erzeuge nur einen Diagnose- oder Advisory-Prompt.",
            ],
            allowed_actions=["create_advisory_prompt", "export_debug_context"],
            blocked_actions=["create_branch", "propose_pull_request", "commit_secrets"],
        )

    def _is_managed_github_owner(self, owner: str) -> bool:
        """Return true when the GitHub owner is configured as operator-managed."""

        return owner.strip().lower() in self.managed_github_owners

    def _repository_full_name_is_managed(self, full_name: str | None) -> bool:
        """Return true when `owner/name` points into a managed GitHub namespace."""

        if not full_name or "/" not in full_name:
            return False
        owner, _name = full_name.split("/", maxsplit=1)
        return self._is_managed_github_owner(owner)

    def _image_ref_is_managed(self, image_ref: str) -> bool:
        """Return true when a container image belongs to a configured managed namespace."""

        normalized = image_ref.lower()
        if normalized.startswith("ghcr.io/"):
            parts = normalized.split("/")
            return len(parts) >= 3 and parts[1] in self.managed_container_namespaces
        if normalized.startswith("docker.io/"):
            parts = normalized.split("/")
            return len(parts) >= 3 and parts[1] in self.managed_container_namespaces
        first_segment = normalized.split("/", maxsplit=1)[0]
        return first_segment in self.managed_container_namespaces

    def _github_parent_full_name(self, metadata: dict[str, Any]) -> str | None:
        """Extract an upstream repository name from GitHub fork metadata when present."""

        parent = metadata.get("parent")
        source = metadata.get("source")
        for candidate in (parent, source):
            if isinstance(candidate, dict) and candidate.get("full_name"):
                return str(candidate["full_name"])
        return None

    def _image_reference(self, identity: RepositoryIdentity) -> str:
        """Return the most useful image reference from Unraid metadata."""

        for key in ("image", "image_ref"):
            value = identity.metadata.get(key)
            if value:
                return str(value)
        image_tags = identity.metadata.get("image_tags")
        if isinstance(image_tags, list) and image_tags:
            return str(image_tags[0])
        return ""

    def _source_repository_from_metadata(self, metadata: dict[str, Any]) -> str | None:
        """
        Extract a GitHub `owner/name` from OCI or scanner metadata.

        Example input/output:
        `{"labels": {"org.opencontainers.image.source": "https://github.com/Feberdin/watchlog"}}`
        becomes `Feberdin/watchlog`.
        """

        direct_keys = (
            "source_repository",
            "repository_full_name",
            "github_repository",
        )
        for key in direct_keys:
            value = metadata.get(key)
            if isinstance(value, str) and "/" in value and "://" not in value:
                return value.strip()

        labels = metadata.get("labels")
        if isinstance(labels, dict):
            for key in (
                "org.opencontainers.image.source",
                "org.opencontainers.image.url",
                "org.label-schema.vcs-url",
            ):
                value = labels.get(key)
                if isinstance(value, str):
                    parsed = self._github_full_name_from_url(value)
                    if parsed:
                        return parsed
        return None

    def _github_full_name_from_url(self, value: str) -> str | None:
        """Parse GitHub HTTPS/SSH URLs into `owner/name` when possible."""

        stripped = value.strip().removesuffix(".git")
        if stripped.startswith("git@github.com:"):
            stripped = stripped.removeprefix("git@github.com:")
            return stripped if "/" in stripped else None
        parsed = urlparse(stripped)
        if parsed.netloc.lower() != "github.com":
            return None
        path_parts = [part for part in parsed.path.split("/") if part]
        if len(path_parts) < 2:
            return None
        return f"{path_parts[0]}/{path_parts[1]}"
