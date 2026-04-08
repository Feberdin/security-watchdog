"""
Purpose: Scan Docker images and Dockerfiles with Trivy and Grype and normalize findings.
Input/Output: Calls external scanner binaries and returns `ContainerFinding` objects.
Important invariants: Tool failures should be logged and converted into empty results instead of
crashing the whole pipeline; findings must preserve the originating tool and target.
Debugging: If scans return nothing, verify that `trivy` and `grype` are installed inside the image
and run the logged command manually with `LOG_LEVEL=debug`.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app.core.config import get_settings
from app.core.utils import run_command
from app.models.schemas import ContainerFinding

LOGGER = logging.getLogger(__name__)


class ContainerScanner:
    """Wrapper around Trivy and Grype for container security findings."""

    def __init__(self) -> None:
        settings = get_settings()
        self.trivy_binary = settings.trivy_binary
        self.grype_binary = settings.grype_binary

    def scan_image(self, image_ref: str) -> list[ContainerFinding]:
        """Run both scanners against a container image reference."""

        findings: list[ContainerFinding] = []
        findings.extend(self._scan_with_trivy_image(image_ref))
        findings.extend(self._scan_with_grype(image_ref))
        return self._deduplicate_findings(findings)

    def scan_dockerfile(self, dockerfile_path: Path) -> list[ContainerFinding]:
        """Run Trivy config scanning on one Dockerfile when available."""

        try:
            output = run_command(
                [self.trivy_binary, "config", "--format", "json", str(dockerfile_path)],
                cwd=dockerfile_path.parent,
                timeout=180,
            )
        except Exception as error:  # noqa: BLE001
            LOGGER.warning(
                "Trivy Dockerfile scan failed",
                extra={"dockerfile": str(dockerfile_path), "error": str(error)},
            )
            return []

        findings: list[ContainerFinding] = []
        payload = json.loads(output or "{}")
        for result in payload.get("Results", []):
            for misconfiguration in result.get("Misconfigurations", []):
                findings.append(
                    ContainerFinding(
                        tool="trivy-config",
                        target=str(dockerfile_path),
                        vulnerability_id=misconfiguration.get("ID", "unknown"),
                        package_name=misconfiguration.get("Title", "dockerfile"),
                        installed_version="n/a",
                        severity=(misconfiguration.get("Severity") or "UNKNOWN").lower(),
                        description=misconfiguration.get("Description", ""),
                    )
                )
        return findings

    def _scan_with_trivy_image(self, image_ref: str) -> list[ContainerFinding]:
        """Parse Trivy image scan JSON output."""

        try:
            output = run_command(
                [self.trivy_binary, "image", "--format", "json", image_ref],
                timeout=600,
            )
        except Exception as error:  # noqa: BLE001
            LOGGER.warning("Trivy image scan failed", extra={"image": image_ref, "error": str(error)})
            return []
        findings: list[ContainerFinding] = []
        payload = json.loads(output or "{}")
        for result in payload.get("Results", []):
            for vulnerability in result.get("Vulnerabilities", []):
                findings.append(
                    ContainerFinding(
                        tool="trivy",
                        target=image_ref,
                        vulnerability_id=vulnerability.get("VulnerabilityID", "unknown"),
                        package_name=vulnerability.get("PkgName", "unknown"),
                        installed_version=vulnerability.get("InstalledVersion", "unknown"),
                        severity=(vulnerability.get("Severity") or "unknown").lower(),
                        fix_version=vulnerability.get("FixedVersion"),
                        description=vulnerability.get("Title", ""),
                    )
                )
        return findings

    def _scan_with_grype(self, image_ref: str) -> list[ContainerFinding]:
        """Parse Grype image scan JSON output."""

        try:
            output = run_command([self.grype_binary, image_ref, "-o", "json"], timeout=600)
        except Exception as error:  # noqa: BLE001
            LOGGER.warning("Grype image scan failed", extra={"image": image_ref, "error": str(error)})
            return []
        findings: list[ContainerFinding] = []
        payload = json.loads(output or "{}")
        for match in payload.get("matches", []):
            vulnerability = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            findings.append(
                ContainerFinding(
                    tool="grype",
                    target=image_ref,
                    vulnerability_id=vulnerability.get("id", "unknown"),
                    package_name=artifact.get("name", "unknown"),
                    installed_version=artifact.get("version", "unknown"),
                    severity=(vulnerability.get("severity") or "unknown").lower(),
                    fix_version=", ".join(vulnerability.get("fix", {}).get("versions", [])) or None,
                    description=vulnerability.get("description", ""),
                )
            )
        return findings

    def _deduplicate_findings(self, findings: list[ContainerFinding]) -> list[ContainerFinding]:
        """
        Collapse duplicate image findings reported by multiple scanners.

        Why this exists:
        Trivy and Grype frequently report the same package/CVE pair. Keeping both as independent
        alerts doubles operator noise without adding much value, so we retain one merged record per
        affected package/version/vulnerability tuple.
        """

        deduplicated: dict[tuple[str, str, str, str], ContainerFinding] = {}
        for finding in findings:
            key = (
                finding.target,
                finding.vulnerability_id,
                finding.package_name,
                finding.installed_version,
            )
            existing = deduplicated.get(key)
            if existing is None:
                deduplicated[key] = finding
                continue
            if not existing.fix_version and finding.fix_version:
                existing.fix_version = finding.fix_version
            if len(finding.description or "") > len(existing.description or ""):
                existing.description = finding.description
            if existing.tool != finding.tool and finding.tool not in existing.tool.split("+"):
                existing.tool = f"{existing.tool}+{finding.tool}"
        return list(deduplicated.values())
