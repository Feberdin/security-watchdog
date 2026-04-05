"""
Purpose: Generate CycloneDX and SPDX JSON documents from normalized dependency inventories.
Input/Output: Accepts repositories and dependencies and writes SBOM files to disk.
Important invariants: SBOM output paths must be deterministic so CI, backups, and operators know
where to look; documents should remain valid JSON even when metadata is sparse.
Debugging: If an SBOM seems incomplete, inspect the dependency list passed into this module first.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import get_settings
from app.core.utils import safe_slug
from app.models.entities import Dependency, Repository


class SbomService:
    """Create minimal but useful CycloneDX and SPDX JSON documents."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def generate(self, repository: Repository, dependencies: list[Dependency]) -> dict[str, str]:
        """Write both SBOM formats and return the output file paths."""

        repo_slug = safe_slug(repository.full_name)
        output_dir = self.settings.sbom_output_path / repo_slug
        output_dir.mkdir(parents=True, exist_ok=True)

        cyclonedx_path = output_dir / "cyclonedx.json"
        spdx_path = output_dir / "spdx.json"

        cyclonedx_path.write_text(
            json.dumps(self._build_cyclonedx(repository, dependencies), indent=2),
            encoding="utf-8",
        )
        spdx_path.write_text(
            json.dumps(self._build_spdx(repository, dependencies), indent=2),
            encoding="utf-8",
        )
        return {"cyclonedx": str(cyclonedx_path), "spdx": str(spdx_path)}

    def _build_cyclonedx(self, repository: Repository, dependencies: list[Dependency]) -> dict:
        """Build a CycloneDX 1.5 JSON document."""

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{safe_slug(repository.full_name)}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(UTC).isoformat(),
                "component": {"type": "application", "name": repository.full_name},
            },
            "components": [
                {
                    "type": "library" if dependency.ecosystem != "docker" else "container",
                    "name": dependency.package_name,
                    "version": dependency.version,
                    "purl": f"pkg:{dependency.ecosystem}/{dependency.package_name}@{dependency.version}",
                }
                for dependency in dependencies
            ],
        }

    def _build_spdx(self, repository: Repository, dependencies: list[Dependency]) -> dict:
        """Build an SPDX 2.3 JSON document."""

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": repository.full_name,
            "documentNamespace": f"https://feberdin.local/spdx/{safe_slug(repository.full_name)}",
            "creationInfo": {
                "created": datetime.now(UTC).isoformat(),
                "creators": ["Tool: security-watchdog"],
            },
            "packages": [
                {
                    "SPDXID": f"SPDXRef-{safe_slug(dependency.package_name)}",
                    "name": dependency.package_name,
                    "versionInfo": dependency.version,
                    "downloadLocation": "NOASSERTION",
                    "primaryPackagePurpose": "LIBRARY",
                }
                for dependency in dependencies
            ],
        }
