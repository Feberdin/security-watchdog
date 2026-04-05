"""
Purpose: Discover installed Home Assistant integrations from mounted configuration directories.
Input/Output: Reads Home Assistant storage and manifest files and returns synthetic assets.
Important invariants: The scanner should work with custom components alone but can enrich built-in
integration metadata when the core components path is also mounted into the container.
Debugging: If integrations are missing, inspect `.storage/core.config_entries` and the mounted paths.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.repositories.store import upsert_repository

LOGGER = logging.getLogger(__name__)


class HomeAssistantScanner:
    """Inventory installed Home Assistant integrations and their manifest locations."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def sync_assets(self, session: Session) -> list[dict[str, Any]]:
        """Return Home Assistant integrations discovered from local configuration state."""

        if not self.settings.homeassistant_scan_enabled:
            return []

        entries_path = self.settings.homeassistant_config_path / ".storage" / "core.config_entries"
        custom_components_path = self.settings.homeassistant_config_path / "custom_components"
        core_components_path = self.settings.homeassistant_core_components_path

        integrations: list[dict[str, Any]] = []
        config_entries = self._load_config_entries(entries_path)
        for entry in config_entries:
            domain = entry.get("domain")
            if not domain:
                continue
            manifest_path = self._resolve_manifest_path(domain, custom_components_path, core_components_path)
            local_path = str(manifest_path.parent) if manifest_path else ""
            repository = upsert_repository(
                session,
                source_type="homeassistant",
                owner="homeassistant",
                name=domain,
                full_name=f"homeassistant/{domain}",
                clone_url=None,
                default_branch="",
                local_path=local_path,
                metadata={
                    "entry_id": entry.get("entry_id"),
                    "title": entry.get("title"),
                    "domain": domain,
                    "manifest_path": str(manifest_path) if manifest_path else "",
                    "source": entry.get("source"),
                },
            )
            integrations.append(
                {
                    "repository": repository,
                    "domain": domain,
                    "manifest_path": manifest_path,
                }
            )

        for manifest_path in custom_components_path.glob("*/manifest.json"):
            domain = manifest_path.parent.name
            full_name = f"homeassistant/{domain}"
            if any(item["repository"].full_name == full_name for item in integrations):
                continue
            repository = upsert_repository(
                session,
                source_type="homeassistant",
                owner="homeassistant",
                name=domain,
                full_name=full_name,
                clone_url=None,
                default_branch="",
                local_path=str(manifest_path.parent),
                metadata={"domain": domain, "manifest_path": str(manifest_path), "source": "custom_component"},
            )
            integrations.append(
                {
                    "repository": repository,
                    "domain": domain,
                    "manifest_path": manifest_path,
                }
            )
        return integrations

    def _load_config_entries(self, entries_path: Path) -> list[dict[str, Any]]:
        """Read Home Assistant config entries from the `.storage` JSON file."""

        if not entries_path.exists():
            LOGGER.info("Home Assistant config entries file not found", extra={"path": str(entries_path)})
            return []
        try:
            payload = json.loads(entries_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            LOGGER.warning("Failed to parse Home Assistant config entries", extra={"error": str(error)})
            return []
        return payload.get("data", {}).get("entries", [])

    def _resolve_manifest_path(
        self,
        domain: str,
        custom_components_path: Path,
        core_components_path: Path,
    ) -> Path | None:
        """Find the manifest for a Home Assistant integration in mounted paths."""

        custom_manifest = custom_components_path / domain / "manifest.json"
        if custom_manifest.exists():
            return custom_manifest
        core_manifest = core_components_path / domain / "manifest.json"
        if core_manifest.exists():
            return core_manifest
        return None
