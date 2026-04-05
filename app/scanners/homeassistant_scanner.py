"""
Purpose: Discover installed Home Assistant integrations from local mounts or a remote API.
Input/Output: Reads local Home Assistant storage/manifest files and optionally the official
REST API, then returns repository-like synthetic assets for downstream scanning and reporting.
Important invariants: Local scanning should keep working without remote access; remote scanning must
be explicitly enabled and should never break the rest of the scan if the API is unreachable.
Debugging: If integrations are missing, inspect `.storage/core.config_entries` for local mode or
test `/api/config` and `/api/components` with the same token for remote mode.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.repositories.store import upsert_repository
from app.services.homeassistant_remote import HomeAssistantRemoteClient, HomeAssistantRemoteError

LOGGER = logging.getLogger(__name__)


class HomeAssistantScanner:
    """Inventory installed Home Assistant integrations and their manifest locations."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.remote_client = HomeAssistantRemoteClient(self.settings)

    def sync_assets(self, session: Session) -> list[dict[str, Any]]:
        """Return Home Assistant assets discovered from whichever scan modes are enabled."""

        integrations: list[dict[str, Any]] = []
        if self.settings.homeassistant_scan_enabled:
            integrations.extend(self._sync_local_assets(session))
        if self.settings.homeassistant_remote_enabled:
            integrations.extend(self._sync_remote_assets(session))
        return integrations

    def _sync_local_assets(self, session: Session) -> list[dict[str, Any]]:
        """Discover integrations from mounted Home Assistant config files."""

        entries_path = self.settings.homeassistant_config_path / ".storage" / "core.config_entries"
        custom_components_path = self.settings.homeassistant_config_path / "custom_components"
        core_components_path = self.settings.homeassistant_core_components_path

        integrations: list[dict[str, Any]] = []
        config_entries = self._load_config_entries(entries_path)
        for entry in config_entries:
            domain = entry.get("domain")
            if not domain:
                continue
            manifest_path = self._resolve_manifest_path(
                domain,
                custom_components_path,
                core_components_path,
            )
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
                    "inventory_source": "local_files",
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
                metadata={
                    "domain": domain,
                    "manifest_path": str(manifest_path),
                    "source": "custom_component",
                    "inventory_source": "local_files",
                },
            )
            integrations.append(
                {
                    "repository": repository,
                    "domain": domain,
                    "manifest_path": manifest_path,
                }
            )
        return integrations

    def _sync_remote_assets(self, session: Session) -> list[dict[str, Any]]:
        """Discover integrations from a remote Home Assistant REST API."""

        try:
            inventory = self.remote_client.fetch_inventory()
        except HomeAssistantRemoteError as error:
            LOGGER.warning("Remote Home Assistant inventory failed", extra={"error": str(error)})
            return []

        owner = f"homeassistant-{inventory.instance_slug}"
        integrations: list[dict[str, Any]] = []
        for integration in inventory.integrations:
            repository = upsert_repository(
                session,
                source_type="homeassistant_remote",
                owner=owner,
                name=integration.domain,
                full_name=f"{owner}/{integration.domain}",
                clone_url=None,
                default_branch="",
                local_path="",
                metadata={
                    "domain": integration.domain,
                    "inventory_source": "rest_api",
                    "homeassistant_base_url": inventory.base_url.rstrip("/"),
                    "homeassistant_version": inventory.homeassistant_version,
                    "location_name": inventory.location_name,
                    "time_zone": inventory.time_zone,
                    "component_names": integration.component_names,
                    "platforms": integration.platforms,
                },
            )
            integrations.append(
                {
                    "repository": repository,
                    "domain": integration.domain,
                    "manifest_path": None,
                }
            )
        return integrations

    def _load_config_entries(self, entries_path: Path) -> list[dict[str, Any]]:
        """Read Home Assistant config entries from the `.storage` JSON file."""

        if not entries_path.exists():
            LOGGER.info(
                "Home Assistant config entries file not found",
                extra={"path": str(entries_path)},
            )
            return []
        try:
            payload = json.loads(entries_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            LOGGER.warning(
                "Failed to parse Home Assistant config entries",
                extra={"error": str(error)},
            )
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
