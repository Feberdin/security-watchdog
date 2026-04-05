"""
Purpose: Verify Home Assistant integration discovery for both mounted files and remote API mode.
Input/Output: Creates temporary config-entry/custom-component files and synthetic remote API
inventories, then checks the normalized scanner output.
Important invariants: Local path resolution should prefer custom components, while remote mode
should collapse Home Assistant component strings into stable integration domains.
Debugging: If Home Assistant coverage regresses, these tests point at storage parsing, path lookup,
or remote inventory normalization.
"""

from __future__ import annotations

import json

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import app.models.entities  # noqa: F401
from app.db.base import Base
from app.scanners.homeassistant_scanner import HomeAssistantScanner
from app.services.homeassistant_remote import (
    HomeAssistantRemoteIntegration,
    HomeAssistantRemoteInventory,
)


def build_test_session() -> Session:
    """Create a throwaway in-memory database session for scanner persistence tests."""

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return Session(engine)


def test_loads_homeassistant_config_entries(tmp_path):
    storage_path = tmp_path / ".storage"
    storage_path.mkdir(parents=True)
    entries_path = storage_path / "core.config_entries"
    entries_path.write_text(
        json.dumps(
            {
                "data": {
                    "entries": [
                        {
                            "entry_id": "1",
                            "domain": "demo",
                            "title": "Demo Integration",
                            "source": "user",
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    entries = HomeAssistantScanner()._load_config_entries(entries_path)

    assert entries[0]["domain"] == "demo"


def test_prefers_custom_component_manifest_path(tmp_path):
    custom_components_path = tmp_path / "custom_components"
    core_components_path = tmp_path / "core_components"
    custom_manifest = custom_components_path / "demo" / "manifest.json"
    custom_manifest.parent.mkdir(parents=True)
    core_manifest = core_components_path / "demo" / "manifest.json"
    core_manifest.parent.mkdir(parents=True)
    custom_manifest.write_text("{}", encoding="utf-8")
    core_manifest.write_text("{}", encoding="utf-8")

    manifest_path = HomeAssistantScanner()._resolve_manifest_path(
        "demo",
        custom_components_path,
        core_components_path,
    )

    assert manifest_path == custom_manifest


def test_normalizes_remote_components_into_integration_domains():
    scanner = HomeAssistantScanner()

    integrations = scanner.remote_client._normalize_integrations(
        ["tapo.switch", "tapo.sensor", "hacs", "sensor", "config.core"]
    )

    by_domain = {integration.domain: integration for integration in integrations}
    assert by_domain["tapo"].component_names == ["tapo.sensor", "tapo.switch"]
    assert by_domain["tapo"].platforms == ["sensor", "switch"]
    assert by_domain["hacs"].component_names == ["hacs"]
    assert by_domain["sensor"].platforms == []


def test_syncs_remote_homeassistant_integrations_into_assets():
    session = build_test_session()
    scanner = HomeAssistantScanner()
    scanner.settings.homeassistant_scan_enabled = False
    scanner.settings.homeassistant_remote_enabled = True
    scanner.remote_client.fetch_inventory = lambda: HomeAssistantRemoteInventory(
        base_url="https://ha.example.local:8123/",
        instance_slug="ha-example-local-8123",
        location_name="Home",
        homeassistant_version="2026.4.0",
        time_zone="Europe/Berlin",
        integrations=[
            HomeAssistantRemoteIntegration(domain="hacs", component_names=["hacs"], platforms=[]),
            HomeAssistantRemoteIntegration(
                domain="tapo",
                component_names=["tapo.sensor", "tapo.switch"],
                platforms=["sensor", "switch"],
            ),
        ],
        raw_config={"version": "2026.4.0"},
    )

    assets = scanner.sync_assets(session)

    assert len(assets) == 2
    assert assets[0]["repository"].source_type == "homeassistant_remote"
    assert assets[0]["repository"].metadata_json["inventory_source"] == "rest_api"
    assert assets[0]["repository"].owner == "homeassistant-ha-example-local-8123"
