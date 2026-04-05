"""
Purpose: Verify Home Assistant integration discovery helper logic for mounted config data.
Input/Output: Creates temporary config-entry and custom-component files and checks the parsed output.
Important invariants: Path resolution should prefer custom components and gracefully handle missing
core paths because many real deployments mount only the config directory.
Debugging: If Home Assistant coverage regresses, these tests point at storage parsing or path lookup.
"""

from __future__ import annotations

import json

from app.scanners.homeassistant_scanner import HomeAssistantScanner


def test_loads_homeassistant_config_entries(tmp_path):
    storage_path = tmp_path / ".storage"
    storage_path.mkdir(parents=True)
    entries_path = storage_path / "core.config_entries"
    entries_path.write_text(
        json.dumps(
            {
                "data": {
                    "entries": [
                        {"entry_id": "1", "domain": "demo", "title": "Demo Integration", "source": "user"}
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
