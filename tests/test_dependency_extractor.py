"""
Purpose: Verify dependency extraction across the main manifest formats used in the project.
Input/Output: Creates temporary manifest files and checks normalized `DependencyRecord` outputs.
Important invariants: Tests focus on readable, deterministic parsing for core ecosystems.
Debugging: If one parser regresses, this test file should show the exact manifest and expectation.
"""

from __future__ import annotations

import json

from app.scanners.dependency_extractor import DependencyExtractor


def test_extracts_poetry_dependencies_from_pyproject(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.poetry.dependencies]
python = "^3.12"
httpx = "^0.28.1"
sqlalchemy = "2.0.40"
""".strip(),
        encoding="utf-8",
    )

    records = DependencyExtractor().extract_from_path(pyproject, tmp_path)

    assert [record.package_name for record in records] == ["httpx", "sqlalchemy"]
    assert records[0].ecosystem == "pypi"


def test_extracts_docker_base_image_from_dockerfile(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\n", encoding="utf-8")

    records = DependencyExtractor().extract_from_path(dockerfile, tmp_path)

    assert len(records) == 1
    assert records[0].package_name == "python"
    assert records[0].version == "3.12-slim"


def test_extracts_homeassistant_requirements_from_manifest(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"domain": "demo", "requirements": ["aiohttp==3.10.0", "tenacity>=8.5.0"]}),
        encoding="utf-8",
    )

    records = DependencyExtractor().extract_from_path(manifest, tmp_path)

    assert [record.package_name for record in records] == ["aiohttp", "tenacity"]
    assert all(record.metadata["source"] == "homeassistant_manifest" for record in records)
