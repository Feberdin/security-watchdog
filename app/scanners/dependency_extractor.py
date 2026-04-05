"""
Purpose: Detect dependency manifests and normalize package/version tuples across ecosystems.
Input/Output: Reads repository or integration files and returns `DependencyRecord` objects.
Important invariants: Parsing should degrade gracefully when one manifest is malformed so the rest
of the repository can still be scanned; every record must include ecosystem and manifest path.
Debugging: If dependencies are missing, log the manifest path and parser branch taken in this file.
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from app.models.schemas import DependencyRecord

LOGGER = logging.getLogger(__name__)

SUPPORTED_MANIFESTS = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "pom.xml",
    "build.gradle",
    "composer.json",
    "Cargo.toml",
    "go.mod",
    "Dockerfile",
    "manifest.json",
}


class DependencyExtractor:
    """Discover manifests and extract normalized dependency records."""

    def discover_manifests(self, root_path: Path) -> list[Path]:
        """Walk a directory tree and return supported manifest files."""

        manifests: list[Path] = []
        for path in root_path.rglob("*"):
            if not path.is_file():
                continue
            if any(part in {".git", ".venv", "node_modules", "__pycache__"} for part in path.parts):
                continue
            if path.name in SUPPORTED_MANIFESTS:
                manifests.append(path)
        return manifests

    def extract_from_path(self, manifest_path: Path, root_path: Path) -> list[DependencyRecord]:
        """Dispatch one manifest to the correct parser."""

        relative_path = manifest_path.relative_to(root_path).as_posix()
        parser_map = {
            "requirements.txt": self._parse_requirements_txt,
            "pyproject.toml": self._parse_pyproject_toml,
            "package.json": self._parse_package_json,
            "package-lock.json": self._parse_package_lock_json,
            "pom.xml": self._parse_pom_xml,
            "build.gradle": self._parse_build_gradle,
            "composer.json": self._parse_composer_json,
            "Cargo.toml": self._parse_cargo_toml,
            "go.mod": self._parse_go_mod,
            "Dockerfile": self._parse_dockerfile,
            "manifest.json": self._parse_homeassistant_manifest,
        }
        parser = parser_map.get(manifest_path.name)
        if not parser:
            return []
        try:
            return parser(manifest_path, relative_path)
        except Exception as error:  # noqa: BLE001
            LOGGER.warning(
                "Dependency parsing failed",
                extra={"manifest_path": str(manifest_path), "error": str(error)},
            )
            return []

    def extract_from_repository(self, root_path: Path) -> list[DependencyRecord]:
        """Extract dependencies from every supported manifest in a repository."""

        dependencies: list[DependencyRecord] = []
        for manifest_path in self.discover_manifests(root_path):
            dependencies.extend(self.extract_from_path(manifest_path, root_path))
        return dependencies

    def _parse_requirements_txt(
        self, manifest_path: Path, relative_path: str
    ) -> list[DependencyRecord]:
        """Parse pinned Python dependencies from `requirements.txt`."""

        records: list[DependencyRecord] = []
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-r"):
                continue
            package_name, version = self._split_requirement_line(stripped)
            records.append(
                DependencyRecord(
                    package_name=package_name,
                    version=version,
                    ecosystem="pypi",
                    manifest_path=relative_path,
                )
            )
        return records

    def _parse_pyproject_toml(
        self, manifest_path: Path, relative_path: str
    ) -> list[DependencyRecord]:
        """Parse PEP 621 and Poetry-style dependency declarations."""

        data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        records: list[DependencyRecord] = []

        for item in data.get("project", {}).get("dependencies", []):
            package_name, version = self._split_requirement_line(item)
            records.append(
                DependencyRecord(
                    package_name=package_name,
                    version=version,
                    ecosystem="pypi",
                    manifest_path=relative_path,
                )
            )

        poetry_dependencies = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for package_name, version in poetry_dependencies.items():
            if package_name == "python":
                continue
            records.append(
                DependencyRecord(
                    package_name=package_name,
                    version=str(version),
                    ecosystem="pypi",
                    manifest_path=relative_path,
                )
            )
        return records

    def _parse_package_json(self, manifest_path: Path, relative_path: str) -> list[DependencyRecord]:
        """Parse npm package declarations from `package.json`."""

        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        records: list[DependencyRecord] = []
        for section_name in ("dependencies", "devDependencies", "optionalDependencies"):
            for package_name, version in data.get(section_name, {}).items():
                records.append(
                    DependencyRecord(
                        package_name=package_name,
                        version=str(version),
                        ecosystem="npm",
                        manifest_path=relative_path,
                        metadata={"section": section_name},
                    )
                )
        return records

    def _parse_package_lock_json(
        self, manifest_path: Path, relative_path: str
    ) -> list[DependencyRecord]:
        """Parse concrete npm versions from lock files where available."""

        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        records: list[DependencyRecord] = []

        packages = data.get("packages", {})
        for package_path, package_data in packages.items():
            if not package_path.startswith("node_modules/"):
                continue
            package_name = package_path.split("node_modules/", maxsplit=1)[1]
            version = str(package_data.get("version", "unknown"))
            records.append(
                DependencyRecord(
                    package_name=package_name,
                    version=version,
                    ecosystem="npm",
                    manifest_path=relative_path,
                    direct_dependency=False,
                    metadata={"section": "lock"},
                )
            )
        return records

    def _parse_pom_xml(self, manifest_path: Path, relative_path: str) -> list[DependencyRecord]:
        """Parse Maven dependencies from XML."""

        tree = ET.parse(manifest_path)
        root = tree.getroot()
        namespace = {"mvn": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
        dependency_xpath = ".//mvn:dependency" if namespace else ".//dependency"

        records: list[DependencyRecord] = []
        for dependency in root.findall(dependency_xpath, namespace):
            group = dependency.findtext("mvn:groupId" if namespace else "groupId", default="", namespaces=namespace)
            artifact = dependency.findtext(
                "mvn:artifactId" if namespace else "artifactId",
                default="",
                namespaces=namespace,
            )
            version = dependency.findtext("mvn:version" if namespace else "version", default="", namespaces=namespace)
            if artifact:
                records.append(
                    DependencyRecord(
                        package_name=f"{group}:{artifact}" if group else artifact,
                        version=version or "unspecified",
                        ecosystem="maven",
                        manifest_path=relative_path,
                        group_name=group or None,
                    )
                )
        return records

    def _parse_build_gradle(self, manifest_path: Path, relative_path: str) -> list[DependencyRecord]:
        """Parse common Gradle dependency declarations."""

        content = manifest_path.read_text(encoding="utf-8")
        pattern = re.compile(
            r"(?P<section>implementation|api|runtimeOnly|testImplementation)\s+['\"](?P<group>[^:'\"]+):(?P<artifact>[^:'\"]+):(?P<version>[^'\"]+)['\"]"
        )
        return [
            DependencyRecord(
                package_name=f"{match.group('group')}:{match.group('artifact')}",
                version=match.group("version"),
                ecosystem="gradle",
                manifest_path=relative_path,
                group_name=match.group("group"),
                metadata={"section": match.group("section")},
            )
            for match in pattern.finditer(content)
        ]

    def _parse_composer_json(
        self, manifest_path: Path, relative_path: str
    ) -> list[DependencyRecord]:
        """Parse PHP Composer dependencies."""

        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        records: list[DependencyRecord] = []
        for section_name in ("require", "require-dev"):
            for package_name, version in data.get(section_name, {}).items():
                if package_name == "php":
                    continue
                records.append(
                    DependencyRecord(
                        package_name=package_name,
                        version=str(version),
                        ecosystem="packagist",
                        manifest_path=relative_path,
                        metadata={"section": section_name},
                    )
                )
        return records

    def _parse_cargo_toml(self, manifest_path: Path, relative_path: str) -> list[DependencyRecord]:
        """Parse Rust crate dependencies."""

        data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        records: list[DependencyRecord] = []
        for table_name in ("dependencies", "dev-dependencies"):
            for package_name, value in data.get(table_name, {}).items():
                version = value.get("version", "unspecified") if isinstance(value, dict) else str(value)
                records.append(
                    DependencyRecord(
                        package_name=package_name,
                        version=version,
                        ecosystem="crates.io",
                        manifest_path=relative_path,
                        metadata={"section": table_name},
                    )
                )
        return records

    def _parse_go_mod(self, manifest_path: Path, relative_path: str) -> list[DependencyRecord]:
        """Parse Go module requirements from `go.mod`."""

        records: list[DependencyRecord] = []
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            if stripped.startswith("require "):
                stripped = stripped.removeprefix("require ").strip("() ")
            parts = stripped.split()
            if len(parts) == 2 and "." in parts[0]:
                records.append(
                    DependencyRecord(
                        package_name=parts[0],
                        version=parts[1],
                        ecosystem="go",
                        manifest_path=relative_path,
                    )
                )
        return records

    def _parse_dockerfile(self, manifest_path: Path, relative_path: str) -> list[DependencyRecord]:
        """Treat Docker base images as dependencies so they enter the same correlation pipeline."""

        records: list[DependencyRecord] = []
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped.upper().startswith("FROM "):
                continue
            image_ref = stripped.split(maxsplit=1)[1].split(" AS ", maxsplit=1)[0]
            if ":" in image_ref:
                package_name, version = image_ref.rsplit(":", maxsplit=1)
            else:
                package_name, version = image_ref, "latest"
            records.append(
                DependencyRecord(
                    package_name=package_name,
                    version=version,
                    ecosystem="docker",
                    manifest_path=relative_path,
                )
            )
        return records

    def _parse_homeassistant_manifest(
        self, manifest_path: Path, relative_path: str
    ) -> list[DependencyRecord]:
        """Parse Home Assistant integration manifests and their Python requirements."""

        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        records: list[DependencyRecord] = []
        for requirement in data.get("requirements", []):
            package_name, version = self._split_requirement_line(requirement)
            records.append(
                DependencyRecord(
                    package_name=package_name,
                    version=version,
                    ecosystem="pypi",
                    manifest_path=relative_path,
                    metadata={"source": "homeassistant_manifest", "domain": data.get("domain")},
                )
            )
        return records

    def _split_requirement_line(self, line: str) -> tuple[str, str]:
        """Split common package specifier syntaxes into package and version parts."""

        cleaned = re.split(r"\s*;\s*", line, maxsplit=1)[0]
        for delimiter in ("==", ">=", "<=", "~=", "!=", ">", "<", "="):
            if delimiter in cleaned:
                package_name, version = cleaned.split(delimiter, maxsplit=1)
                return package_name.strip(), f"{delimiter}{version.strip()}"
        return cleaned.strip(), "unspecified"
