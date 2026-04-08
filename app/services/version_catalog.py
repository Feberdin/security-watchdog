"""
Purpose: Resolve current package versions from upstream registries for dashboard and API views.
Input/Output: Accepts a package name plus ecosystem and returns the latest known version together
with a small amount of provenance metadata.
Important invariants: Version lookup is best-effort and must never break dashboards if a registry is
slow or unavailable; results are cached in-memory to avoid hammering public registries on refresh.
Debugging: If latest versions are missing, inspect the `source` and `note` fields returned here and
check the outbound network access from the container to the relevant package registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import logging
from typing import Any
from urllib.parse import quote

import httpx

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class LatestVersionRecord:
    """Result of a best-effort latest-version lookup for one dependency."""

    latest_version: str | None
    source: str
    note: str = ""


class VersionCatalogService:
    """Best-effort resolver for package registries used by the dashboard."""

    def __init__(self, *, timeout_seconds: int = 5, cache_ttl_hours: int = 6) -> None:
        self.timeout_seconds = timeout_seconds
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self._cache: dict[tuple[str, str], tuple[datetime, LatestVersionRecord]] = {}

    def resolve_latest_version(self, ecosystem: str, package_name: str) -> LatestVersionRecord:
        """Return the latest known version for one package without raising lookup errors."""

        cache_key = (ecosystem, package_name)
        cached = self._cache.get(cache_key)
        now = datetime.now(UTC)
        if cached and cached[0] > now:
            return cached[1]

        try:
            record = self._resolve_uncached(ecosystem, package_name)
        except Exception as error:
            LOGGER.warning(
                "Latest version lookup failed",
                extra={
                    "ecosystem": ecosystem,
                    "package_name": package_name,
                    "error": str(error),
                },
            )
            record = LatestVersionRecord(
                latest_version=None,
                source="lookup_failed",
                note=str(error),
            )

        self._cache[cache_key] = (now + self.cache_ttl, record)
        return record

    def _resolve_uncached(self, ecosystem: str, package_name: str) -> LatestVersionRecord:
        """Dispatch one ecosystem to the matching public registry API."""

        handlers = {
            "pypi": self._resolve_pypi,
            "npm": self._resolve_npm,
            "maven": self._resolve_maven,
            "gradle": self._resolve_maven,
            "packagist": self._resolve_packagist,
            "crates.io": self._resolve_crates,
            "go": self._resolve_go,
        }
        handler = handlers.get(ecosystem)
        if handler is None:
            return LatestVersionRecord(
                latest_version=None,
                source="unsupported",
                note=f"Automatic lookup is not implemented for ecosystem={ecosystem!r}.",
            )
        return handler(package_name)

    def _resolve_pypi(self, package_name: str) -> LatestVersionRecord:
        payload = self._get_json(f"https://pypi.org/pypi/{quote(package_name, safe='')}/json")
        return LatestVersionRecord(
            latest_version=str(payload.get("info", {}).get("version", "")) or None,
            source="pypi",
        )

    def _resolve_npm(self, package_name: str) -> LatestVersionRecord:
        payload = self._get_json(f"https://registry.npmjs.org/{quote(package_name, safe='@/')}")
        return LatestVersionRecord(
            latest_version=str(payload.get("dist-tags", {}).get("latest", "")) or None,
            source="npm",
        )

    def _resolve_maven(self, package_name: str) -> LatestVersionRecord:
        group_name, artifact_name = self._split_maven_coordinate(package_name)
        if not group_name or not artifact_name:
            return LatestVersionRecord(
                latest_version=None,
                source="maven",
                note="Expected a Maven coordinate in the form group:artifact.",
            )

        payload = self._get_json(
            "https://search.maven.org/solrsearch/select",
            params={
                "q": f'g:"{group_name}" AND a:"{artifact_name}"',
                "rows": 1,
                "wt": "json",
            },
        )
        docs = payload.get("response", {}).get("docs", [])
        latest_version = str(docs[0].get("latestVersion", "")) if docs else ""
        return LatestVersionRecord(latest_version=latest_version or None, source="maven")

    def _resolve_packagist(self, package_name: str) -> LatestVersionRecord:
        payload = self._get_json(f"https://repo.packagist.org/p2/{package_name}.json")
        packages = payload.get("packages", {}).get(package_name, [])
        latest_version = str(packages[0].get("version", "")) if packages else ""
        return LatestVersionRecord(latest_version=latest_version or None, source="packagist")

    def _resolve_crates(self, package_name: str) -> LatestVersionRecord:
        payload = self._get_json(f"https://crates.io/api/v1/crates/{quote(package_name, safe='')}")
        return LatestVersionRecord(
            latest_version=str(payload.get("crate", {}).get("newest_version", "")) or None,
            source="crates.io",
        )

    def _resolve_go(self, package_name: str) -> LatestVersionRecord:
        payload = self._get_json(f"https://proxy.golang.org/{quote(package_name, safe='/')}/@latest")
        return LatestVersionRecord(
            latest_version=str(payload.get("Version", "")) or None,
            source="proxy.golang.org",
        )

    def _get_json(self, url: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Perform one registry HTTP request and validate that it returns a JSON object."""

        with httpx.Client(timeout=self.timeout_seconds, follow_redirects=True) as client:
            response = client.get(url, params=params)
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError(f"Registry returned an unexpected payload type for url={url!r}.")
        return payload

    def _split_maven_coordinate(self, package_name: str) -> tuple[str, str]:
        """Split `group:artifact` coordinates used by Maven and Gradle dependencies."""

        if ":" not in package_name:
            return "", ""
        group_name, artifact_name = package_name.split(":", maxsplit=1)
        return group_name.strip(), artifact_name.strip()
