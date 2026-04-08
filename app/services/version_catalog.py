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
    checked_at: datetime
    released_at: datetime | None = None
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
                checked_at=now,
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
                checked_at=datetime.now(UTC),
                note=f"Automatic lookup is not implemented for ecosystem={ecosystem!r}.",
            )
        return handler(package_name)

    def _resolve_pypi(self, package_name: str) -> LatestVersionRecord:
        payload = self._get_json(f"https://pypi.org/pypi/{quote(package_name, safe='')}/json")
        latest_version = str(payload.get("info", {}).get("version", "")) or None
        return LatestVersionRecord(
            latest_version=latest_version,
            source="pypi",
            checked_at=datetime.now(UTC),
            released_at=self._latest_pypi_release_time(payload, latest_version),
        )

    def _resolve_npm(self, package_name: str) -> LatestVersionRecord:
        payload = self._get_json(f"https://registry.npmjs.org/{quote(package_name, safe='@/')}")
        latest_version = str(payload.get("dist-tags", {}).get("latest", "")) or None
        return LatestVersionRecord(
            latest_version=latest_version,
            source="npm",
            checked_at=datetime.now(UTC),
            released_at=self._parse_datetime(payload.get("time", {}).get(latest_version or "")),
        )

    def _resolve_maven(self, package_name: str) -> LatestVersionRecord:
        group_name, artifact_name = self._split_maven_coordinate(package_name)
        if not group_name or not artifact_name:
            return LatestVersionRecord(
                latest_version=None,
                source="maven",
                checked_at=datetime.now(UTC),
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
        timestamp_value = docs[0].get("timestamp") if docs else None
        return LatestVersionRecord(
            latest_version=latest_version or None,
            source="maven",
            checked_at=datetime.now(UTC),
            released_at=self._parse_epoch_milliseconds(timestamp_value),
        )

    def _resolve_packagist(self, package_name: str) -> LatestVersionRecord:
        payload = self._get_json(f"https://repo.packagist.org/p2/{package_name}.json")
        packages = payload.get("packages", {}).get(package_name, [])
        latest_package = packages[0] if packages else {}
        latest_version = str(latest_package.get("version", "")) if latest_package else ""
        return LatestVersionRecord(
            latest_version=latest_version or None,
            source="packagist",
            checked_at=datetime.now(UTC),
            released_at=self._parse_datetime(latest_package.get("time")),
        )

    def _resolve_crates(self, package_name: str) -> LatestVersionRecord:
        payload = self._get_json(f"https://crates.io/api/v1/crates/{quote(package_name, safe='')}")
        latest_version = str(payload.get("crate", {}).get("newest_version", "")) or None
        return LatestVersionRecord(
            latest_version=latest_version,
            source="crates.io",
            checked_at=datetime.now(UTC),
            released_at=self._latest_crate_release_time(payload, latest_version),
        )

    def _resolve_go(self, package_name: str) -> LatestVersionRecord:
        payload = self._get_json(f"https://proxy.golang.org/{quote(package_name, safe='/')}/@latest")
        return LatestVersionRecord(
            latest_version=str(payload.get("Version", "")) or None,
            source="proxy.golang.org",
            checked_at=datetime.now(UTC),
            released_at=self._parse_datetime(payload.get("Time")),
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

    def _latest_pypi_release_time(
        self,
        payload: dict[str, Any],
        latest_version: str | None,
    ) -> datetime | None:
        """Return the most recent upload time for the resolved PyPI version."""

        if not latest_version:
            return None
        release_files = payload.get("releases", {}).get(latest_version, [])
        timestamps = [
            self._parse_datetime(item.get("upload_time_iso_8601") or item.get("upload_time"))
            for item in release_files
        ]
        timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
        return max(timestamps, default=None)

    def _latest_crate_release_time(
        self,
        payload: dict[str, Any],
        latest_version: str | None,
    ) -> datetime | None:
        """Return the publish time for the newest stable crate version if available."""

        if not latest_version:
            return None
        versions = payload.get("versions", [])
        for version in versions:
            if str(version.get("num", "")) == latest_version:
                return self._parse_datetime(version.get("created_at") or version.get("updated_at"))
        return self._parse_datetime(payload.get("crate", {}).get("updated_at"))

    def _parse_datetime(self, value: Any) -> datetime | None:
        """Parse common registry date formats into timezone-aware UTC datetimes."""

        if not value:
            return None
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)

    def _parse_epoch_milliseconds(self, value: Any) -> datetime | None:
        """Parse Maven Central millisecond timestamps into aware UTC datetimes."""

        if value in (None, ""):
            return None
        try:
            milliseconds = int(value)
        except (TypeError, ValueError):
            return None
        return datetime.fromtimestamp(milliseconds / 1000, tz=UTC)
