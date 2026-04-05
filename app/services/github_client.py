"""
Purpose: Wrap GitHub REST API calls used for repository inventory, advisories, issues, and alerts.
Input/Output: Accepts typed method arguments and returns normalized dictionaries or lists.
Important invariants: The token must never be logged; paginated list methods should stop cleanly
when GitHub returns fewer than one page to avoid endless loops.
Debugging: Enable DEBUG logs to see request targets and pagination behavior if repos are missing.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

import httpx

from app.core.config import get_settings

LOGGER = logging.getLogger(__name__)


class GitHubClient:
    """Minimal GitHub REST client used by the scanners and alert dispatcher."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.settings.github_token:
            self._headers["Authorization"] = f"Bearer {self.settings.github_token}"

    def _request(self, method: str, path_or_url: str, **kwargs: Any) -> Any:
        """Perform one HTTP request and raise a detailed error on failure."""

        url = (
            path_or_url
            if path_or_url.startswith("http")
            else f"{self.settings.github_api_url.rstrip('/')}/{path_or_url.lstrip('/')}"
        )
        LOGGER.debug("Calling GitHub API", extra={"method": method, "url": url})
        with httpx.Client(timeout=self.settings.github_request_timeout_seconds) as client:
            response = client.request(method, url, headers=self._headers, **kwargs)
            response.raise_for_status()
            if response.headers.get("content-type", "").startswith("application/json"):
                return response.json()
            return response.text

    def list_repositories(self) -> list[dict[str, Any]]:
        """Return all repositories visible to the configured user token."""

        repositories: list[dict[str, Any]] = []
        page = 1
        while True:
            response = self._request(
                "GET",
                "/user/repos",
                params={
                    "per_page": 100,
                    "page": page,
                    "visibility": "all",
                    "affiliation": "owner,collaborator,organization_member",
                    "sort": "updated",
                },
            )
            if not response:
                break
            for repository in response:
                if repository.get("private") and not self.settings.github_include_private:
                    continue
                repositories.append(repository)
            if len(response) < 100:
                break
            page += 1
        return repositories

    def search_security_issues(self, keywords: list[str]) -> Iterator[dict[str, Any]]:
        """Yield GitHub issues related to supply-chain security keywords."""

        for keyword in keywords:
            query = f'{keyword} in:title,body is:issue archived:false'
            results = self._request("GET", "/search/issues", params={"q": query, "per_page": 20})
            for item in results.get("items", []):
                yield item

    def list_advisories(self, ecosystem: str, package_name: str) -> list[dict[str, Any]]:
        """Fetch GitHub Security Advisories for one package/ecosystem pair."""

        response = self._request(
            "GET",
            self.settings.github_advisory_url,
            params={"ecosystem": ecosystem, "affects": package_name, "per_page": 20},
        )
        return response if isinstance(response, list) else []

    def create_issue(self, repository: str, title: str, body: str) -> dict[str, Any]:
        """Create a GitHub issue and return the API response body."""

        return self._request(
            "POST",
            f"/repos/{repository}/issues",
            json={"title": title, "body": body},
        )
