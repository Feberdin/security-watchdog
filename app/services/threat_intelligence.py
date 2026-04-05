"""
Purpose: Collect unstructured threat intelligence from RSS, Reddit, Hacker News, and GitHub issues.
Input/Output: Fetches remote content and returns/stores normalized threat article records.
Important invariants: Articles are deduplicated by content hash so repeated polling does not bloat
the database; normalization keeps only the fields that later AI extraction actually needs.
Debugging: If a feed dries up, test the exact source URL logged by this module before assuming an AI
or correlation issue further downstream.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import feedparser
import httpx
from dateutil import parser as date_parser
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.schemas import ThreatArticleRecord
from app.repositories.store import record_scan_result, store_threat_article
from app.services.github_client import GitHubClient

LOGGER = logging.getLogger(__name__)


class ThreatIntelligenceService:
    """Collect and persist threat intelligence articles from several sources."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.github_client = GitHubClient()

    def collect_and_store(self, session: Session) -> int:
        """Fetch all configured sources and persist new articles."""

        collected = 0
        for article in self._fetch_rss_articles():
            store_threat_article(session, article)
            collected += 1
        for article in self._fetch_reddit_articles():
            store_threat_article(session, article)
            collected += 1
        for article in self._fetch_github_issue_articles():
            store_threat_article(session, article)
            collected += 1
        record_scan_result(
            session,
            repository_id=None,
            scanner_name="threat_intelligence",
            status="success",
            findings_count=collected,
            details={"sources": ["rss", "reddit", "github_issues"]},
        )
        return collected

    def _fetch_rss_articles(self) -> list[ThreatArticleRecord]:
        """Normalize configured RSS and Atom feeds into article records."""

        articles: list[ThreatArticleRecord] = []
        for feed_url in self.settings.default_rss_feeds:
            parsed = feedparser.parse(feed_url)
            for entry in parsed.entries[:20]:
                articles.append(
                    ThreatArticleRecord(
                        source_type="rss",
                        title=entry.get("title", "Untitled feed item"),
                        source_url=entry.get("link", feed_url),
                        published_at=self._parse_datetime(entry.get("published") or entry.get("updated")),
                        raw_content=entry.get("summary", ""),
                        normalized_text=self._normalize_text(
                            f"{entry.get('title', '')}\n{entry.get('summary', '')}"
                        ),
                        tags=["rss", "threat_intel"],
                    )
                )
        return articles

    def _fetch_reddit_articles(self) -> list[ThreatArticleRecord]:
        """Read the `r/netsec` JSON feed and normalize posts."""

        try:
            with httpx.Client(timeout=30, headers={"User-Agent": "security-watchdog/0.1"}) as client:
                response = client.get(self.settings.reddit_netsec_url)
                response.raise_for_status()
                payload = response.json()
        except Exception as error:  # noqa: BLE001
            LOGGER.warning("Reddit threat feed failed", extra={"error": str(error)})
            return []

        articles: list[ThreatArticleRecord] = []
        for child in payload.get("data", {}).get("children", []):
            data = child.get("data", {})
            articles.append(
                ThreatArticleRecord(
                    source_type="reddit",
                    title=data.get("title", "Untitled Reddit post"),
                    source_url=f"https://reddit.com{data.get('permalink', '')}",
                    published_at=datetime.fromtimestamp(data.get("created_utc", 0), tz=UTC),
                    raw_content=data.get("selftext", ""),
                    normalized_text=self._normalize_text(
                        f"{data.get('title', '')}\n{data.get('selftext', '')}"
                    ),
                    tags=["reddit", "netsec"],
                )
            )
        return articles

    def _fetch_github_issue_articles(self) -> list[ThreatArticleRecord]:
        """Turn GitHub issue search results into article-like records."""

        articles: list[ThreatArticleRecord] = []
        try:
            results = list(self.github_client.search_security_issues(self.settings.github_issue_keywords))
        except Exception as error:  # noqa: BLE001
            LOGGER.warning("GitHub issue threat feed failed", extra={"error": str(error)})
            return []
        for item in results:
            articles.append(
                ThreatArticleRecord(
                    source_type="github_issue",
                    title=item.get("title", "Untitled GitHub issue"),
                    source_url=item.get("html_url", ""),
                    published_at=self._parse_datetime(item.get("created_at")),
                    raw_content=item.get("body", ""),
                    normalized_text=self._normalize_text(
                        f"{item.get('title', '')}\n{item.get('body', '')}"
                    ),
                    tags=["github_issue", "threat_intel"],
                )
            )
        return articles

    def _normalize_text(self, value: str) -> str:
        """Collapse whitespace so downstream AI prompts stay small and consistent."""

        return " ".join(value.split())

    def _parse_datetime(self, value: str | None) -> datetime | None:
        """Parse feed dates defensively because every provider formats them differently."""

        if not value:
            return None
        try:
            parsed = date_parser.parse(value)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except (ValueError, TypeError):
            return None
