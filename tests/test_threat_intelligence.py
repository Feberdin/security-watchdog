"""
Purpose: Verify threat intelligence normalization stays resilient to inconsistent external APIs.
Input/Output: Injects synthetic GitHub issue search results and checks the normalized article output.
Important invariants: A single optional `null` text field from GitHub must not crash the scheduled
threat-feed collection job.
Debugging: If the deployed worker logs Pydantic validation errors for `ThreatArticleRecord`, start
with `ThreatIntelligenceService._fetch_github_issue_articles()`.
"""

from __future__ import annotations

from app.services.threat_intelligence import ThreatIntelligenceService


def test_github_issue_articles_treat_null_body_as_empty_text() -> None:
    """GitHub can return `body: null`; normalize it before creating the article model."""

    service = ThreatIntelligenceService()
    service.github_client.search_security_issues = lambda _keywords: iter(
        [
            {
                "title": "Dependency confusion report",
                "html_url": "https://github.com/example/project/issues/1",
                "created_at": "2026-07-29T20:30:00Z",
                "body": None,
            }
        ]
    )

    articles = service._fetch_github_issue_articles()

    assert len(articles) == 1
    assert articles[0].raw_content == ""
    assert articles[0].normalized_text == "Dependency confusion report"


def test_github_issue_articles_default_missing_title_and_url_to_strings() -> None:
    """Missing optional text fields should still produce a valid article record."""

    service = ThreatIntelligenceService()
    service.github_client.search_security_issues = lambda _keywords: iter(
        [
            {
                "title": None,
                "html_url": None,
                "created_at": None,
                "body": "malicious package noted in the ecosystem",
            }
        ]
    )

    articles = service._fetch_github_issue_articles()

    assert len(articles) == 1
    assert articles[0].title == "Untitled GitHub issue"
    assert articles[0].source_url == ""
    assert articles[0].normalized_text == "Untitled GitHub issue malicious package noted in the ecosystem"
