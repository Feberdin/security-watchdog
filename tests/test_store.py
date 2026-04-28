"""
Purpose: Verify repository persistence helpers stay idempotent for repeated threat-feed imports.
Input/Output: Uses an in-memory SQLite database and stores duplicate threat articles with controlled
URLs and content changes.
Important invariants: Re-importing the same source URL must update the existing row instead of
crashing on a database unique constraint; identical content should still deduplicate cleanly.
Debugging: If this test fails, inspect `store_threat_article()` together with the `ThreatArticle`
unique constraints before touching the scheduler or feed collectors.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

import app.models.entities  # noqa: F401
from app.db.base import Base
from app.models.entities import ThreatArticle
from app.models.schemas import ThreatArticleRecord
from app.repositories.store import store_threat_article


def build_test_session() -> Session:
    """Create a throwaway in-memory database session for repository store tests."""

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return Session(engine)


def test_store_threat_article_updates_existing_row_when_source_url_repeats() -> None:
    """The feed importer should upsert by source URL instead of violating the unique constraint."""

    session = build_test_session()
    original = ThreatArticleRecord(
        source_type="rss",
        title="Original title",
        source_url="https://example.com/article",
        published_at=datetime(2026, 4, 28, 18, 0, tzinfo=UTC),
        raw_content="original body",
        normalized_text="original body",
        tags=["rss"],
    )
    updated = ThreatArticleRecord(
        source_type="rss",
        title="Updated title",
        source_url="https://example.com/article",
        published_at=datetime(2026, 4, 28, 18, 5, tzinfo=UTC),
        raw_content="updated body",
        normalized_text="updated body",
        tags=["rss", "refresh"],
    )

    store_threat_article(session, original)
    row = store_threat_article(session, updated)
    session.commit()

    stored_rows = session.scalars(select(ThreatArticle)).all()
    assert len(stored_rows) == 1
    assert row.id == stored_rows[0].id
    assert stored_rows[0].title == "Updated title"
    assert stored_rows[0].normalized_text == "updated body"
    assert stored_rows[0].tags == ["rss", "refresh"]


def test_store_threat_article_reuses_existing_row_for_identical_article() -> None:
    """Re-importing the same normalized article should return the existing database row."""

    session = build_test_session()
    first = ThreatArticleRecord(
        source_type="rss",
        title="Same story",
        source_url="https://example.com/article-a",
        published_at=datetime(2026, 4, 28, 18, 0, tzinfo=UTC),
        raw_content="shared body",
        normalized_text="shared body",
        tags=["rss"],
    )
    repeated = ThreatArticleRecord(
        source_type="rss",
        title="Same story",
        source_url="https://example.com/article-a",
        published_at=datetime(2026, 4, 28, 18, 0, tzinfo=UTC),
        raw_content="shared body",
        normalized_text="shared body",
        tags=["rss"],
    )

    first_row = store_threat_article(session, first)
    repeated_row = store_threat_article(session, repeated)
    session.commit()

    stored_rows = session.scalars(select(ThreatArticle)).all()
    assert len(stored_rows) == 1
    assert repeated_row.id == first_row.id
