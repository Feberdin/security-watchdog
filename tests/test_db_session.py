"""
Purpose: Verify idempotent runtime database extensions needed by production services.
Input/Output: Builds an isolated SQLite schema, applies startup extensions, and inspects its query
plan.
Important invariants: Repeated startup is safe and the deployment gate uses its partial index for
exact-commit HIGH/CRITICAL lookups.
Debugging: Inspect the reported SQLite query plan if this test stops naming the gate index.
"""

from __future__ import annotations

from sqlalchemy import create_engine, text

from app.db import session as db_session
from app.db.base import Base


def test_runtime_schema_creates_and_uses_deployment_gate_index(
    tmp_path,
    monkeypatch,
) -> None:
    """Large historical alert tables must not force a full scan during a deployment gate check."""

    engine = create_engine(f"sqlite:///{tmp_path / 'watchdog.db'}", future=True)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(db_session, "engine", engine)

    db_session._ensure_runtime_schema()
    db_session._ensure_runtime_schema()

    query_plan_sql = """
        EXPLAIN QUERY PLAN
        SELECT lower(severity), count(id)
        FROM alerts
        WHERE repository_id = :repository_id
          AND status IN ('open', 'acknowledged')
          AND lower(severity) IN ('critical', 'high')
          AND json_extract("metadata", '$."scanned_commit_sha"') = :commit_sha
        GROUP BY lower(severity)
    """
    with engine.connect() as connection:
        index_name = connection.scalar(
            text(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'index' AND name = 'ix_alerts_deployment_gate'"
            )
        )
        query_plan = connection.execute(
            text(query_plan_sql),
            {"repository_id": 1, "commit_sha": "a" * 40},
        ).all()

    assert index_name == "ix_alerts_deployment_gate"
    plan_text = " ".join(str(row) for row in query_plan)
    assert "ix_alerts_deployment_gate" in plan_text
