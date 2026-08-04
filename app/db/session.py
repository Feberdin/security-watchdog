"""
Purpose: Create SQLAlchemy engines and provide request-safe database sessions.
Input/Output: Reads configured database URL and yields `Session` objects.
Important invariants: Session creation stays lazy so tests can override the database URL; SQLite
needs `check_same_thread=False` while PostgreSQL should use sane connection pooling defaults.
Debugging: If startup hangs or sessions leak, inspect `database_url` and check that `session.close()`
is reached in the FastAPI dependency and worker jobs.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.base import Base

settings = get_settings()

engine = create_engine(
    settings.database_url,
    future=True,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)


def initialize_database() -> None:
    """Create missing tables and apply small idempotent runtime schema extensions."""

    import app.models.entities  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_runtime_schema()


def _ensure_runtime_schema() -> None:
    """
    Add narrow post-`create_all` columns that existing installations need after upgrades.

    Why this exists:
    The project intentionally avoids a full migration stack for now. SQLAlchemy `create_all()` only
    creates missing tables; it will not alter existing tables. These DDL statements are therefore
    small, guarded by column existence checks, and safe to run at every API or worker startup.
    """

    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    dialect_name = engine.dialect.name

    if "repositories" in table_names:
        repository_columns = {column["name"] for column in inspector.get_columns("repositories")}
        if "scan_enabled" not in repository_columns:
            _execute_schema_ddl(
                postgresql="ALTER TABLE repositories ADD COLUMN scan_enabled BOOLEAN NOT NULL DEFAULT TRUE",
                sqlite="ALTER TABLE repositories ADD COLUMN scan_enabled BOOLEAN NOT NULL DEFAULT 1",
                generic="ALTER TABLE repositories ADD COLUMN scan_enabled BOOLEAN NOT NULL DEFAULT TRUE",
                dialect_name=dialect_name,
            )

    if "manual_scan_jobs" in table_names:
        job_columns = {column["name"] for column in inspector.get_columns("manual_scan_jobs")}
        if "scan_sources" not in job_columns:
            _execute_schema_ddl(
                postgresql=(
                    "ALTER TABLE manual_scan_jobs ADD COLUMN scan_sources JSON NOT NULL "
                    'DEFAULT \'["github","unraid","homeassistant"]\'::json'
                ),
                sqlite=(
                    "ALTER TABLE manual_scan_jobs ADD COLUMN scan_sources JSON NOT NULL "
                    'DEFAULT \'["github","unraid","homeassistant"]\''
                ),
                generic=(
                    "ALTER TABLE manual_scan_jobs ADD COLUMN scan_sources JSON NOT NULL "
                    'DEFAULT \'["github","unraid","homeassistant"]\''
                ),
                dialect_name=dialect_name,
            )
        if "cancel_requested" not in job_columns:
            _execute_schema_ddl(
                postgresql="ALTER TABLE manual_scan_jobs ADD COLUMN cancel_requested BOOLEAN NOT NULL DEFAULT FALSE",
                sqlite="ALTER TABLE manual_scan_jobs ADD COLUMN cancel_requested BOOLEAN NOT NULL DEFAULT 0",
                generic="ALTER TABLE manual_scan_jobs ADD COLUMN cancel_requested BOOLEAN NOT NULL DEFAULT FALSE",
                dialect_name=dialect_name,
            )
        if "pause_requested" not in job_columns:
            _execute_schema_ddl(
                postgresql="ALTER TABLE manual_scan_jobs ADD COLUMN pause_requested BOOLEAN NOT NULL DEFAULT FALSE",
                sqlite="ALTER TABLE manual_scan_jobs ADD COLUMN pause_requested BOOLEAN NOT NULL DEFAULT 0",
                generic="ALTER TABLE manual_scan_jobs ADD COLUMN pause_requested BOOLEAN NOT NULL DEFAULT FALSE",
                dialect_name=dialect_name,
            )
        if "priority" not in job_columns:
            _execute_schema_ddl(
                postgresql="ALTER TABLE manual_scan_jobs ADD COLUMN priority INTEGER NOT NULL DEFAULT 0",
                sqlite="ALTER TABLE manual_scan_jobs ADD COLUMN priority INTEGER NOT NULL DEFAULT 0",
                generic="ALTER TABLE manual_scan_jobs ADD COLUMN priority INTEGER NOT NULL DEFAULT 0",
                dialect_name=dialect_name,
            )
        if "purpose" not in job_columns:
            _execute_schema_ddl(
                postgresql="ALTER TABLE manual_scan_jobs ADD COLUMN purpose VARCHAR(50) NOT NULL DEFAULT 'manual'",
                sqlite="ALTER TABLE manual_scan_jobs ADD COLUMN purpose VARCHAR(50) NOT NULL DEFAULT 'manual'",
                generic="ALTER TABLE manual_scan_jobs ADD COLUMN purpose VARCHAR(50) NOT NULL DEFAULT 'manual'",
                dialect_name=dialect_name,
            )
        if "target_commit_sha" not in job_columns:
            _execute_schema_ddl(
                postgresql="ALTER TABLE manual_scan_jobs ADD COLUMN target_commit_sha VARCHAR(40)",
                sqlite="ALTER TABLE manual_scan_jobs ADD COLUMN target_commit_sha VARCHAR(40)",
                generic="ALTER TABLE manual_scan_jobs ADD COLUMN target_commit_sha VARCHAR(40)",
                dialect_name=dialect_name,
            )
        if "refresh_image_cache" not in job_columns:
            _execute_schema_ddl(
                postgresql="ALTER TABLE manual_scan_jobs ADD COLUMN refresh_image_cache BOOLEAN NOT NULL DEFAULT FALSE",
                sqlite="ALTER TABLE manual_scan_jobs ADD COLUMN refresh_image_cache BOOLEAN NOT NULL DEFAULT 0",
                generic="ALTER TABLE manual_scan_jobs ADD COLUMN refresh_image_cache BOOLEAN NOT NULL DEFAULT FALSE",
                dialect_name=dialect_name,
            )


def _execute_schema_ddl(
    *,
    postgresql: str,
    sqlite: str,
    generic: str,
    dialect_name: str,
) -> None:
    """Run one dialect-specific DDL statement in its own committed transaction."""

    statement = {"postgresql": postgresql, "sqlite": sqlite}.get(dialect_name, generic)
    with engine.begin() as connection:
        connection.execute(text(statement))


def get_db_session() -> Generator[Session, None, None]:
    """Yield a session for FastAPI dependencies and close it reliably."""

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
