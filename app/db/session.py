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

from sqlalchemy import create_engine
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
    """Create missing tables for local and container deployments."""

    import app.models.entities  # noqa: F401

    Base.metadata.create_all(bind=engine)


def get_db_session() -> Generator[Session, None, None]:
    """Yield a session for FastAPI dependencies and close it reliably."""

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
