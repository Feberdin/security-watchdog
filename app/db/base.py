"""
Purpose: Define the declarative SQLAlchemy base used by all persistent entities.
Input/Output: Imported by model modules and initialization scripts.
Important invariants: Every database model must inherit from `Base`; metadata is the single source
of truth for `create_all()` in local and container environments.
Debugging: If a table is missing, confirm the model is imported before `initialize_database()`.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared SQLAlchemy base class."""
