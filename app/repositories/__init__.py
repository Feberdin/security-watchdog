"""
Purpose: Package marker for persistence helpers that keep business logic out of route handlers.
Input/Output: No side effects; enables explicit imports from repository helper modules.
Important invariants: Repository helpers should stay thin wrappers around SQLAlchemy sessions.
Debugging: If data appears inconsistent, inspect these helpers for accidental duplicate inserts.
"""
