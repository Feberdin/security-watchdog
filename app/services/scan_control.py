"""
Purpose: Shared control-flow primitives for long-running scan jobs.
Input/Output: Provides a small exception type that callers raise when a durable cancellation flag
has been set for the active scan.
Important invariants: Operator cancellation is not a scanner failure; callers should persist it as
`canceled` and leave already committed scan results intact for later resume or review.
Debugging: If a canceled scan appears as failed, inspect the exception handling around
`ScanCanceledError` in the worker-facing manual scan job service.
"""

from __future__ import annotations


class ScanCanceledError(Exception):
    """Raised when an operator-requested scan cancellation is observed by the worker."""
