"""
Purpose: Shared control-flow primitives for long-running scan jobs.
Input/Output: Provides small exception types that callers raise when a durable cancellation or pause
flag has been set for the active scan.
Important invariants: Operator cancellation and pause are not scanner failures; callers should
persist them as explicit lifecycle states and leave already committed scan results intact.
Debugging: If a canceled or paused scan appears as failed, inspect the exception handling around
these types in the worker-facing manual scan job service.
"""

from __future__ import annotations


class ScanCanceledError(Exception):
    """Raised when an operator-requested scan cancellation is observed by the worker."""


class ScanPausedError(Exception):
    """Raised when an operator-requested pause is observed by the worker."""
