"""
Purpose: Central helpers for masking secrets and classifying high-risk strings before logging.
Input/Output: Accepts arbitrary nested Python values and returns log-safe copies.
Important invariants: This module must never modify original objects in place; masking favors false
positives over leaking a token into logs.
Debugging: If a secret appears in logs, add its key pattern here and rerun tests in debug mode.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

SENSITIVE_KEYS = {
    "authorization",
    "api_key",
    "apikey",
    "github_token",
    "openai_api_key",
    "password",
    "secret",
    "slack_webhook_url",
    "smtp_password",
    "token",
}


def mask_string(value: str) -> str:
    """Return a shortened placeholder for secret-like values."""

    if len(value) <= 6:
        return "***"
    return f"{value[:3]}***{value[-3:]}"


def mask_sensitive_values(value: Any) -> Any:
    """Recursively mask likely secrets while preserving structure for debugging."""

    if isinstance(value, Mapping):
        return {
            key: (
                mask_string(str(item_value))
                if str(key).lower() in SENSITIVE_KEYS and item_value
                else mask_sensitive_values(item_value)
            )
            for key, item_value in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [mask_sensitive_values(item) for item in value]
    return value
