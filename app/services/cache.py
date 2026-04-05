"""
Purpose: Provide a tiny Redis-backed state store for job heartbeats and alert throttling.
Input/Output: Accepts simple keys and values; silently degrades if Redis is unavailable.
Important invariants: The application must continue working without Redis because PostgreSQL is the
source of truth; Redis only improves operator experience and deduplication latency.
Debugging: If duplicate notifications appear, inspect Redis availability and TTL handling here.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from redis import Redis
from redis.exceptions import RedisError

from app.core.config import get_settings

LOGGER = logging.getLogger(__name__)


class RedisStateStore:
    """Small helper around Redis with graceful failure behavior."""

    def __init__(self) -> None:
        settings = get_settings()
        self._client = Redis.from_url(settings.redis_url, decode_responses=True)

    def set_job_heartbeat(self, job_name: str) -> None:
        """Record the last successful job execution timestamp."""

        try:
            self._client.set(f"jobs:{job_name}:heartbeat", datetime.now(UTC).isoformat(), ex=86400)
        except RedisError as error:
            LOGGER.warning("Redis heartbeat write failed", extra={"error": str(error)})

    def seen_recently(self, fingerprint: str, ttl_seconds: int = 3600) -> bool:
        """Return True if a value already exists, otherwise set it for the given TTL."""

        try:
            key = f"alerts:{fingerprint}"
            if self._client.exists(key):
                return True
            self._client.set(key, "1", ex=ttl_seconds)
            return False
        except RedisError as error:
            LOGGER.warning("Redis alert dedupe lookup failed", extra={"error": str(error)})
            return False
