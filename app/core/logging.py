"""
Purpose: Provide structured JSON logging that is readable by humans and log aggregators.
Input/Output: Accepts standard Python log records and emits JSON lines to stdout.
Important invariants: Secret-like values should be masked before they leave the process; every
service should call `configure_logging()` exactly once during startup.
Debugging: Raise `LOG_LEVEL=DEBUG` and inspect the `event`, `logger`, and `context` fields to
reconstruct failing scanner flows or external API requests.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from app.core.security import mask_sensitive_values


class JsonFormatter(logging.Formatter):
    """Serialize records as predictable JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        extra_context = {
            key: value
            for key, value in record.__dict__.items()
            if key
            not in {
                "args",
                "asctime",
                "created",
                "exc_info",
                "exc_text",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "message",
                "msg",
                "name",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "thread",
                "threadName",
            }
        }
        if extra_context:
            payload["context"] = mask_sensitive_values(extra_context)
        return json.dumps(mask_sensitive_values(payload), default=str)


def configure_logging(level: str) -> None:
    """Install a single stdout handler with the requested log level."""

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(level.upper())

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root_logger.addHandler(handler)
