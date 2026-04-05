"""
Purpose: Shared filesystem, hashing, and subprocess helpers used across scanners and services.
Input/Output: Accepts paths, strings, and command arrays; returns deterministic helper values.
Important invariants: External commands must fail fast with captured stderr so operators can act
quickly; hashing functions should stay stable because they are used for deduplication.
Debugging: When a scanner fails on an external tool, inspect the raised `RuntimeError` message first
because it includes command, exit code, and stderr.
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from pathlib import Path
from typing import Any

from slugify import slugify

LOGGER = logging.getLogger(__name__)


def stable_json_dumps(payload: Any) -> str:
    """Serialize JSON with stable key ordering for hashing and snapshots."""

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def sha256_text(value: str) -> str:
    """Generate a stable SHA-256 digest for deduplication keys."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash a file without loading it completely into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_slug(value: str) -> str:
    """Create a filesystem-safe slug while preserving enough meaning for operators."""

    return slugify(value, lowercase=True, separator="-", max_length=80)


def run_command(command: list[str], *, cwd: Path | None = None, timeout: int = 300) -> str:
    """Run a command and raise a detailed error if it fails."""

    LOGGER.debug(
        "Running external command",
        extra={"command": [_mask_command_part(part) for part in command], "cwd": str(cwd or ".")},
    )
    result = subprocess.run(  # noqa: S603
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "External command failed. "
            f"command={[_mask_command_part(part) for part in command]!r} "
            f"exit_code={result.returncode} stderr={result.stderr.strip()!r}"
        )
    return result.stdout.strip()


def _mask_command_part(part: str) -> str:
    """Hide embedded credentials from logged command arguments."""

    if "x-access-token:" in part and "@" in part:
        prefix, suffix = part.split("x-access-token:", maxsplit=1)
        _, host = suffix.split("@", maxsplit=1)
        return f"{prefix}x-access-token:***@{host}"
    return part
