"""
Purpose: Guard the documented container runtime exception used by the Unraid deployment image.
Input/Output: Reads repository policy files and the entrypoint script; returns pytest assertions.
Important invariants: The image may start as root only for bootstrap tasks, and the application
command must then run as the unprivileged watchdog user through gosu.
Debugging: If this test fails, inspect `.trivyignore`, `Dockerfile`, and `docker/entrypoint.sh`
together before changing the deployment gate policy.
"""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _active_trivyignore_entries() -> list[str]:
    """
    Return non-comment Trivy ignore IDs exactly as Trivy sees them.

    Why this exists:
    The deployment gate trusts scanner output. A broad ignore file would hide real findings, so the
    test keeps the repository-level exception list small and reviewable.
    """

    ignore_file = REPOSITORY_ROOT / ".trivyignore"
    return [
        line.strip()
        for line in ignore_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_trivyignore_only_documents_root_bootstrap_exception() -> None:
    """The repository should suppress only the Dockerfile root-user bootstrap finding."""

    assert _active_trivyignore_entries() == ["DS-0002", "AVD-DS-0002"]


def test_entrypoint_drops_privileges_after_unraid_bootstrap() -> None:
    """The root-user exception is valid only while the entrypoint drops to the service user."""

    entrypoint = (REPOSITORY_ROOT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")

    assert "PUID=\"${PUID:-99}\"" in entrypoint
    assert "PGID=\"${PGID:-100}\"" in entrypoint
    assert "groupmod -o -g" in entrypoint
    assert "usermod -o -u" in entrypoint
    assert "chown -R \"${PUID}:${PGID}\" /app/data" in entrypoint
    assert "usermod -aG \"${EXISTING_DOCKER_GROUP}\" \"${WATCHDOG_USER}\"" in entrypoint
    assert 'exec gosu "${WATCHDOG_USER}" "$@"' in entrypoint
