"""
Purpose: Guard the immutable image references used by production Docker Compose.
Input/Output: Reads docker-compose.yml and asserts every production image has a digest.
Important invariants: Deployments must not resolve a different image behind a mutable tag.
Debugging: Verify the linux/amd64 registry digest, update tag and digest together, then rerun pytest.
"""

from pathlib import Path

import yaml


def test_all_production_images_are_digest_pinned() -> None:
    """Watchdog, PostgreSQL, and Redis must all resolve to reviewed immutable manifests."""

    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))

    for service_name in ("postgres", "redis", "watchdog", "worker"):
        image = compose["services"][service_name]["image"]
        assert "@sha256:" in image, f"{service_name} image is not digest-pinned"
