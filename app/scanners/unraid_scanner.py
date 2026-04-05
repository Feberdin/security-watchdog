"""
Purpose: Inventory running Docker containers and images on an Unraid host through the Docker API.
Input/Output: Reads Docker metadata and returns synthetic repository-like assets for correlation.
Important invariants: Unraid access should work via local socket or remote Docker host; container
metadata is stored so operators can trace findings back to the exact runtime object.
Debugging: If no containers appear, verify the mounted Docker socket or `UNRAID_DOCKER_HOST` value.
"""

from __future__ import annotations

import logging
from typing import Any

import docker
from docker.errors import DockerException
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.repositories.store import upsert_repository

LOGGER = logging.getLogger(__name__)


class UnraidScanner:
    """Discover Unraid Docker workloads and mirror them into the database."""

    def __init__(self) -> None:
        settings = get_settings()
        self.settings = settings
        self._client: docker.DockerClient | None = None

    def sync_assets(self, session: Session) -> list[dict[str, Any]]:
        """Return all running containers as synthetic assets ready for image scanning."""

        assets: list[dict[str, Any]] = []
        if not self.settings.unraid_docker_enabled:
            return assets
        try:
            client = self._client or docker.DockerClient(
                base_url=self.settings.unraid_docker_host,
                tls=self.settings.unraid_verify_tls or False,
            )
            self._client = client
            containers = client.containers.list(all=True)
        except DockerException as error:
            LOGGER.warning("Unraid Docker inventory failed", extra={"error": str(error)})
            return assets

        for container in containers:
            image_tags = container.image.tags or [container.image.short_id]
            primary_image = image_tags[0]
            full_name = f"unraid/{container.name}"
            repository = upsert_repository(
                session,
                source_type="unraid_docker",
                owner="unraid",
                name=container.name,
                full_name=full_name,
                clone_url=None,
                default_branch="",
                local_path="",
                metadata={
                    "container_id": container.id,
                    "status": container.status,
                    "image": primary_image,
                    "image_tags": image_tags,
                    "labels": container.labels,
                    "ports": container.attrs.get("NetworkSettings", {}).get("Ports", {}),
                },
            )
            assets.append(
                {
                    "repository": repository,
                    "image_ref": primary_image,
                    "container_name": container.name,
                }
            )
        return assets
