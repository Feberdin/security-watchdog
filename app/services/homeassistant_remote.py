"""
Purpose: Connect to a remote Home Assistant instance over the official REST API and normalize the
returned integration inventory for downstream scanners.
Input/Output: Accepts runtime settings plus a long-lived access token and returns a typed
`HomeAssistantRemoteInventory` object with instance metadata and integration domains.
Important invariants: Remote access must be explicitly enabled, authentication must use a bearer
token, and failures should explain whether the problem is URL, TLS, auth, or network reachability.
Debugging: If the remote scan returns nothing, start by testing `/api/config` and `/api/components`
with the same base URL and token because those are the exact endpoints this client uses.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.config import Settings, get_settings
from app.core.utils import safe_slug

LOGGER = logging.getLogger(__name__)

HOMEASSISTANT_INTERNAL_DOMAINS = {
    "ai_task",
    "alarm_control_panel",
    "analytics",
    "api",
    "application_credentials",
    "assist_pipeline",
    "assist_satellite",
    "auth",
    "automation",
    "backup",
    "binary_sensor",
    "blueprint",
    "bluetooth",
    "bluetooth_adapters",
    "brands",
    "button",
    "calendar",
    "camera",
    "climate",
    "cloud",
    "config",
    "conversation",
    "counter",
    "cover",
    "default_config",
    "device_automation",
    "device_tracker",
    "diagnostics",
    "energy",
    "event",
    "fan",
    "file",
    "file_upload",
    "folder",
    "fontawesome",
    "frontend",
    "group",
    "hardware",
    "hassio",
    "history",
    "homeassistant",
    "homeassistant_alerts",
    "homeassistant_green",
    "homeassistant_hardware",
    "http",
    "humidifier",
    "image",
    "image_upload",
    "input_boolean",
    "input_button",
    "input_datetime",
    "input_number",
    "input_select",
    "input_text",
    "integration",
    "intent",
    "labs",
    "light",
    "lock",
    "logbook",
    "logger",
    "lovelace",
    "matter",
    "media_player",
    "media_source",
    "mobile_app",
    "my",
    "network",
    "notify",
    "number",
    "onboarding",
    "person",
    "persistent_notification",
    "recorder",
    "remote",
    "repairs",
    "scene",
    "schedule",
    "script",
    "search",
    "select",
    "sensor",
    "shell_command",
    "siren",
    "ssdp",
    "stream",
    "stt",
    "sun",
    "switch",
    "system_health",
    "system_log",
    "tag",
    "template",
    "thread",
    "timer",
    "todo",
    "trace",
    "tts",
    "update",
    "usage_prediction",
    "usb",
    "utility_meter",
    "vacuum",
    "valve",
    "wake_word",
    "water_heater",
    "weather",
    "web_rtc",
    "webhook",
    "websocket_api",
    "wyoming",
    "zeroconf",
    "zone",
}


class HomeAssistantRemoteError(RuntimeError):
    """Raised when the remote Home Assistant API cannot be queried safely."""


@dataclass(slots=True)
class HomeAssistantRemoteIntegration:
    """Normalized view of one Home Assistant integration domain discovered via the API."""

    domain: str
    component_names: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HomeAssistantRemoteInventory:
    """Remote Home Assistant instance metadata plus normalized integration inventory."""

    base_url: str
    instance_slug: str
    location_name: str
    homeassistant_version: str
    time_zone: str
    integrations: list[HomeAssistantRemoteIntegration]
    raw_config: dict[str, Any]


class HomeAssistantRemoteClient:
    """Fetch remote Home Assistant inventory through the documented REST API."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def fetch_inventory(self) -> HomeAssistantRemoteInventory:
        """
        Fetch the instance config and loaded components from a remote Home Assistant.

        Why this exists:
        Some operators run Home Assistant on a different device, so mount-based scanning is not
        possible. The REST API still gives us an authenticated inventory of loaded integrations.
        """

        base_url = self._validated_base_url()
        token = self._validated_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        LOGGER.info(
            "Fetching remote Home Assistant inventory",
            extra={
                "base_url": base_url,
                "verify_tls": self.settings.homeassistant_remote_verify_tls,
            },
        )

        try:
            with httpx.Client(
                base_url=base_url,
                headers=headers,
                follow_redirects=True,
                timeout=self.settings.homeassistant_remote_timeout_seconds,
                verify=self.settings.homeassistant_remote_verify_tls,
            ) as client:
                config = self._request_json(client, "api/config")
                try:
                    components_payload = self._request_json(client, "api/components")
                except HomeAssistantRemoteError as error:
                    LOGGER.warning(
                        (
                            "Remote Home Assistant components endpoint failed, "
                            "falling back to /api/config"
                        ),
                        extra={"base_url": base_url, "error": str(error)},
                    )
                    components_payload = config.get("components", [])
        except httpx.ConnectError as error:
            raise HomeAssistantRemoteError(
                "Unable to reach the remote Home Assistant instance. "
                f"Check HOMEASSISTANT_REMOTE_BASE_URL={base_url!r}, network reachability, and "
                "reverse-proxy/firewall rules."
            ) from error
        except httpx.TimeoutException as error:
            raise HomeAssistantRemoteError(
                "Timed out while talking to the remote Home Assistant API. "
                "Increase HOMEASSISTANT_REMOTE_TIMEOUT_SECONDS or verify that the instance is "
                "responsive."
            ) from error

        if not isinstance(config, dict):
            raise HomeAssistantRemoteError(
                "Remote Home Assistant /api/config returned an unexpected payload type. "
                "Expected a JSON object."
            )
        if not isinstance(components_payload, list):
            raise HomeAssistantRemoteError(
                "Remote Home Assistant /api/components returned an unexpected payload type. "
                "Expected a JSON array."
            )

        parsed_url = urlparse(base_url)
        instance_slug = safe_slug(parsed_url.netloc or parsed_url.path or "homeassistant-remote")

        return HomeAssistantRemoteInventory(
            base_url=base_url,
            instance_slug=instance_slug or "homeassistant-remote",
            location_name=str(config.get("location_name", "")),
            homeassistant_version=str(config.get("version", "")),
            time_zone=str(config.get("time_zone", "")),
            integrations=self._normalize_integrations(components_payload),
            raw_config=config,
        )

    def _request_json(self, client: httpx.Client, endpoint: str) -> Any:
        """Call one Home Assistant REST endpoint and return its JSON body."""

        try:
            response = client.get(endpoint)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as error:
            raise HomeAssistantRemoteError(self._format_http_error(error)) from error
        except ValueError as error:
            raise HomeAssistantRemoteError(
                "Remote Home Assistant returned invalid JSON. "
                f"endpoint={endpoint!r}. Check if a reverse proxy is returning HTML instead."
            ) from error

    def _normalize_integrations(
        self, components: list[Any]
    ) -> list[HomeAssistantRemoteIntegration]:
        """
        Collapse Home Assistant component strings into unique integration domains.

        Example input:
        - `["tapo.switch", "tapo.sensor", "hacs"]`

        Example output:
        - domain=`tapo`, platforms=`["sensor", "switch"]`
        - domain=`hacs`, platforms=`[]`
        """

        grouped: dict[str, HomeAssistantRemoteIntegration] = {}
        for raw_component in components:
            component_name = str(raw_component).strip()
            if not component_name:
                continue
            domain, _, platform = component_name.partition(".")
            if domain in HOMEASSISTANT_INTERNAL_DOMAINS:
                continue
            integration = grouped.setdefault(domain, HomeAssistantRemoteIntegration(domain=domain))
            if component_name not in integration.component_names:
                integration.component_names.append(component_name)
            if platform and platform not in integration.platforms:
                integration.platforms.append(platform)

        for integration in grouped.values():
            integration.component_names.sort()
            integration.platforms.sort()
        return [grouped[domain] for domain in sorted(grouped)]

    def _validated_base_url(self) -> str:
        """Validate that the configured base URL is present and shaped like HTTP(S)."""

        base_url = self.settings.homeassistant_remote_base_url
        if not base_url:
            raise HomeAssistantRemoteError(
                "HOMEASSISTANT_REMOTE_ENABLED is true, but HOMEASSISTANT_REMOTE_BASE_URL is empty. "
                "Use a full URL like https://homeassistant.local:8123."
            )

        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise HomeAssistantRemoteError(
                "HOMEASSISTANT_REMOTE_BASE_URL must be a full http(s) URL, for example "
                "https://homeassistant.local:8123."
            )
        return f"{base_url}/"

    def _validated_token(self) -> str:
        """Ensure the operator configured a Home Assistant long-lived access token."""

        token = self.settings.homeassistant_remote_token.strip()
        if not token:
            raise HomeAssistantRemoteError(
                "HOMEASSISTANT_REMOTE_ENABLED is true, but HOMEASSISTANT_REMOTE_TOKEN is empty. "
                "Create a long-lived access token in your Home Assistant profile page."
            )
        return token

    def _format_http_error(self, error: httpx.HTTPStatusError) -> str:
        """Turn HTTP status codes into actionable operator guidance."""

        status_code = error.response.status_code
        if status_code == 401:
            return (
                "Remote Home Assistant rejected the token with HTTP 401. "
                "Create a fresh long-lived access token in the Home Assistant profile page and "
                "paste it into HOMEASSISTANT_REMOTE_TOKEN."
            )
        if status_code == 403:
            return (
                "Remote Home Assistant returned HTTP 403. "
                "Check reverse-proxy rules, trusted proxies, and whether the API is exposed to "
                "this container."
            )
        if status_code == 404:
            return (
                "Remote Home Assistant API endpoint not found (HTTP 404). "
                "Verify that the base URL points to the Home Assistant root, not to a sub-page."
            )
        if status_code >= 500:
            return (
                "Remote Home Assistant returned a server error. "
                f"status_code={status_code}. Check the Home Assistant logs on the remote host."
            )
        return (
            "Remote Home Assistant request failed. "
            f"status_code={status_code} endpoint={error.request.url!s}"
        )
