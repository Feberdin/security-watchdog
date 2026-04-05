"""
Purpose: Central runtime configuration for the API, worker, scanners, and integrations.
Input/Output: Reads environment variables and returns a typed `Settings` object.
Important invariants: Secrets stay in environment variables, never in source control; storage paths
must exist before scanners run; default values should be safe enough for local development.
Debugging: Set `LOG_LEVEL=debug` and inspect the startup log that prints the non-sensitive config
summary if a container starts with the wrong URLs or directories.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, computed_field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application settings with secure defaults."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "security-watchdog"
    environment: str = "development"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 31337
    run_embedded_scheduler: bool = False

    database_url: str = "sqlite:///./data/security_watchdog.db"
    redis_url: str = "redis://redis:6379/0"

    github_api_url: str = "https://api.github.com"
    github_clone_base_url: str = "https://github.com"
    github_token: str = ""
    github_username: str = ""
    github_alert_repository: str = ""
    github_request_timeout_seconds: int = 30
    github_include_private: bool = True

    repo_storage_path: Path = Path("./data/repos")
    sbom_output_path: Path = Path("./data/sbom")
    homeassistant_config_path: Path = Path("./data/homeassistant-config")
    homeassistant_core_components_path: Path = Path("./data/homeassistant-core/components")
    homeassistant_scan_enabled: bool = True
    homeassistant_remote_enabled: bool = False
    homeassistant_remote_base_url: str = ""
    homeassistant_remote_token: str = ""
    homeassistant_remote_verify_tls: bool = True
    homeassistant_remote_timeout_seconds: int = 15

    unraid_docker_enabled: bool = True
    unraid_docker_host: str = "unix:///var/run/docker.sock"
    unraid_verify_tls: bool = False

    scan_schedule_hours: int = 24
    feed_schedule_hours: int = 6
    ai_schedule_days: int = 30

    osv_api_url: str = "https://api.osv.dev/v1/query"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    github_advisory_url: str = "https://api.github.com/advisories"

    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4.1-mini"
    ai_enabled: bool = False

    email_enabled: bool = False
    email_from: str = "watchdog@example.local"
    email_to: str = ""
    smtp_host: str = "mailhog"
    smtp_port: int = 1025
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = False

    slack_webhook_url: str = ""

    default_rss_feeds: list[str] = Field(
        default_factory=lambda: [
            "https://feeds.feedburner.com/TheHackersNews",
            "https://www.bleepingcomputer.com/feed/",
            "https://krebsonsecurity.com/feed/",
            "https://hnrss.org/newest?q=supply+chain+security",
        ]
    )
    reddit_netsec_url: str = "https://www.reddit.com/r/netsec/.json"
    github_issue_keywords: list[str] = Field(
        default_factory=lambda: [
            "malicious package",
            "dependency confusion",
            "supply chain attack",
            "compromised dependency",
        ]
    )

    trivy_binary: str = "trivy"
    grype_binary: str = "grype"
    git_binary: str = "git"

    @computed_field
    @property
    def scans_output_path(self) -> Path:
        """Dedicated location for raw scan artifacts."""

        return self.repo_storage_path.parent / "scan-results"

    @field_validator("homeassistant_remote_base_url")
    @classmethod
    def normalize_homeassistant_remote_base_url(cls, value: str) -> str:
        """Strip whitespace and trailing slashes so API calls compose predictably."""

        return value.strip().rstrip("/")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a shared settings instance and ensure only internal writable directories exist."""

    settings = Settings()
    settings.repo_storage_path.mkdir(parents=True, exist_ok=True)
    settings.sbom_output_path.mkdir(parents=True, exist_ok=True)
    settings.scans_output_path.mkdir(parents=True, exist_ok=True)
    return settings
