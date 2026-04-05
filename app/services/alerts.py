"""
Purpose: Dispatch alerts via Slack, email, and optional GitHub issues once correlation is done.
Input/Output: Accepts ORM alert objects and sends notifications to configured channels.
Important invariants: Notification delivery must be best-effort and non-blocking for the main scan;
deduplication should prevent the same alert from flooding channels repeatedly.
Debugging: If alerts exist in the DB but nobody gets notified, inspect channel-specific errors here.
"""

from __future__ import annotations

import json
import logging
import smtplib
from email.message import EmailMessage

import httpx

from app.models.entities import Alert, Repository
from app.services.cache import RedisStateStore
from app.services.github_client import GitHubClient

LOGGER = logging.getLogger(__name__)


class AlertDispatcher:
    """Best-effort multi-channel alert delivery."""

    def __init__(self) -> None:
        from app.core.config import get_settings

        self.settings = get_settings()
        self.github_client = GitHubClient()
        self.redis = RedisStateStore()

    def dispatch(self, alert: Alert, repository: Repository | None) -> None:
        """Send one alert to all configured channels unless it was just sent recently."""

        if self.redis.seen_recently(alert.fingerprint):
            LOGGER.info("Skipping recently-sent alert", extra={"alert_id": alert.id})
            return
        self._send_slack(alert, repository)
        self._send_email(alert, repository)
        self._create_github_issue(alert, repository)

    def _send_slack(self, alert: Alert, repository: Repository | None) -> None:
        """Post alert summaries to Slack via incoming webhook."""

        if not self.settings.slack_webhook_url:
            return
        payload = {
            "text": (
                f"[{alert.severity.upper()}] {alert.title}\n"
                f"Repository/Asset: {repository.full_name if repository else 'global'}\n"
                f"Risk score: {alert.risk_score}\n{alert.description}"
            )
        }
        try:
            with httpx.Client(timeout=15) as client:
                client.post(self.settings.slack_webhook_url, json=payload).raise_for_status()
        except Exception as error:  # noqa: BLE001
            LOGGER.warning("Slack alert delivery failed", extra={"alert_id": alert.id, "error": str(error)})

    def _send_email(self, alert: Alert, repository: Repository | None) -> None:
        """Send alert summaries by SMTP."""

        if not self.settings.email_enabled or not self.settings.email_to:
            return
        message = EmailMessage()
        message["Subject"] = f"[security-watchdog] {alert.severity.upper()} {alert.title}"
        message["From"] = self.settings.email_from
        message["To"] = self.settings.email_to
        message.set_content(
            f"Repository/Asset: {repository.full_name if repository else 'global'}\n"
            f"Risk score: {alert.risk_score}\n\n{alert.description}"
        )
        try:
            with smtplib.SMTP(self.settings.smtp_host, self.settings.smtp_port, timeout=15) as client:
                if self.settings.smtp_use_tls:
                    client.starttls()
                if self.settings.smtp_username:
                    client.login(self.settings.smtp_username, self.settings.smtp_password)
                client.send_message(message)
        except OSError as error:
            LOGGER.warning("Email alert delivery failed", extra={"alert_id": alert.id, "error": str(error)})

    def _create_github_issue(self, alert: Alert, repository: Repository | None) -> None:
        """Open a GitHub issue in the central alert repository if configured."""

        if not self.settings.github_alert_repository:
            return
        title = f"{alert.severity.upper()}: {alert.title}"
        body = (
            f"Repository/Asset: {repository.full_name if repository else 'global'}\n\n"
            f"Risk score: {alert.risk_score}\n\n"
            f"{alert.description}\n\n"
            f"Metadata:\n```json\n{json.dumps(alert.metadata_json, indent=2)}\n```"
        )
        try:
            self.github_client.create_issue(self.settings.github_alert_repository, title, body)
        except Exception as error:  # noqa: BLE001
            LOGGER.warning("GitHub issue alert delivery failed", extra={"alert_id": alert.id, "error": str(error)})
