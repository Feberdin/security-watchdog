"""
Purpose: Convert unstructured threat articles into structured malicious-package intelligence via AI.
Input/Output: Sends article text to an OpenAI-compatible API and stores structured threat records.
Important invariants: AI output must be JSON and validated before persistence; failed AI requests
must never mark an article as processed because that would silently drop future coverage.
Debugging: If extraction fails, inspect the raw model content and JSON parsing branch in this file.
"""

from __future__ import annotations

import json
import logging

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.entities import AIExtractedThreat, ThreatArticle
from app.models.schemas import AIExtractedThreatRecord
from app.repositories.store import record_scan_result

LOGGER = logging.getLogger(__name__)


class AIExtractionService:
    """Call an OpenAI-compatible API to extract package-centric threat indicators."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def extract_pending_articles(self, session: Session) -> int:
        """Process all unprocessed articles if AI extraction is enabled."""

        if not self.settings.ai_enabled or not self.settings.openai_api_key:
            LOGGER.info("AI extraction disabled by configuration")
            return 0

        articles = session.scalars(
            select(ThreatArticle).where(ThreatArticle.processed_by_ai.is_(False))
        ).all()
        extracted_count = 0
        for article in articles:
            threats = self._extract_one_article(article.normalized_text, article.source_url)
            session.execute(
                delete(AIExtractedThreat).where(AIExtractedThreat.threat_article_id == article.id)
            )
            for threat in threats:
                session.add(
                    AIExtractedThreat(
                        threat_article_id=article.id,
                        package_name=threat.package_name,
                        ecosystem=threat.ecosystem,
                        affected_versions=threat.affected_versions,
                        attack_type=threat.attack_type,
                        confidence_score=threat.confidence_score,
                        summary=threat.summary,
                        source_url=threat.source_url,
                        raw_payload=threat.raw_payload,
                    )
                )
                extracted_count += 1
            article.processed_by_ai = True

        record_scan_result(
            session,
            repository_id=None,
            scanner_name="ai_threat_extraction",
            status="success",
            findings_count=extracted_count,
            details={"processed_articles": len(articles)},
        )
        return extracted_count

    def _extract_one_article(self, article_text: str, source_url: str) -> list[AIExtractedThreatRecord]:
        """Send one article to the model and validate the returned JSON."""

        prompt = (
            "Extract supply-chain threat information from the article. "
            "Return only JSON with this shape: "
            '{"threats":[{"package_name":"str","ecosystem":"str","affected_versions":["str"],'
            '"attack_type":"str","confidence_score":0.0,"summary":"str"}]}. '
            "If no package-specific threat exists, return {\"threats\":[]}."
        )
        payload = {
            "model": self.settings.openai_model,
            "messages": [
                {"role": "system", "content": "You extract structured software supply-chain threats."},
                {
                    "role": "user",
                    "content": f"{prompt}\n\nSource URL: {source_url}\n\nArticle:\n{article_text[:12000]}",
                },
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=90) as client:
            response = client.post(
                f"{self.settings.openai_base_url.rstrip('/')}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
        parsed = self._safe_json_loads(content)
        threats = parsed.get("threats", [])
        return [
            AIExtractedThreatRecord(
                package_name=item["package_name"],
                ecosystem=item["ecosystem"],
                affected_versions=item.get("affected_versions", []),
                attack_type=item["attack_type"],
                confidence_score=float(item.get("confidence_score", 0.0)),
                source_url=source_url,
                summary=item.get("summary", ""),
                raw_payload=item,
            )
            for item in threats
            if item.get("package_name") and item.get("ecosystem") and item.get("attack_type")
        ]

    def _safe_json_loads(self, value: str) -> dict:
        """Parse JSON and strip common markdown fences if the model still adds them."""

        cleaned = value.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            cleaned = cleaned.removeprefix("json").strip()
        return json.loads(cleaned)
