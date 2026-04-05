"""
Purpose: Detect likely secrets, keys, and credentials in repository and integration files.
Input/Output: Reads text files and returns `SecretFinding` objects with context and detector names.
Important invariants: Findings must provide enough evidence to triage without printing full secrets;
binary files and giant dependency folders are skipped to keep scans fast and predictable.
Debugging: If a secret is missed, add a detector or inspect the entropy threshold in this module.
"""

from __future__ import annotations

import logging
import math
import re
from pathlib import Path

from app.models.schemas import SecretFinding

LOGGER = logging.getLogger(__name__)

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----"),
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "generic_password": re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}\b"),
}


class SecretScanner:
    """Regex and entropy based secret scanner."""

    def __init__(self, entropy_threshold: float = 4.0) -> None:
        self.entropy_threshold = entropy_threshold

    def scan_directory(self, root_path: Path) -> list[SecretFinding]:
        """Scan a directory tree for suspicious secrets."""

        findings: list[SecretFinding] = []
        for path in root_path.rglob("*"):
            if not path.is_file():
                continue
            if any(part in {".git", ".venv", "node_modules", "__pycache__"} for part in path.parts):
                continue
            findings.extend(self.scan_file(path, root_path))
        return findings

    def scan_file(self, file_path: Path, root_path: Path | None = None) -> list[SecretFinding]:
        """Scan one file line by line."""

        findings: list[SecretFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as error:
            LOGGER.warning("Failed to read file for secret scan", extra={"file": str(file_path), "error": str(error)})
            return findings

        relative_path = file_path.relative_to(root_path).as_posix() if root_path else file_path.as_posix()
        for line_number, line in enumerate(content, start=1):
            for detector_name, pattern in SECRET_PATTERNS.items():
                if pattern.search(line):
                    findings.append(
                        SecretFinding(
                            file_path=relative_path,
                            line_number=line_number,
                            detector=detector_name,
                            excerpt=self._redact_line(line),
                        )
                    )
            for candidate in re.findall(r"[A-Za-z0-9/+_=.-]{20,}", line):
                entropy = self._shannon_entropy(candidate)
                if entropy >= self.entropy_threshold and not any(char in candidate for char in ("http://", "https://")):
                    findings.append(
                        SecretFinding(
                            file_path=relative_path,
                            line_number=line_number,
                            detector="high_entropy",
                            excerpt=self._redact_line(candidate),
                            entropy=round(entropy, 3),
                        )
                    )
        return findings

    def _redact_line(self, value: str) -> str:
        """Keep only a tiny preview so alerts do not leak the full secret."""

        value = value.strip()
        if len(value) <= 12:
            return "***"
        return f"{value[:4]}...{value[-4:]}"

    def _shannon_entropy(self, value: str) -> float:
        """Compute Shannon entropy for a candidate token."""

        length = len(value)
        if length == 0:
            return 0.0
        frequencies = {character: value.count(character) / length for character in set(value)}
        return -sum(probability * math.log2(probability) for probability in frequencies.values())
