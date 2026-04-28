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
import subprocess
from collections.abc import Iterator
from pathlib import Path

from app.core.config import get_settings
from app.models.schemas import SecretFinding

LOGGER = logging.getLogger(__name__)

SKIPPED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
}
LOW_SIGNAL_PATH_PARTS = {
    "doc",
    "docs",
    "example",
    "examples",
    "fixture",
    "fixtures",
    "test",
    "tests",
}
LOCKFILE_NAMES = {
    "cargo.lock",
    "composer.lock",
    "package-lock.json",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "yarn.lock",
}
SKIPPED_BINARY_EXTENSIONS = {
    ".7z",
    ".avi",
    ".bin",
    ".bmp",
    ".class",
    ".dll",
    ".dylib",
    ".eot",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".lockb",
    ".mov",
    ".mp3",
    ".mp4",
    ".ogg",
    ".otf",
    ".pdf",
    ".png",
    ".pyc",
    ".so",
    ".sqlite",
    ".tar",
    ".ttf",
    ".wav",
    ".webm",
    ".woff",
    ".woff2",
    ".zip",
}
SECRET_CONTEXT_PATTERN = re.compile(
    r"(?i)\b("
    r"access[_-]?key|"
    r"api[_-]?key|"
    r"apikey|"
    r"auth(?:orization)?|"
    r"bearer|"
    r"client[_-]?secret|"
    r"credential|"
    r"dsn|"
    r"passwd|"
    r"password|"
    r"private[_-]?key|"
    r"refresh[_-]?token|"
    r"secret|"
    r"token|"
    r"webhook"
    r")\b"
)
HIGH_SIGNAL_PREFIXES = (
    "akia",
    "gho_",
    "ghp_",
    "ghr_",
    "ghs_",
    "ghu_",
    "sk-",
    "xox",
)
PLACEHOLDER_SECRET_TOKENS = (
    "changeme",
    "change-me",
    "dummy",
    "example",
    "fake",
    "not-set",
    "not_configured",
    "not-configured",
    "placeholder",
    "sample",
    "todo",
    "your_",
)
VARIABLE_REFERENCE_PREFIXES = (
    "$",
    "${",
    "{{",
    "env.",
    "process.env.",
    "secretref:",
    "secrets.",
    "settings.",
    "vault:",
)
VARIABLE_REFERENCE_SUBSTRINGS = (
    "process.env.",
    "secrets.",
    "settings.",
    "vault:",
)
GENERIC_SECRET_VALUE_PATTERN = re.compile(r"[^\s'\"#]{8,}")
GIT_HISTORY_COMMIT_PREFIX = "__COMMIT__"
GIT_HUNK_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----"),
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "generic_password": re.compile(
        r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]?(?P<secret_value>[^'\"\s#]{8,})['\"]?"
    ),
    "generic_token_assignment": re.compile(
        r"(?i)\b("
        r"access[_-]?key|"
        r"api[_-]?key|"
        r"auth[_-]?token|"
        r"client[_-]?secret|"
        r"private[_-]?token|"
        r"refresh[_-]?token|"
        r"secret|"
        r"token"
        r")\b\s*[:=]\s*['\"]?(?P<secret_value>[^'\"\s#]{8,})['\"]?"
    ),
    "credential_in_url": re.compile(r"\bhttps?://[^/\s:@]+:[^/\s:@]+@[^/\s]+\b"),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}\b"),
}


class SecretScanner:
    """Regex and entropy based secret scanner."""

    def __init__(self, entropy_threshold: float = 4.0) -> None:
        self.entropy_threshold = entropy_threshold
        self.settings = get_settings()

    def scan_directory(self, root_path: Path, *, include_git_history: bool = False) -> list[SecretFinding]:
        """Scan a directory tree for suspicious secrets."""

        findings: list[SecretFinding] = []
        for path in root_path.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIPPED_DIRECTORIES for part in path.parts):
                continue
            findings.extend(self.scan_file(path, root_path))
        if include_git_history:
            findings.extend(self.scan_git_history(root_path))
        return self._deduplicate_findings(findings)

    def scan_file(self, file_path: Path, root_path: Path | None = None) -> list[SecretFinding]:
        """Scan one file line by line."""

        findings: list[SecretFinding] = []
        if self._should_skip_file(file_path) or self._looks_binary(file_path):
            return findings

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as error:
            LOGGER.warning("Failed to read file for secret scan", extra={"file": str(file_path), "error": str(error)})
            return findings

        relative_path = file_path.relative_to(root_path).as_posix() if root_path else file_path.as_posix()
        allow_entropy_scan = self._allow_entropy_scan(relative_path)
        for line_number, line in enumerate(content, start=1):
            findings.extend(
                self._scan_text_line(
                    line=line,
                    file_path=relative_path,
                    line_number=line_number,
                    allow_entropy_scan=allow_entropy_scan,
                )
            )
        return self._deduplicate_findings(findings)

    def scan_git_history(self, root_path: Path) -> list[SecretFinding]:
        """
        Scan added lines across git history for publicly exposed secrets.

        Why this exists:
        A leaked key can stay publicly reachable in old commits even after it has been deleted from
        the current working tree. Scanning commit diffs lets us flag those historical exposures.
        """

        if not (root_path / ".git").exists():
            return []

        findings: list[SecretFinding] = []
        current_commit: str | None = None
        current_file: str | None = None
        current_line_number: int | None = None

        for raw_line in self._iter_git_history_lines(root_path):
            line = raw_line.rstrip("\n")
            if line.startswith(GIT_HISTORY_COMMIT_PREFIX):
                current_commit = line.removeprefix(GIT_HISTORY_COMMIT_PREFIX)
                current_file = None
                current_line_number = None
                continue
            if line.startswith("+++ /dev/null"):
                current_file = None
                continue
            if line.startswith("+++ b/"):
                current_file = line.removeprefix("+++ b/")
                continue
            if line.startswith("@@"):
                current_line_number = self._extract_added_hunk_line_number(line)
                continue
            if current_commit is None or current_file is None or current_line_number is None:
                continue
            if not line.startswith("+") or line.startswith("+++"):
                continue

            findings.extend(
                self._scan_text_line(
                    line=line[1:],
                    file_path=current_file,
                    line_number=current_line_number,
                    allow_entropy_scan=self._allow_entropy_scan(current_file),
                    content_source="git_history",
                    commit_sha=current_commit,
                )
            )
            current_line_number += 1

        return self._deduplicate_findings(findings)

    def _iter_git_history_lines(self, root_path: Path) -> Iterator[str]:
        """Stream `git log -p` output so large repositories do not have to fit fully in memory."""

        command = [
            self.settings.git_binary,
            "-C",
            str(root_path),
            "log",
            "--all",
            f"--format={GIT_HISTORY_COMMIT_PREFIX}%H",
            "--unified=0",
            "--no-color",
            "--no-ext-diff",
        ]
        if self.settings.secret_history_max_commits_per_repo > 0:
            command.insert(4, f"--max-count={self.settings.secret_history_max_commits_per_repo}")

        process = subprocess.Popen(  # noqa: S603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        assert process.stdout is not None
        assert process.stderr is not None
        try:
            for line in process.stdout:
                yield line
        finally:
            stderr = process.stderr.read()
            return_code = process.wait()
            if return_code != 0:
                raise RuntimeError(
                    "Git history secret scan failed. "
                    f"repository={root_path} exit_code={return_code} stderr={stderr.strip()!r}"
                )

    def _scan_text_line(
        self,
        *,
        line: str,
        file_path: str,
        line_number: int,
        allow_entropy_scan: bool,
        content_source: str = "working_tree",
        commit_sha: str | None = None,
    ) -> list[SecretFinding]:
        """Run regex and entropy detectors against one logical source line."""

        findings: list[SecretFinding] = []
        for detector_name, pattern in SECRET_PATTERNS.items():
            match = pattern.search(line)
            if match is None:
                continue

            secret_preview_source = match.groupdict().get("secret_value") or match.group(0)
            if detector_name in {"generic_password", "generic_token_assignment"}:
                if not self._looks_plausible_assigned_secret(secret_preview_source):
                    continue

            findings.append(
                SecretFinding(
                    file_path=file_path,
                    line_number=line_number,
                    detector=detector_name,
                    excerpt=self._redact_line(secret_preview_source),
                    content_source=content_source,
                    commit_sha=commit_sha,
                )
            )

        if not allow_entropy_scan:
            return findings

        for candidate in re.findall(r"[A-Za-z0-9/+_=.-]{20,}", line):
            if not self._is_high_entropy_candidate(candidate):
                continue
            if not self._is_secret_like_entropy_context(line, candidate):
                continue
            entropy = self._shannon_entropy(candidate)
            if entropy >= self.entropy_threshold:
                findings.append(
                    SecretFinding(
                        file_path=file_path,
                        line_number=line_number,
                        detector="high_entropy",
                        excerpt=self._redact_line(candidate),
                        entropy=round(entropy, 3),
                        content_source=content_source,
                        commit_sha=commit_sha,
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

    def _should_skip_file(self, file_path: Path) -> bool:
        """Skip obviously binary/media artifacts that create noise and slow scans down."""

        return file_path.suffix.lower() in SKIPPED_BINARY_EXTENSIONS

    def _looks_binary(self, file_path: Path) -> bool:
        """Detect binary content even when the extension looks inconclusive."""

        try:
            sample = file_path.read_bytes()[:2048]
        except OSError:
            return False
        if not sample:
            return False
        if b"\x00" in sample:
            return True
        try:
            sample.decode("utf-8")
        except UnicodeDecodeError:
            return True
        return False

    def _allow_entropy_scan(self, relative_path: str) -> bool:
        """
        Disable entropy-only scanning for low-signal paths.

        Why this exists:
        Documentation, fixtures, tests, and lockfiles often contain long synthetic or generated
        strings. Regex-based detectors still run there, but raw entropy scanning creates too many
        false positives for operators to trust.
        """

        path = Path(relative_path.lower())
        if path.name in LOCKFILE_NAMES:
            return False
        return not any(part in LOW_SIGNAL_PATH_PARTS for part in path.parts)

    def _is_high_entropy_candidate(self, candidate: str) -> bool:
        """Filter out common noisy tokens before we compute entropy."""

        lowered = candidate.lower()
        if lowered.startswith(("http://", "https://")):
            return False
        if re.fullmatch(r"[0-9a-f]{20,}", lowered):
            return False
        if len(candidate) > 200:
            return False

        has_lower = any(character.islower() for character in candidate)
        has_upper = any(character.isupper() for character in candidate)
        has_digit = any(character.isdigit() for character in candidate)
        has_symbol = any(character in "/+_=.-" for character in candidate)
        signal_classes = sum((has_lower, has_upper, has_digit, has_symbol))
        return signal_classes >= 2

    def _is_secret_like_entropy_context(self, line: str, candidate: str) -> bool:
        """Require secret-like context so entropy alone does not overwhelm the dashboard."""

        lowered_candidate = candidate.lower()
        if self._looks_placeholder_secret(lowered_candidate):
            return False
        if lowered_candidate.startswith(HIGH_SIGNAL_PREFIXES):
            return True
        if SECRET_CONTEXT_PATTERN.search(line):
            return True
        return bool(
            re.search(rf"[:=]\s*[\"']?{re.escape(candidate)}(?:[\"']|\b)", line)
        )

    def _looks_plausible_assigned_secret(self, value: str) -> bool:
        """Ignore placeholders and references while still catching realistic assigned secrets."""

        normalized_value = value.strip().strip("'\"")
        if not GENERIC_SECRET_VALUE_PATTERN.fullmatch(normalized_value):
            return False
        if self._looks_placeholder_secret(normalized_value):
            return False

        has_lower = any(character.islower() for character in normalized_value)
        has_upper = any(character.isupper() for character in normalized_value)
        has_digit = any(character.isdigit() for character in normalized_value)
        has_symbol = any(character in "/+_=.@:-" for character in normalized_value)
        signal_classes = sum((has_lower, has_upper, has_digit, has_symbol))
        return signal_classes >= 2

    def _looks_placeholder_secret(self, value: str) -> bool:
        """Filter obvious placeholders, examples, and environment references."""

        normalized_value = value.strip().strip("'\"").lower()
        if not normalized_value:
            return True
        if normalized_value.startswith(VARIABLE_REFERENCE_PREFIXES):
            return True
        if any(marker in normalized_value for marker in VARIABLE_REFERENCE_SUBSTRINGS):
            return True
        if any(token in normalized_value for token in PLACEHOLDER_SECRET_TOKENS):
            return True
        if re.fullmatch(r"[x*._-]{8,}", normalized_value):
            return True
        return False

    def _extract_added_hunk_line_number(self, line: str) -> int | None:
        """Parse the `+new_line` portion from one unified-diff hunk header."""

        match = GIT_HUNK_PATTERN.search(line)
        if match is None:
            return None
        return int(match.group(1))

    def _deduplicate_findings(self, findings: list[SecretFinding]) -> list[SecretFinding]:
        """Collapse duplicate findings from repeated detectors on the same line."""

        deduplicated: list[SecretFinding] = []
        seen: set[tuple[str, int, str, str, str, str | None]] = set()
        for finding in findings:
            key = (
                finding.file_path,
                finding.line_number,
                finding.detector,
                finding.excerpt,
                finding.content_source,
                finding.commit_sha,
            )
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(finding)
        return deduplicated
