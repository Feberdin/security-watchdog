"""
Purpose: Detect likely secrets, keys, and credentials in repository and integration files.
Input/Output: Reads text files and returns `SecretFinding` objects with context and detector names.
Important invariants: Findings must provide enough evidence to triage without printing full secrets;
binary files and giant dependency folders are skipped to keep scans fast and predictable.
Debugging: If a secret is missed, add a detector or inspect the entropy threshold in this module.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

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
TEST_FIXTURE_PATH_PARTS = {
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
SECURITY_KEY_QUALIFIERS = {
    "ACCESS",
    "API",
    "AUTH",
    "CREDENTIAL",
    "ENCRYPTION",
    "HMAC",
    "JWT",
    "MASTER",
    "PRIVATE",
    "SECRET",
    "SESSION",
    "SIGNING",
    "SSH",
}
PLACEHOLDER_SECRET_TOKENS = (
    "a1b2c3d4",
    "abcdefghijklmnopqrstuvwxyz",
    "changeme",
    "change-me",
    "demo",
    "dummy",
    "example",
    "fake",
    "fresh-token",
    "fresh_token",
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
    "secret://",
    "secretref:",
    "secrets.",
    "self.",
    "settings.",
    "vault:",
)
VARIABLE_REFERENCE_SUBSTRINGS = (
    "process.env.",
    "secret://",
    "secrets.",
    "self.",
    "settings.",
    "vault:",
)
GENERIC_SECRET_VALUE_PATTERN = re.compile(r"[^\s'\"#]{8,}")
SECRET_REFERENCE_PATTERN = re.compile(r"secret://[A-Za-z0-9_.-]+")
CODE_REFERENCE_EXPRESSION_PATTERN = re.compile(
    r"^(?:await\s+)?[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\s*(?:\(|\[)"
)
CODE_MEMBER_REFERENCE_PATTERN = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+"
)
CODE_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
CODE_KEYWORD_ARGUMENT_PATTERN = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*=[A-Za-z_$][A-Za-z0-9_$]*"
)
CODE_TYPE_ANNOTATION_PATTERN = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$.]*(?:\s*\|\s*[A-Za-z_$][A-Za-z0-9_$.]*)*"
    r"(?:\s*=\s*(?:None|null|undefined)?)?"
)
HUMAN_READABLE_SLUG_PATTERN = re.compile(r"[a-z]+(?:[-_](?:[a-z]+|\d+))+")
SOURCE_CODE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".cjs",
    ".cts",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".htm",
    ".html",
    ".kt",
    ".kts",
    ".mjs",
    ".mts",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".svelte",
    ".swift",
    ".ts",
    ".tsx",
    ".vue",
}
ASSIGNMENT_PATTERN = re.compile(
    r"""^\s*(?:-\s*)?(?:export\s+)?(?P<name>["']?[A-Za-z_][A-Za-z0-9_.-]*["']?)\s*(?::|=)\s*(?P<value>.+?)\s*,?\s*$"""
)
GIT_HISTORY_COMMIT_PREFIX = "__COMMIT__"
GIT_HUNK_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")

BROKER_SECRET_NAMES = {
    "BITWARDEN_CLIENT_ID",
    "BITWARDEN_CLIENT_SECRET",
    "BITWARDEN_MASTER_PASSWORD",
    "BITWARDEN_SERVER_URL",
    "BITWARDEN_SERVER_URL_FALLBACK_SECRET_REFS",
    "BROKER_MCP_TOKEN",
    "BROKER_SECRET_KEY",
    "BROKER_WEBHOOK_TOKEN",
    "GITHUB_NOTIFICATIONS_TOKEN",
    "NTFY_TOKEN",
    "NTFY_TOPIC",
    "SECURITY_WATCHDOG_DEPLOYMENT_GATE_TOKEN",
    "SECURITY_WATCHDOG_GATE_TOKEN",
    "SECURITY_WATCHDOG_GITHUB_TOKEN",
    "SMTP_PASSWORD",
    "SMTP_USERNAME",
    "UNIFI_PASSWORD",
    "UNIFI_USERNAME",
    "UNRAID_API_KEY",
    "UNRAID_DEPLOY_BROKER_TOKEN",
}
BROKER_TEMPLATE_SECRET_NAMES = {
    "SECONDBRAIN_VOICE_OAUTH_ALLOWED_REDIRECT_URIS",
    "SECONDBRAIN_VOICE_OAUTH_BOOTSTRAP_USER_EMAIL",
    "SECONDBRAIN_VOICE_OAUTH_BOOTSTRAP_USER_PASSWORD",
    "SECONDBRAIN_VOICE_OAUTH_CLIENT_SECRET",
    "SECONDBRAIN_VOICE_OAUTH_DATABASE_URL",
    "SECONDBRAIN_VOICE_OAUTH_JWT_SECRET",
    "SECONDBRAIN_VOICE_OAUTH_POSTGRES_PASSWORD",
    "SECONDBRAIN_VOICE_OAUTH_PUBLIC_BASE_URL",
}
BROKER_NON_SECRET_VARIABLES = {
    "BROKER_CONFIG",
    "BROKER_DATA_DIR",
    "BROKER_LOG_LEVEL",
    "BROKER_STACKS_HOST_DIR",
    "CSI_SOURCE",
    "MODELS_DIR",
    "RUST_LOG",
    "SENSING_ALLOWED_HOSTS",
}
BROKER_SECRET_NAME_FIELD_NAMES = {
    "database_url_secret_name",
    "password_secret_name",
}
SAFE_LITERAL_VALUES = {
    "false",
    "none",
    "null",
    "off",
    "on",
    "true",
}
SECRET_NAME_VALUE_PATTERN = re.compile(r"[A-Z][A-Z0-9_.-]*")
SECRET_NAME_LIST_PATTERN = re.compile(r"[A-Z][A-Z0-9_.-]*(?:\s*,\s*[A-Z][A-Z0-9_.-]*)*")

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
HIGH_SIGNAL_SECRET_DETECTORS = {
    "aws_access_key",
    "github_token",
    "openai_key",
    "private_key",
    "slack_token",
}


@dataclass(frozen=True)
class ParsedAssignment:
    """One simple key/value assignment from env, YAML, TOML, or JSON-like config."""

    name: str
    value: str
    name_was_quoted: bool
    value_was_quoted: bool


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
                    # Git history contains every transient generated value ever committed. Entropy
                    # alone is too noisy there, so history scans keep high-confidence regex
                    # detectors and skip entropy-only findings.
                    allow_entropy_scan=False,
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

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        if process.stdout is None or process.stderr is None:
            raise RuntimeError(
                "Git history secret scan failed before output streams were available. "
                f"repository={root_path}"
            )
        try:
            yield from process.stdout
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
        assignment = self._parse_assignment(line)
        assignment_finding = self._scan_assignment_for_secret(
            assignment=assignment,
            file_path=file_path,
            line_number=line_number,
            content_source=content_source,
            commit_sha=commit_sha,
        )
        if assignment_finding is not None:
            is_generic_fixture_finding = (
                self._is_test_fixture_path(file_path)
                and not self._contains_high_signal_literal_secret(assignment.value)
            )
            if not is_generic_fixture_finding:
                findings.append(assignment_finding)
            if (
                assignment_finding.detector != "generic_token_assignment"
                and not is_generic_fixture_finding
            ):
                return findings
        if assignment is not None and self._is_safe_assignment_context(
            assignment,
            file_path=file_path,
        ):
            return findings

        for detector_name, pattern in SECRET_PATTERNS.items():
            if (
                self._is_test_fixture_path(file_path)
                and detector_name not in HIGH_SIGNAL_SECRET_DETECTORS
            ):
                continue
            match = pattern.search(line)
            if match is None:
                continue

            secret_preview_source = match.groupdict().get("secret_value") or match.group(0)
            if self._looks_placeholder_secret(secret_preview_source):
                continue
            if self._looks_synthetic_regex_match(
                detector_name,
                secret_preview_source,
                file_path=file_path,
            ):
                continue
            if detector_name in {"generic_password", "generic_token_assignment"}:
                value_start = match.start("secret_value")
                value_was_quoted = value_start > 0 and line[value_start - 1] in {"'", '"'}
                if not self._looks_plausible_assigned_secret(
                    secret_preview_source,
                    file_path=file_path,
                    value_was_quoted=value_was_quoted,
                ):
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
            if not self._is_secret_like_entropy_context(
                line,
                candidate,
                file_path=file_path,
            ):
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

    def _parse_assignment(self, line: str) -> ParsedAssignment | None:
        """
        Parse simple config assignments without attempting to parse whole files.

        Why this exists:
        Broker and Compose configuration often uses `KEY=value`, `KEY: value`, or JSON/TOML-like
        `"KEY": "value"` lines. Understanding the left-hand variable name lets the scanner separate
        secret references from hard-coded credentials before broader regex checks run.
        """

        match = ASSIGNMENT_PATTERN.search(line)
        if match is None:
            return None
        raw_name = match.group("name").strip()
        name_was_quoted = (
            len(raw_name) >= 2
            and raw_name[0] == raw_name[-1]
            and raw_name[0] in {"'", '"'}
        )
        name = raw_name.strip("'\"")
        raw_value = re.sub(r"\s+#.*$", "", match.group("value")).strip().rstrip(",").strip()
        value_was_quoted = (
            len(raw_value) >= 2
            and raw_value[0] == raw_value[-1]
            and raw_value[0] in {"'", '"'}
        )
        value = self._clean_assignment_value(raw_value)
        if not name or not value:
            return None
        return ParsedAssignment(
            name=name,
            value=value,
            name_was_quoted=name_was_quoted,
            value_was_quoted=value_was_quoted,
        )

    def _clean_assignment_value(self, value: str) -> str:
        """Normalize one assigned value while preserving enough evidence for detector decisions."""

        return value.strip().strip("'\"")

    def _scan_assignment_for_secret(
        self,
        *,
        assignment: ParsedAssignment | None,
        file_path: str,
        line_number: int,
        content_source: str,
        commit_sha: str | None,
    ) -> SecretFinding | None:
        """
        Apply explicit Broker and environment-variable secret-name rules to one assignment.

        Why this exists:
        The Deployment Broker uses many variables whose names contain `secret`, `token`, or `url`
        even when the value is only a Broker-managed reference. These rules flag literal values for
        credential-bearing names and skip safe reference/name fields.
        """

        if assignment is None:
            return None

        normalized_name = self._normalize_variable_name(assignment.name)
        value = assignment.value
        if self._looks_non_literal_source_assignment(
            assignment,
            file_path=file_path,
        ):
            return None
        if self._is_secret_name_field(normalized_name):
            if self._looks_safe_secret_name_reference_value(value):
                return None
            if self._looks_concrete_secret_value(
                value,
                allow_short=False,
                allow_url=True,
                file_path=file_path,
                value_was_quoted=assignment.value_was_quoted,
            ):
                return self._build_secret_finding(
                    detector="secret_name_field_unusual_value",
                    value=value,
                    file_path=file_path,
                    line_number=line_number,
                    content_source=content_source,
                    commit_sha=commit_sha,
                )
            return None

        if self._is_known_non_secret_variable(normalized_name):
            return None

        if self._is_known_broker_secret_name(normalized_name):
            if self._looks_concrete_secret_value(
                value,
                allow_short=True,
                allow_url=True,
                file_path=file_path,
                value_was_quoted=assignment.value_was_quoted,
            ):
                return self._build_secret_finding(
                    detector="broker_secret_assignment",
                    value=value,
                    file_path=file_path,
                    line_number=line_number,
                    content_source=content_source,
                    commit_sha=commit_sha,
                )
            return None

        # Preserve the dedicated password detector and its established alert classification for
        # plain `password`, `passwd`, and `pwd` assignments.
        if normalized_name in {"PASSWORD", "PASSWD", "PWD"}:
            return None

        is_credential_name = self._is_heuristic_secret_name(normalized_name)
        is_generic_key_name = normalized_name.endswith("_KEY")
        if not is_credential_name and not is_generic_key_name:
            return None

        if not self._looks_concrete_secret_value(
            value,
            allow_short=False,
            allow_url=normalized_name.endswith("_DATABASE_URL"),
            file_path=file_path,
            value_was_quoted=assignment.value_was_quoted,
        ):
            return None

        # Why this exists:
        # A generic `*_key` can be a business identifier such as `sender_key=email:...`. Only
        # explicit security-key names or genuinely high-entropy literals are credential evidence.
        if not is_credential_name and not self._looks_high_entropy_literal(value):
            return None

        return self._build_secret_finding(
            detector="generic_token_assignment",
            value=value,
            file_path=file_path,
            line_number=line_number,
            content_source=content_source,
            commit_sha=commit_sha,
        )

    def _build_secret_finding(
        self,
        *,
        detector: str,
        value: str,
        file_path: str,
        line_number: int,
        content_source: str,
        commit_sha: str | None,
    ) -> SecretFinding:
        """Create a redacted finding for an assigned literal credential."""

        return SecretFinding(
            file_path=file_path,
            line_number=line_number,
            detector=detector,
            excerpt=self._redact_line(value),
            content_source=content_source,
            commit_sha=commit_sha,
        )

    def _is_safe_assignment_context(
        self,
        assignment: ParsedAssignment,
        *,
        file_path: str,
    ) -> bool:
        """Return true when an assignment is intentionally a reference or non-secret config."""

        normalized_name = self._normalize_variable_name(assignment.name)
        if self._looks_non_literal_source_assignment(
            assignment,
            file_path=file_path,
        ):
            return True
        if SECRET_REFERENCE_PATTERN.search(assignment.value):
            return True
        if self._is_secret_name_field(normalized_name) and self._looks_safe_secret_name_reference_value(
            assignment.value
        ):
            return True
        if self._is_known_non_secret_variable(normalized_name):
            return not self._contains_high_signal_literal_secret(assignment.value)
        if (
            self._is_known_broker_secret_name(normalized_name)
            or self._is_heuristic_secret_name(normalized_name)
        ):
            return not self._looks_concrete_secret_value(
                assignment.value,
                allow_short=self._is_known_broker_secret_name(normalized_name),
                allow_url=(
                    normalized_name == "BITWARDEN_SERVER_URL"
                    or normalized_name.endswith("_DATABASE_URL")
                ),
                file_path=file_path,
                value_was_quoted=assignment.value_was_quoted,
            )
        return False

    def _normalize_variable_name(self, name: str) -> str:
        """Normalize config keys for case-insensitive secret-name classification."""

        return name.strip().strip("'\"").replace("-", "_").upper()

    def _is_secret_name_field(self, normalized_name: str) -> bool:
        """Identify fields whose value is expected to be one or more Broker secret names."""

        lowered_name = normalized_name.lower()
        return (
            lowered_name in BROKER_SECRET_NAME_FIELD_NAMES
            or lowered_name.endswith("_secret_ref")
            or lowered_name.endswith("_secret_refs")
        )

    def _is_known_non_secret_variable(self, normalized_name: str) -> bool:
        """Recognize Broker runtime settings that are configuration, not credentials."""

        return normalized_name in BROKER_NON_SECRET_VARIABLES

    def _is_known_broker_secret_name(self, normalized_name: str) -> bool:
        """Recognize Broker-managed secret variables and template-generated secret names."""

        return (
            normalized_name in BROKER_SECRET_NAMES
            or normalized_name in BROKER_TEMPLATE_SECRET_NAMES
            or normalized_name.startswith("INTERNET_WATCHER_COMPLAINT_SMTP_")
        )

    def _looks_non_literal_source_assignment(
        self,
        assignment: ParsedAssignment,
        *,
        file_path: str,
    ) -> bool:
        """
        Recognize source-code metadata and runtime references before treating them as credentials.

        Why this exists:
        A line scanner sees Python type annotations, JavaScript object properties, help-text maps,
        and role labels in the same `name: value` shape as YAML. Source files therefore need a
        narrow syntax-aware filter. Provider-shaped tokens and random-looking literal values are
        deliberately not suppressed here.
        """

        if Path(file_path).suffix.lower() not in SOURCE_CODE_EXTENSIONS:
            return False

        value = assignment.value.strip().strip("'\"").rstrip(",;")
        lowered_value = value.lower()
        if self._contains_high_signal_literal_secret(value):
            return False

        normalized_name = self._normalize_variable_name(assignment.name)
        if (
            normalized_name.endswith("_PREFIX")
            and value == lowered_value
            and len(value) <= 32
            and re.fullmatch(r"[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)+", value)
        ):
            return True

        if not assignment.value_was_quoted:
            if self._looks_code_reference_expression(value, file_path=file_path):
                return True
            if CODE_IDENTIFIER_PATTERN.fullmatch(value):
                return True
            if CODE_TYPE_ANNOTATION_PATTERN.fullmatch(value):
                return True

        if assignment.name_was_quoted:
            if (
                HUMAN_READABLE_SLUG_PATTERN.fullmatch(lowered_value)
                and lowered_value.endswith(
                    ("-admin", "-operator", "-read", "-role", "-scope", "-viewer", "-write")
                )
            ):
                return True
            words = value.split()
            if len(words) >= 4 and value.endswith((".", ":")):
                return True

        return bool(
            assignment.value_was_quoted
            and lowered_value.startswith(("example-", "my-", "sample-", "test-"))
            and HUMAN_READABLE_SLUG_PATTERN.fullmatch(lowered_value)
        )

    def _is_heuristic_secret_name(self, normalized_name: str) -> bool:
        """Catch credential-like environment names outside the explicit Broker lists."""

        if self._is_known_non_secret_variable(normalized_name):
            return False
        if self._is_secret_name_field(normalized_name):
            return False
        name_parts = {part for part in normalized_name.split("_") if part}
        return (
            "TOKEN" in name_parts
            or "SECRET" in name_parts
            or "PASSWORD" in name_parts
            or "BEARER" in name_parts
            or {"CLIENT", "SECRET"}.issubset(name_parts)
            or normalized_name.endswith("_DATABASE_URL")
            or normalized_name.endswith("_DATABASE_PASSWORD")
            or ("KEY" in name_parts and bool(name_parts & SECURITY_KEY_QUALIFIERS))
        )

    def _looks_high_entropy_literal(self, value: str) -> bool:
        """
        Recognize credential-shaped literals assigned to otherwise generic `*_key` fields.

        Why this exists:
        Names such as `sender_key` or `cache_key` are ambiguous. A readable structured identifier
        is business data, while a long random-looking literal still warrants review even without a
        security qualifier in the variable name.
        """

        normalized_value = value.strip().strip("'\"")
        if re.fullmatch(r"[A-Za-z0-9/+_=.-]{20,}", normalized_value) is None:
            return False
        if not self._is_high_entropy_candidate(normalized_value):
            return False
        return self._shannon_entropy(normalized_value) >= self.entropy_threshold

    def _looks_safe_secret_name_reference_value(self, value: str) -> bool:
        """Accept `secret://NAME`, env references, and uppercase secret-name lists as references."""

        normalized_value = value.strip().strip("'\"")
        if not normalized_value:
            return True
        lowered_value = normalized_value.lower()
        if normalized_value.startswith(VARIABLE_REFERENCE_PREFIXES):
            return True
        if any(marker in lowered_value for marker in VARIABLE_REFERENCE_SUBSTRINGS):
            return True
        if SECRET_REFERENCE_PATTERN.fullmatch(normalized_value):
            return True
        if SECRET_NAME_VALUE_PATTERN.fullmatch(normalized_value) and self._is_secret_reference_name_token(
            normalized_value
        ):
            return True
        if SECRET_NAME_LIST_PATTERN.fullmatch(normalized_value):
            parts = [part.strip() for part in normalized_value.split(",") if part.strip()]
            return bool(parts) and all(self._is_secret_reference_name_token(part) for part in parts)

        list_value = normalized_value.strip("[]")
        if list_value == normalized_value:
            return False
        parts = [part.strip().strip("'\"") for part in list_value.split(",") if part.strip()]
        return bool(parts) and all(
            SECRET_NAME_VALUE_PATTERN.fullmatch(part) and self._is_secret_reference_name_token(part)
            for part in parts
        )

    def _is_secret_reference_name_token(self, value: str) -> bool:
        """Return true when a plain string is shaped like a Broker secret name, not a secret value."""

        normalized_name = self._normalize_variable_name(value)
        return self._is_known_broker_secret_name(normalized_name) or self._is_heuristic_secret_name(
            normalized_name
        )

    def _looks_concrete_secret_value(
        self,
        value: str,
        *,
        allow_short: bool,
        allow_url: bool,
        file_path: str | None = None,
        value_was_quoted: bool = False,
    ) -> bool:
        """Return true for literal credential values, false for placeholders and references."""

        normalized_value = value.strip().strip("'\"")
        lowered_value = normalized_value.lower()
        if self._looks_placeholder_secret(normalized_value):
            return False
        if not value_was_quoted and self._looks_code_reference_expression(
            normalized_value,
            file_path=file_path,
        ):
            return False
        if self._looks_synthetic_low_signal_value(normalized_value, file_path=file_path):
            return False
        if self._looks_safe_secret_name_reference_value(normalized_value):
            return False
        if lowered_value in SAFE_LITERAL_VALUES:
            return False
        if re.fullmatch(r"\d+(?:\.\d+)?", normalized_value):
            return False
        if not allow_url and normalized_value.startswith(("http://", "https://")):
            return False
        if allow_short:
            return True
        return self._looks_plausible_assigned_secret(
            normalized_value,
            file_path=file_path,
            value_was_quoted=value_was_quoted,
        )

    def _contains_high_signal_literal_secret(self, value: str) -> bool:
        """Let strong token/key detectors still fire inside otherwise non-secret settings."""

        return any(
            pattern.search(value)
            for detector_name, pattern in SECRET_PATTERNS.items()
            if detector_name in HIGH_SIGNAL_SECRET_DETECTORS
        )

    def _is_test_fixture_path(self, file_path: str) -> bool:
        """
        Return true only for tests and fixtures, not general documentation.

        Generic credentials in README files remain actionable. Tests and fixtures are different:
        they intentionally contain scanner examples, so only provider-shaped signatures are
        trustworthy enough to alert there.
        """

        path = Path(file_path.lower())
        is_playwright_config = path.name.startswith("playwright.") and ".config." in path.name
        return is_playwright_config or any(
            part in TEST_FIXTURE_PATH_PARTS for part in path.parts
        )

    def _looks_synthetic_regex_match(
        self,
        detector_name: str,
        value: str,
        *,
        file_path: str,
    ) -> bool:
        """Suppress readable test fixtures while retaining provider-shaped credentials."""

        if self._allow_entropy_scan(file_path):
            return False

        normalized_value = value.strip().strip("'\"")
        if normalized_value.lower().startswith(HIGH_SIGNAL_PREFIXES):
            return False
        if detector_name == "bearer_token":
            token = re.sub(r"(?i)^bearer\s+", "", normalized_value).lower()
            return bool(HUMAN_READABLE_SLUG_PATTERN.fullmatch(token))
        if detector_name == "credential_in_url":
            try:
                parsed = urlsplit(normalized_value)
            except ValueError:
                return False
            credential_parts = [part for part in (parsed.username, parsed.password) if part]
            if not credential_parts or any(
                part.lower().startswith(HIGH_SIGNAL_PREFIXES) for part in credential_parts
            ):
                return False
            hostname = (parsed.hostname or "").lower()
            local_fixture_host = (
                hostname == "localhost"
                or hostname.endswith((".example", ".internal", ".invalid", ".local", ".test"))
            )
            if not local_fixture_host:
                try:
                    local_fixture_host = ipaddress.ip_address(hostname).is_private
                except ValueError:
                    local_fixture_host = False
            return local_fixture_host and all(
                len(part) <= 12
                or self._looks_placeholder_secret(part)
                or HUMAN_READABLE_SLUG_PATTERN.fullmatch(part.lower())
                for part in credential_parts
            )
        return False

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
        if path.suffix in {".md", ".rst"} or any(
            marker in path.name for marker in (".example", ".sample", ".template")
        ):
            return False
        return not any(part in LOW_SIGNAL_PATH_PARTS for part in path.parts)

    def _is_high_entropy_candidate(self, candidate: str) -> bool:
        """Filter out common noisy tokens before we compute entropy."""

        lowered = candidate.lower()
        if lowered.startswith(("http://", "https://")):
            return False
        if re.fullmatch(r"[0-9a-f]{20,}", lowered):
            return False
        if "_" in candidate and re.fullmatch(r"[A-Z][A-Z0-9_]{19,}", candidate):
            return False
        if len(candidate) > 200:
            return False

        has_lower = any(character.islower() for character in candidate)
        has_upper = any(character.isupper() for character in candidate)
        has_digit = any(character.isdigit() for character in candidate)
        has_symbol = any(character in "/+_=.-" for character in candidate)
        signal_classes = sum((has_lower, has_upper, has_digit, has_symbol))
        return signal_classes >= 2

    def _is_secret_like_entropy_context(
        self,
        line: str,
        candidate: str,
        *,
        file_path: str,
    ) -> bool:
        """Require secret-like context so entropy alone does not overwhelm the dashboard."""

        lowered_candidate = candidate.lower()
        if "secret://" in line.lower():
            return False
        if self._looks_placeholder_secret(lowered_candidate):
            return False
        if lowered_candidate.startswith(HIGH_SIGNAL_PREFIXES):
            return True
        if self._looks_source_code_entropy_noise(candidate, file_path=file_path):
            return False
        return bool(SECRET_CONTEXT_PATTERN.search(line))

    def _looks_source_code_entropy_noise(self, candidate: str, *, file_path: str) -> bool:
        """
        Exclude code identifiers, API routes, and asset paths from entropy-only findings.

        Literal credential assignments are handled before entropy scanning. This filter only
        removes tokens whose shape is ordinary source code but whose surrounding line happens to
        mention words such as `secret`, `token`, or `bearer`.
        """

        if Path(file_path).suffix.lower() not in SOURCE_CODE_EXTENSIONS:
            return False
        normalized_value = candidate.strip().strip("'\"")
        lowered_value = normalized_value.lower()
        if lowered_value.startswith(HIGH_SIGNAL_PREFIXES):
            return False
        if normalized_value.startswith("/"):
            return True
        if CODE_IDENTIFIER_PATTERN.fullmatch(normalized_value):
            return True
        if CODE_MEMBER_REFERENCE_PATTERN.fullmatch(normalized_value):
            return True
        if CODE_KEYWORD_ARGUMENT_PATTERN.fullmatch(normalized_value):
            return True
        if HUMAN_READABLE_SLUG_PATTERN.fullmatch(lowered_value):
            return True
        return "/" in normalized_value

    def _looks_plausible_assigned_secret(
        self,
        value: str,
        *,
        file_path: str | None = None,
        value_was_quoted: bool = False,
    ) -> bool:
        """Ignore placeholders and references while still catching realistic assigned secrets."""

        normalized_value = self._normalize_assigned_secret_candidate(value, file_path=file_path)
        if not GENERIC_SECRET_VALUE_PATTERN.fullmatch(normalized_value):
            return False
        if self._looks_placeholder_secret(normalized_value):
            return False
        if not value_was_quoted and self._looks_code_reference_expression(
            normalized_value,
            file_path=file_path,
        ):
            return False
        if self._looks_synthetic_low_signal_value(normalized_value, file_path=file_path):
            return False
        if (
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", normalized_value)
            and not any(character.isdigit() for character in normalized_value)
        ):
            return False
        if normalized_value.startswith(("/", "./", "../", "http://", "https://")):
            return False

        has_lower = any(character.islower() for character in normalized_value)
        has_upper = any(character.isupper() for character in normalized_value)
        has_digit = any(character.isdigit() for character in normalized_value)
        has_symbol = any(character in "/+_=.@:-" for character in normalized_value)
        signal_classes = sum((has_lower, has_upper, has_digit, has_symbol))
        return signal_classes >= 2

    def _normalize_assigned_secret_candidate(self, value: str, *, file_path: str | None) -> str:
        """
        Remove Markdown presentation characters that are not part of an assigned value.

        Why this exists:
        Markdown examples also occur inside source-code comments and docstrings, so normalization
        cannot depend on a Markdown filename. Only presentation characters at the candidate
        boundary are removed; real mixed-class values remain detectable after that trimming.
        """

        normalized_value = value.strip().strip("'\"")
        return normalized_value.lstrip("`([{").rstrip("`.,;:)]}")

    def _looks_code_reference_expression(self, value: str, *, file_path: str | None) -> bool:
        """
        Recognize calls and indexed lookups that resolve credentials at runtime.

        Why this exists:
        Source code commonly assigns `token` from a validator, configuration object, browser
        storage, or string-normalization call. The expression identifies where a value comes from;
        it is not a committed credential literal.
        """

        normalized_value = value.strip().strip("'\"").rstrip(",;)]}")
        if CODE_REFERENCE_EXPRESSION_PATTERN.match(normalized_value):
            return True
        if file_path is None or Path(file_path).suffix.lower() not in SOURCE_CODE_EXTENSIONS:
            return False
        return bool(
            CODE_IDENTIFIER_PATTERN.fullmatch(normalized_value)
            or CODE_MEMBER_REFERENCE_PATTERN.fullmatch(normalized_value)
        )

    def _looks_synthetic_low_signal_value(self, value: str, *, file_path: str | None) -> bool:
        """
        Suppress readable fixture slugs only in documentation, examples, and test paths.

        A value such as `worker-review-token` is useful in a test but is not shaped like a real
        credential. The same value in production configuration remains a finding. Known provider
        prefixes always win so a real leaked key in a fixture is still reported.
        """

        if file_path is None or self._allow_entropy_scan(file_path):
            return False
        normalized_value = value.strip().strip("'\"").lower()
        if normalized_value.startswith(HIGH_SIGNAL_PREFIXES):
            return False
        if self._looks_noncredential_local_url(normalized_value):
            return True
        return bool(HUMAN_READABLE_SLUG_PATTERN.fullmatch(normalized_value))

    def _looks_noncredential_local_url(self, value: str) -> bool:
        """Recognize private fixture endpoints without hiding URLs that embed credentials."""

        if not value.startswith(("http://", "https://")):
            return False
        try:
            parsed = urlsplit(value)
        except ValueError:
            return False
        if parsed.username or parsed.password:
            return False
        if parsed.query and SECRET_CONTEXT_PATTERN.search(parsed.query):
            return False
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False
        if hostname == "localhost" or hostname.endswith(
            (".example", ".internal", ".invalid", ".local", ".test")
        ):
            return True
        try:
            return ipaddress.ip_address(hostname).is_private
        except ValueError:
            return False

    def _looks_placeholder_secret(self, value: str) -> bool:
        """Filter obvious placeholders, examples, and environment references."""

        normalized_value = value.strip().strip("'\"").lower()
        if not normalized_value:
            return True
        if normalized_value in {"...", "…"}:
            return True
        if normalized_value.startswith("<") and normalized_value.endswith(">"):
            return True
        if normalized_value.startswith(VARIABLE_REFERENCE_PREFIXES):
            return True
        if any(marker in normalized_value for marker in VARIABLE_REFERENCE_SUBSTRINGS):
            return True
        if any(token in normalized_value for token in PLACEHOLDER_SECRET_TOKENS):
            return True
        if re.search(r"(?:^|[^a-z0-9])(?:example|fake|test)[-_]", normalized_value):
            return True
        if "{" in normalized_value and "}" in normalized_value:
            return True
        if re.fullmatch(r"(?:self|this)\.[A-Za-z_][A-Za-z0-9_.]*\([^)]*\)", normalized_value):
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
