"""
Purpose: Verify regex and entropy-based secret detection behaves predictably on text files.
Input/Output: Writes small temporary files and checks the returned `SecretFinding` objects.
Important invariants: Findings must redact the preview and identify the detector used.
Debugging: If a detector becomes too noisy or too quiet, this file should fail in an obvious way.
"""

from __future__ import annotations

from pathlib import Path

from app.scanners.secret_scanner import SecretScanner


def test_detects_regex_based_secret(tmp_path):
    sample = tmp_path / "config.txt"
    value = "".join(("Super", "Value", "123!"))
    sample.write_text(f'password = "{value}"\n', encoding="utf-8")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings
    assert findings[0].detector == "generic_password"
    assert "..." in findings[0].excerpt


def test_detects_high_entropy_string(tmp_path):
    sample = tmp_path / "settings.txt"
    value = "".join(("Q7mP2xR9", "L4vN8cT1", "K6wD3sF5", "H2jB9zU4"))
    sample.write_text(f'api_key = "{value}"\n', encoding="utf-8")

    findings = SecretScanner(entropy_threshold=3.5).scan_file(sample, tmp_path)

    assert any(finding.detector == "high_entropy" for finding in findings)


def test_detects_generic_api_key_assignment_without_quotes(tmp_path):
    sample = tmp_path / ".env"
    value = "".join(("Live", "Signal_", "1234", "Abcd", "5678", "Value"))
    sample.write_text(f"API_KEY={value}\n", encoding="utf-8")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert any(finding.detector == "generic_token_assignment" for finding in findings)


def test_skips_environment_reference_assignments(tmp_path):
    sample = tmp_path / ".env.example"
    sample.write_text("API_KEY=process.env.OPENAI_API_KEY\n", encoding="utf-8")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_skips_common_template_placeholders(tmp_path):
    """Repository templates often keep values as placeholders without actual secrets."""

    sample = tmp_path / ".env.example"
    sample.write_text(
        "\n".join(
            [
                "DEPLOYMENT_GATE_TOKEN=replace-with-a-long-random-token",
                "GITHUB_TOKEN=replace-me",
                "TEST_GATE_TOKEN=test-only-token",
            ]
        ),
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_skips_code_level_token_references(tmp_path):
    """Function calls and f-string references are not literal credentials."""

    sample = tmp_path / "client.py"
    sample.write_text(
        'token = self._validated_token()\nheader = f"Bearer {token}"\n',
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_skips_typed_dataclass_assignments(tmp_path):
    """Pydantic/attrs-style typed defaults are config metadata, not committed secrets."""

    sample = tmp_path / "model.py"
    typed_defaults = "".join(
        (
            "smtp_",
            'password: str = ""\n',
            "API_",
            'KEY: str = ""\n',
        )
    )
    sample.write_text(
        typed_defaults,
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_skips_angle_bracket_placeholders(tmp_path):
    """Markdown/docs placeholder secrets in angle brackets should not be treated as literals."""

    sample = tmp_path / "README.md"
    sample.write_text("SECURITY_WATCHDOG_GATE_TOKEN=<secure token>\n", encoding="utf-8")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_skips_broker_secret_references(tmp_path):
    """Broker-managed secret references identify a value source, not a literal credential."""

    sample = tmp_path / "docker-compose.yml"
    sample.write_text("DATABASE_URL: secret://WATCHDOG_DATABASE_URL\n", encoding="utf-8")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_skips_broker_secret_name_reference_fields(tmp_path):
    """Broker secret-ref fields contain secret names that the Broker resolves later."""

    sample = tmp_path / "broker-config.toml"
    sample.write_text(
        '\n'.join(
            [
                'broker_mcp_token_secret_ref = "BROKER_MCP_TOKEN"',
                'password_secret_name = "APP_POSTGRES_PASSWORD"',
                'database_url_secret_name = "APP_DATABASE_URL"',
                'BITWARDEN_SERVER_URL_FALLBACK_SECRET_REFS="BITWARDEN_SERVER_URL,NTFY_TOKEN"',
            ]
        ),
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_skips_known_broker_non_secret_runtime_variables(tmp_path):
    """Broker paths, log settings, hosts, and runtime modes are configuration, not credentials."""

    sample = tmp_path / ".env"
    sample.write_text(
        '\n'.join(
            [
                "BROKER_CONFIG=/etc/unraid-deploy-broker/config.toml",
                "BROKER_DATA_DIR=/var/lib/unraid-deploy-broker",
                "BROKER_LOG_LEVEL=debug",
                "BROKER_STACKS_HOST_DIR=/mnt/user/appdata/stacks",
                "RUST_LOG=info",
                "CSI_SOURCE=broker",
                "MODELS_DIR=/models",
                "SENSING_ALLOWED_HOSTS=https://broker.local,http://192.168.57.10",
                "BROKER_HTTP_PORT=18443",
                "BROKER_REQUEST_TIMEOUT_SECONDS=30",
            ]
        ),
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_detects_hardcoded_known_broker_secret_values(tmp_path):
    """Known Broker secret variables are findings when they carry literal values."""

    sample = tmp_path / ".env"
    assignments = [
        "=".join(("BROKER_MCP_TOKEN", "".join(("MYTOKEN", "VALUE123")))),
        "=".join(("BITWARDEN_SERVER_URL", "https://vault.internal.lan")),
        "=".join(("NTFY_TOPIC", "prod-alerts")),
    ]
    sample.write_text(
        "\n".join(assignments),
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert len(findings) == 3
    assert {finding.detector for finding in findings} == {"broker_secret_assignment"}


def test_skips_known_broker_secret_reference_assignments(tmp_path):
    """Known Broker secret variables may point at Broker refs or same-name placeholders."""

    sample = tmp_path / "docker-compose.yml"
    sample.write_text(
        '\n'.join(
            [
                "BROKER_SECRET_KEY: secret://BROKER_SECRET_KEY",
                "SECURITY_WATCHDOG_GATE_TOKEN=BROKER_MCP_TOKEN",
                "UNRAID_DEPLOY_BROKER_TOKEN=${UNRAID_DEPLOY_BROKER_TOKEN}",
            ]
        ),
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_detects_dynamic_database_url_secret_assignments(tmp_path):
    """Stack-specific database URLs are treated as secrets when committed as concrete values."""

    sample = tmp_path / ".env"
    database_url = "".join(
        (
            "postgresql://watchdog:",
            "Hard",
            "Password123",
            "@postgres/security_watchdog",
        )
    )
    sample.write_text(
        "=".join(("APP_DATABASE_URL", database_url)) + "\n",
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert any(finding.detector == "generic_token_assignment" for finding in findings)


def test_secret_scanner_fixture_source_does_not_flag_itself():
    """Detector fixtures must not become deployment-blocking findings in this repository."""

    source_path = Path(__file__)

    findings = SecretScanner().scan_file(source_path, source_path.parent.parent)

    assert findings == []


def test_skips_code_identifiers_and_docker_paths(tmp_path):
    """Identifiers and package-install paths should not become entropy-only critical alerts."""

    sample = tmp_path / "Dockerfile"
    sample.write_text(
        "cache_entry = normalized_package_name\n"
        "RUN gpg --dearmor -o /usr/share/keyrings/trivy.gpg\n",
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_skips_high_entropy_noise_in_docs_paths(tmp_path):
    docs_path = tmp_path / "docs"
    docs_path.mkdir()
    sample = docs_path / "README.md"
    sample.write_text('api_key = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"\n', encoding="utf-8")

    findings = SecretScanner(entropy_threshold=3.5).scan_file(sample, tmp_path)

    assert not any(finding.detector == "high_entropy" for finding in findings)


def test_skips_binary_media_files(tmp_path):
    sample = tmp_path / "default-background.jpg"
    sample.write_bytes(b"\xff\xd8\xff\xe0binary-image-content")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_detects_secret_in_git_history(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    scanner = SecretScanner()
    history_value = "".join(("History_", "1234", "Abcd", "5678", "Value"))
    monkeypatch.setattr(
        scanner,
        "_iter_git_history_lines",
        lambda root_path: iter(
            [
                "__COMMIT__abc123def456\n",
                "diff --git a/.env b/.env\n",
                "+++ b/.env\n",
                "@@ -0,0 +1 @@\n",
                f'+API_KEY="{history_value}"\n',
            ]
        ),
    )

    findings = scanner.scan_git_history(repo)

    assert findings
    assert all(finding.content_source == "git_history" for finding in findings)
    assert any(finding.commit_sha == "abc123def456" for finding in findings)


def test_skips_entropy_only_findings_in_git_history(monkeypatch, tmp_path):
    """History scans should avoid entropy-only noise while keeping regex detectors active."""

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    scanner = SecretScanner(entropy_threshold=3.5)
    monkeypatch.setattr(
        scanner,
        "_iter_git_history_lines",
        lambda root_path: iter(
            [
                "__COMMIT__abc123def456\n",
                "diff --git a/app.py b/app.py\n",
                "+++ b/app.py\n",
                "@@ -0,0 +1 @@\n",
                '+headers = {"Authorization": "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"}\n',
            ]
        ),
    )

    findings = scanner.scan_git_history(repo)

    assert findings == []


def test_skips_git_history_findings_in_low_signal_paths(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    scanner = SecretScanner()
    monkeypatch.setattr(
        scanner,
        "_iter_git_history_lines",
        lambda root_path: iter(
            [
                "__COMMIT__abc123def456\n",
                "diff --git a/tests/test_secret_scanner.py b/tests/test_secret_scanner.py\n",
                "+++ b/tests/test_secret_scanner.py\n",
                "@@ -0,0 +1 @@\n",
                '+BROKER_MCP_TOKEN="MYTOKENVALUE123"\n',
            ]
        ),
    )

    findings = scanner.scan_git_history(repo)

    assert findings == []
