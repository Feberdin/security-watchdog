"""
Purpose: Verify regex and entropy-based secret detection behaves predictably on text files.
Input/Output: Writes small temporary files and checks the returned `SecretFinding` objects.
Important invariants: Findings must redact the preview and identify the detector used.
Debugging: If a detector becomes too noisy or too quiet, this file should fail in an obvious way.
"""

from __future__ import annotations

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

    findings = SecretScanner().scan_file(sample, tmp_path)

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


def test_skips_code_level_token_references(tmp_path):
    """Function calls and f-string references are not literal credentials."""

    sample = tmp_path / "client.py"
    sample.write_text(
        'token = self._validated_token()\n'
        "const browserToken = window.localStorage.getItem('paperless_worker_token') || '';\n"
        'auth_token=str(auth_token or "")\n'
        "ai_api_key = self.config.ai_api_key\n"
        'header = f"Bearer {token}"\n',
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_typed_source_assignments_use_the_real_right_hand_side(tmp_path):
    """Type annotations are code syntax; literal values still remain detectable."""

    sample = tmp_path / "settings.py"
    api_value = "".join(("Typed", "Signal_", "1234", "Abcd", "5678"))
    sample.write_text(
        "smtp_username: str = \"\"\n"
        "smtp_password: str = \"\"\n"
        "session_key: str = settings.session_key\n"
        f'api_key: str = "{api_value}"\n',
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assignment_findings = [
        finding for finding in findings if finding.detector == "generic_token_assignment"
    ]
    assert len(assignment_findings) == 1
    assert assignment_findings[0].line_number == 4


def test_embedded_scanner_fixtures_keep_provider_detectors_active(tmp_path):
    """Generic unit-test examples are ignored, but provider-shaped tokens are still findings."""

    tests_path = tmp_path / "tests"
    tests_path.mkdir()
    sample = tests_path / "test_secret_scanner.py"
    provider_value = "".join(("ghp_", "AbCdEf123456", "GhIjKl789012"))
    sample.write_text(
        "sample.write_text('api_key = \"config.live123\"\\n', encoding=\"utf-8\")\n"
        '    "BROKER_MCP_TOKEN=MYTOKENVALUE123",\n'
        f'    "AUTH_TOKEN={provider_value}",\n',
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert {finding.detector for finding in findings} == {"github_token"}
    assert findings[0].line_number == 3


def test_skips_business_key_values_and_code_expressions(tmp_path):
    """Business grouping keys and runtime expressions are not credential literals."""

    samples = {
        "app/services/inbox_cleanup_service.py": "normalized_key = validated_sender_group_key(sender_key)\n",
        "app/web/routes.py": "sender_key = validated_sender_group_key(form.sender_key)\n",
        "tests/test_inbox_cleanup_service.py": 'sender_key="email:person@gmail.com"\n',
    }
    for relative_path, content in samples.items():
        sample = tmp_path / relative_path
        sample.parent.mkdir(parents=True, exist_ok=True)
        sample.write_text(content, encoding="utf-8")

    findings = SecretScanner().scan_directory(tmp_path)

    assert findings == []


def test_detects_explicit_security_key_assignments(tmp_path):
    """Named API, private, encryption, signing, and session keys remain findings."""

    values = {
        "API_KEY": "".join(("Api", "Signal_", "1234", "Abcd", "5678")),
        "PRIVATE_KEY": "".join(("Private", "Signal_", "1234", "Abcd")),
        "ENCRYPTION_KEY": "".join(("Encrypt", "Signal_", "1234", "Abcd")),
        "SIGNING_KEY": "".join(("Signing", "Signal_", "1234", "Abcd")),
        "SESSION_KEY": "".join(("Session", "Signal_", "1234", "Abcd")),
    }
    sample = tmp_path / ".env"
    sample.write_text(
        "\n".join(f'{name}="{value}"' for name, value in values.items()),
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assignment_findings = [
        finding for finding in findings if finding.detector == "generic_token_assignment"
    ]
    assert len(assignment_findings) == len(values)


def test_detects_high_entropy_literal_for_generic_key_name(tmp_path):
    """A random-looking literal remains suspicious even when the `*_key` name is ambiguous."""

    sample = tmp_path / "settings.py"
    value = "".join(("Q7mP2xR9", "L4vN8cT1", "K6wD3sF5", "H2jB9zU4"))
    sample.write_text(f'sender_key = "{value}"\n', encoding="utf-8")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert any(finding.detector == "generic_token_assignment" for finding in findings)


def test_detects_quoted_dotted_literal_in_source_code(tmp_path):
    """A quoted dotted value is data, not a member reference, and must remain detectable."""

    sample = tmp_path / "client.py"
    sample.write_text('api_key = "config.live123"\n', encoding="utf-8")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert any(finding.detector == "generic_token_assignment" for finding in findings)


def test_skips_angle_bracket_documentation_placeholders(tmp_path):
    """README placeholders name required input without embedding a usable credential."""

    sample = tmp_path / "README.md"
    sample.write_text(
        "Paperless Token: <PAPERLESS_TOKEN>\nAI API Key: <OPENAI_API_KEY>\n",
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_skips_readable_token_slugs_only_in_low_signal_paths(tmp_path):
    """Human-readable fixture values should not block deploys, but production literals should."""

    tests_path = tmp_path / "tests"
    tests_path.mkdir()
    fixture = tests_path / "test_worker.py"
    fixture.write_text(
        'auth_token="worker-review-token"\npaperless_token="token-123"\n',
        encoding="utf-8",
    )
    production = tmp_path / ".env"
    production.write_text("AUTH_TOKEN=worker-review-token\n", encoding="utf-8")

    assert SecretScanner().scan_file(fixture, tmp_path) == []
    assert SecretScanner().scan_file(production, tmp_path)


def test_token_count_configuration_is_not_a_secret_name(tmp_path):
    """Plural token counters and pricing constants describe units rather than credentials."""

    sample = tmp_path / "runner.py"
    sample.write_text(
        "input_cost_per_1k_tokens_eur = DEFAULT_INPUT_COST_PER_1K_TOKENS_EUR\n"
        "self.min_remaining_tokens = config.min_remaining_tokens\n",
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_detects_high_signal_token_in_test_path(tmp_path):
    """Low-signal paths must not suppress a provider-shaped credential."""

    tests_path = tmp_path / "tests"
    tests_path.mkdir()
    sample = tests_path / "fixture.py"
    value = "".join(("ghp_", "AbCdEf123456", "GhIjKl789012"))
    sample.write_text(f'auth_token="{value}"\n', encoding="utf-8")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert any(finding.detector == "github_token" for finding in findings)


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
    sample.write_text(
        '\n'.join(
                [
                    "BROKER_MCP_TOKEN=MYTOKENVALUE123",
                    "BITWARDEN_SERVER_URL=https://vault.internal.lan",
                    "NTFY_TOPIC=prod-alerts",
                ]
            ),
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
    sample.write_text(
        "APP_DATABASE_URL=postgresql://watchdog:HardPassword123@postgres/security_watchdog\n",
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert any(finding.detector == "generic_token_assignment" for finding in findings)


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
    value = "".join(("A1B2C3D4", "E5F6G7H8", "I9J0K1L2", "M3N4O5P6"))
    sample.write_text(f'api_key = "{value}"\n', encoding="utf-8")

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


def test_skips_business_key_values_and_code_expressions_in_git_history(monkeypatch, tmp_path):
    """The same non-secret rules apply to added lines from historical commits."""

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    scanner = SecretScanner()
    monkeypatch.setattr(
        scanner,
        "_iter_git_history_lines",
        lambda root_path: iter(
            [
                "__COMMIT__abc123def456\n",
                "diff --git a/app/services/inbox_cleanup_service.py b/app/services/inbox_cleanup_service.py\n",
                "+++ b/app/services/inbox_cleanup_service.py\n",
                "@@ -0,0 +362 @@\n",
                "+normalized_key = validated_sender_group_key(sender_key)\n",
                "diff --git a/app/web/routes.py b/app/web/routes.py\n",
                "+++ b/app/web/routes.py\n",
                "@@ -0,0 +1240 @@\n",
                "+sender_key = validated_sender_group_key(form.sender_key)\n",
                "diff --git a/tests/test_inbox_cleanup_service.py b/tests/test_inbox_cleanup_service.py\n",
                "+++ b/tests/test_inbox_cleanup_service.py\n",
                "@@ -0,0 +253 @@\n",
                '+sender_key="email:person@gmail.com"\n',
            ]
        ),
    )

    findings = scanner.scan_git_history(repo)

    assert findings == []


def test_history_skips_scanner_fixtures_and_typed_empty_defaults_but_keeps_provider_tokens(
    monkeypatch,
    tmp_path,
):
    """Historical generic fixtures resolve without suppressing strong provider evidence."""

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    provider_value = "".join(("ghp_", "AbCdEf123456", "GhIjKl789012"))

    scanner = SecretScanner()
    monkeypatch.setattr(
        scanner,
        "_iter_git_history_lines",
        lambda root_path: iter(
            [
                "__COMMIT__abc123def456\n",
                "diff --git a/tests/test_secret_scanner.py b/tests/test_secret_scanner.py\n",
                "+++ b/tests/test_secret_scanner.py\n",
                "@@ -0,0 +1,3 @@\n",
                "+sample.write_text('api_key = \"config.live123\"\\n', encoding=\"utf-8\")\n",
                '+    "BROKER_MCP_TOKEN=MYTOKENVALUE123",\n',
                f'+    "AUTH_TOKEN={provider_value}",\n',
                "diff --git a/app/core/config.py b/app/core/config.py\n",
                "+++ b/app/core/config.py\n",
                "@@ -0,0 +1,2 @@\n",
                '+smtp_username: str = ""\n',
                '+smtp_password: str = ""\n',
            ]
        ),
    )

    findings = scanner.scan_git_history(repo)

    assert {finding.detector for finding in findings} == {"github_token"}
    assert findings[0].content_source == "git_history"
