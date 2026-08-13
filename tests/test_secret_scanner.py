"""
Purpose: Verify regex and entropy-based secret detection behaves predictably on text files.
Input/Output: Writes small temporary files and checks the returned `SecretFinding` objects.
Important invariants: Findings must redact the preview and identify the detector used.
Debugging: If a detector becomes too noisy or too quiet, this file should fail in an obvious way.
"""

from __future__ import annotations

import base64

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


def test_skips_broker_source_metadata_and_runtime_references(tmp_path):
    """Broker help maps, type hints, role labels, and UI member access are not credentials."""

    samples = {
        "src/broker/auth.py": (
            'AUTOMATIC_READ_TOKENS = {\n'
            '    "BROKER_DOCKER_CONSUMERS_TOKEN": "docker-consumers-read",\n'
            '    "UNRAID_DEPLOY_BROKER_TOKEN": "deployment-broker-read",\n'
            "}\n"
        ),
        "src/broker/config.py": (
            '"""Example config:\n'
            '  ntfy_topic: "my-private-topic"\n'
            '"""\n'
            "ntfy_topic: str | None = None\n"
            'smtp_username: str = ""\n'
            'smtp_password: str = ""\n'
            "auth: AuthConfig = Field(default_factory=AuthConfig)\n"
        ),
        "src/broker/service.py": (
            "def configure(bitwarden_server_url: str | None = None):\n"
            "    reasons = {\n"
            '        "BITWARDEN_CLIENT_SECRET": '
            '"Vaultwarden client secret requested through the secure Broker flow.",\n'
            "    }\n"
        ),
        "src/broker/client.py": "connect(client_secret=client_secret)\n",
        "src/broker/static/admin.html": (
            "const payload = {\n"
            "  database_url_secret_name: item.name,\n"
            "  approval_token: approval.approval_token,\n"
            "};\n"
        ),
    }
    for relative_path, content in samples.items():
        sample = tmp_path / relative_path
        sample.parent.mkdir(parents=True, exist_ok=True)
        sample.write_text(content, encoding="utf-8")

    findings = SecretScanner().scan_directory(tmp_path)

    assert findings == []


def test_skips_readable_source_prefix_metadata_but_detects_random_secret(tmp_path):
    """Protocol labels are metadata; a random session secret in the same source remains blocked."""

    sample = tmp_path / "src" / "auth.py"
    sample.parent.mkdir(parents=True)
    random_secret = "".join(("Q7mP2xR9", "L4vN8cT1", "K6wD3sF5", "H2jB9zU4"))
    sample.write_text(
        'SEALED_SECRET_PREFIX = "sealed-v1"\n'
        f'SESSION_SECRET = "{random_secret}"\n',
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert not any(finding.line_number == 1 for finding in findings)
    assert any(
        finding.line_number == 2 and finding.detector == "generic_token_assignment"
        for finding in findings
    )


def test_playwright_config_suppresses_synthetic_credentials_not_provider_tokens(tmp_path):
    """Root Playwright configs are fixtures, but provider-shaped tokens remain high signal."""

    sample = tmp_path / "playwright.auth.config.ts"
    provider_token = "".join(("ghp_", "AbCdEf123456", "GhIjKl789012"))
    sample.write_text(
        'const INITIAL_ADMIN_PASSWORD = "test-admin-password";\n'
        'const SESSION_SECRET = "test-session-secret";\n'
        f'const AUTH_TOKEN = "{provider_token}";\n',
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert not any(finding.line_number in {1, 2} for finding in findings)
    assert any(
        finding.line_number == 3 and finding.detector == "github_token"
        for finding in findings
    )


def test_mjs_local_auth_paths_are_source_code_not_entropy_findings(tmp_path):
    """Local storage-state paths in Node scripts must not look like credentials."""

    sample = tmp_path / "scripts" / "capture-production-auth-state.mjs"
    sample.parent.mkdir(parents=True)
    sample.write_text(
        'const storageStatePath = ".auth/autobroker-production.json";\n'
        'const proofPath = ".auth/autobroker-production-proof.json";\n',
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_skips_annotation_only_secret_named_dataclass_fields(tmp_path):
    """Type declarations without assigned values must not become credential findings."""

    sample = tmp_path / "app" / "tax_export.py"
    sample.parent.mkdir(parents=True)
    sample.write_text(
        "from dataclasses import dataclass\n\n"
        "@dataclass\n"
        "class TaxExportConfig:\n"
        "    smtp_username: str | None\n"
        "    smtp_password: str | None\n",
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_skips_source_routes_identifiers_and_asset_paths_in_entropy_scan(tmp_path):
    """Secret-related route names and code identifiers must not become entropy-only alerts."""

    samples = {
        "src/broker/api.py": (
            '@app.post("/admin/api/security-gate/override", '
            "dependencies=[Depends(auth.require_bearer)])\n"
            'description = "Broker-Einmalplan-mit-Sicherheits-Pruefung"\n'
        ),
        "src/broker/backup.py": (
            'warnings.append("BROKER_ASSET_DIR/default-background.png")\n'
        ),
        "src/broker/generator.py": (
            'return Decision(True, "generated_secret_value_format", 32)\n'
        ),
        "src/broker/static/admin.html": (
            "await copySecretFromExistingRequest(item, selector.value);\n"
            "const count = duplicateSummary.same_value_group_count;\n"
        ),
    }
    for relative_path, content in samples.items():
        sample = tmp_path / relative_path
        sample.parent.mkdir(parents=True, exist_ok=True)
        sample.write_text(content, encoding="utf-8")

    findings = SecretScanner().scan_directory(tmp_path)

    assert findings == []


def test_skips_paths_and_config_key_prefixes_in_non_source_entropy_scan(tmp_path):
    """Generated metadata may mention secret words next to paths and config key prefixes."""

    samples = {
        "example.env": (
            "DATABASE_URL=postgresql://app:password@postgres:5432/app\n"
        ),
        "scripts/fix-markers.json": (
            '{"token_source": "docs/integration/example.md"}\n'
        ),
        ".claude-flow/metrics/security-audit.json": (
            '{"secret_scanner": ".claude/helpers/validate.js"}\n'
        ),
        "scripts/homecore-seed.sh": (
            'printf "%s" "$HOMECORE_BEARER_TOKEN"\n'
        ),
    }
    for relative_path, content in samples.items():
        sample = tmp_path / relative_path
        sample.parent.mkdir(parents=True, exist_ok=True)
        sample.write_text(content, encoding="utf-8")

    findings = SecretScanner().scan_directory(tmp_path)

    assert findings == []


def test_skips_obvious_documentation_credentials_but_keeps_random_literals(tmp_path):
    """Readable docs examples are safe; a random literal in the same file remains actionable."""

    sample = tmp_path / "archive" / "v1" / "docs" / "integration" / "README.md"
    sample.parent.mkdir(parents=True)
    random_value = "".join(("Live", "Signal_", "1234", "Abcd", "5678", "Value"))
    sample.write_text(
        "PASSWORD=SecurePass123!\n"
        "DATABASE_URL=postgresql+asyncpg://app:password@postgres:5432/app\n"
        f'API_KEY="{random_value}"\n',
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert not any(finding.line_number in {1, 2} for finding in findings)
    assert any(
        finding.line_number == 3 and finding.detector == "generic_token_assignment"
        for finding in findings
    )


def test_skips_explicit_test_tokens_and_local_fixture_urls(tmp_path):
    """Reserved test endpoints and readable fixture credentials do not block deployments."""

    tests_path = tmp_path / "tests"
    tests_path.mkdir()
    (tests_path / "test_auth.py").write_text(
        'context = auth.authenticate("Bearer consumer-access-token")\n'
        'url = "https://user:pass@broker.test/path"\n'
        'bitwarden_server_url = "http://vaultwarden.internal:8080"\n',
        encoding="utf-8",
    )
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("BROKER_MCP_TOKEN: test-token\n", encoding="utf-8")

    findings = SecretScanner().scan_directory(tmp_path)

    assert findings == []


def test_detects_random_literal_in_source_secret_mapping(tmp_path):
    """Source-code metadata filtering must not hide credential-shaped mapping values."""

    sample = tmp_path / "src" / "broker" / "config.py"
    sample.parent.mkdir(parents=True)
    value = "".join(("Live", "Signal_", "1234", "Abcd", "5678", "Value"))
    sample.write_text(
        "CONFIG = {\n"
        f'    "BROKER_MCP_TOKEN": "{value}",\n'
        "}\n",
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert any(finding.detector == "broker_secret_assignment" for finding in findings)


def test_detects_generic_secret_literal_in_documentation(tmp_path):
    """README files are not fixtures; realistic literal credentials must remain actionable."""

    sample = tmp_path / "README.md"
    value = "".join(("Live", "Signal_", "1234", "Abcd", "5678", "Value"))
    sample.write_text(f'API_KEY="{value}"\n', encoding="utf-8")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert any(finding.detector == "generic_token_assignment" for finding in findings)


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
        "Paperless Token: <PAPERLESS_TOKEN>\n"
        "AI API Key: <OPENAI_API_KEY>\n"
        'BROKER_MCP_TOKEN="..."\n',
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings == []


def test_markdown_placeholder_punctuation_does_not_hide_or_invent_secrets(tmp_path):
    """
    Inline-code punctuation must not turn an uppercase placeholder into a finding.

    The second line is a negative control: a plausible mixed-class literal remains detectable
    after the same Markdown wrapper is removed.
    """

    docs_path = tmp_path / "docs"
    docs_path.mkdir()
    sample = docs_path / "jellyfin-setup.md"
    sample.write_text(
        "Set URL to `http://WATCHLOG_HOST:8111/api/webhooks/jellyfin?secret=WEBHOOK_SECRET`.\n"
        "Unsafe example: `http://watchlog.local/api/webhooks/jellyfin?secret=LiveSignal_1234Abcd5678Value`.\n",
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert not any(finding.line_number == 1 for finding in findings)
    assert any(
        finding.line_number == 2 and finding.detector == "generic_token_assignment"
        for finding in findings
    )


def test_markdown_placeholder_in_source_docstring_is_not_a_secret(tmp_path):
    """The same presentation punctuation is harmless inside source documentation."""

    sample = tmp_path / "runtime_config.py"
    sample.write_text(
        '"""Use an uppercase query-string placeholder followed by inline-code punctuation."""\n'
        'EXAMPLE = "?secret=WEBHOOK_SECRET`."\n',
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


def test_skips_structural_provider_placeholders_in_low_signal_paths(tmp_path):
    """Alphabet keys, printable example bearer values, and key markers are fixtures, not leaks."""

    openai_placeholder = "".join(("sk-", "abcdefghijklmnop", "qrstuv12"))
    bearer_placeholder = base64.urlsafe_b64encode(b"example bearer credential").decode("ascii")
    samples = {
        "examples/client.py": f'api_key = "{openai_placeholder}"\n',
        "examples/http_server.rs": f'let header = "Bearer {bearer_placeholder}";\n',
        "validation/security_validation.rs": (
            'let marker = "' + "-----BEGIN " + 'PRIVATE KEY-----";\n'
        ),
    }
    for relative_path, content in samples.items():
        sample = tmp_path / relative_path
        sample.parent.mkdir(parents=True, exist_ok=True)
        sample.write_text(content, encoding="utf-8")

    findings = SecretScanner().scan_directory(tmp_path)

    assert findings == []


def test_keeps_random_openai_signature_in_low_signal_path(tmp_path):
    """Alphabet placeholders are ignored, but a random provider-shaped key still blocks."""

    sample = tmp_path / "examples" / "client.py"
    sample.parent.mkdir(parents=True)
    random_provider_value = "".join(("sk-", "Z7mP2xR9", "L4vN8cT1", "K6wD3sF5"))
    sample.write_text(f'api_key = "{random_provider_value}"\n', encoding="utf-8")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert any(finding.detector == "openai_key" for finding in findings)


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


def test_skips_generated_rust_and_vite_trees(tmp_path):
    """Generated dependency metadata must not drown out actionable repository findings."""

    target_file = tmp_path / "v2" / "target" / "debug" / "deps" / "crate.d"
    vite_file = tmp_path / "ui" / ".vite" / "deps" / "bundle.js.map"
    for path in (target_file, vite_file):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('api_key="LiveSignal_1234Abcd5678Value"\n', encoding="utf-8")

    assert SecretScanner().scan_directory(tmp_path) == []


def test_skips_generated_paths_in_git_history(monkeypatch, tmp_path):
    """The generated-directory exclusion also applies to files that only exist in history."""

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    scanner = SecretScanner()
    monkeypatch.setattr(
        scanner,
        "_iter_git_history_lines",
        lambda root_path: iter(
            [
                "__COMMIT__abc123def456\n",
                "diff --git a/v2/target/debug/deps/crate.d b/v2/target/debug/deps/crate.d\n",
                "+++ b/v2/target/debug/deps/crate.d\n",
                "@@ -0,0 +1 @@\n",
                '+API_KEY="LiveSignal_1234Abcd5678Value"\n',
                "diff --git a/ui/.vite/deps/bundle.js.map b/ui/.vite/deps/bundle.js.map\n",
                "+++ b/ui/.vite/deps/bundle.js.map\n",
                "@@ -0,0 +1 @@\n",
                '+API_KEY="LiveSignal_1234Abcd5678Value"\n',
            ]
        ),
    )

    assert scanner.scan_git_history(repo) == []


def test_skips_unquoted_terraform_and_rust_references(tmp_path):
    """Typed fields and runtime references name value sources; they are not literal credentials."""

    terraform = tmp_path / "terraform" / "main.tf"
    terraform.parent.mkdir()
    terraform.write_text(
        "password = random_password.database.result\n"
        "auth_token = module.identity.auth_token\n",
        encoding="utf-8",
    )
    rust = tmp_path / "src" / "config.rs"
    rust.parent.mkdir()
    rust.write_text(
        "    pub token: Option<String>,\n"
        "    let password = HeaderValue::from_str(config.password.as_str());\n",
        encoding="utf-8",
    )

    assert SecretScanner().scan_directory(tmp_path) == []


def test_rust_scoped_token_variants_are_not_assignments(tmp_path):
    """The first colon in Rust's `Type::Variant` syntax is not a key/value separator."""

    rust = tmp_path / "src" / "parser.rs"
    rust.parent.mkdir()
    rust.write_text(
        "match input {\n"
        "    'x' => Ok(Token::Identifier),\n"
        "    _ => Ok(Password::Missing),\n"
        "}\n",
        encoding="utf-8",
    )

    assert SecretScanner().scan_file(rust, tmp_path) == []


def test_generated_provider_placeholders_do_not_hide_real_provider_tokens(tmp_path):
    """Repeated-x examples are harmless, while realistic provider-shaped values still alert."""

    sample = tmp_path / ".env.example"
    openai_placeholder = "".join(("sk-", "x" * 21))
    slack_placeholder = "".join(("xoxb-", "x" * 21))
    real_token = "".join(("xoxb-", "AbCdEf123456", "GhIjKl789012"))
    sample.write_text(
        f"OPENAI_API_KEY={openai_placeholder}\n"
        f"SLACK_BOT_TOKEN={slack_placeholder}\n"
        f"LEAKED_SLACK_TOKEN={real_token}\n",
        encoding="utf-8",
    )

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert not any(finding.line_number in {1, 2} for finding in findings)
    assert any(
        finding.line_number == 3 and finding.detector == "slack_token"
        for finding in findings
    )


def test_provider_placeholder_inside_source_string_is_not_a_history_leak(tmp_path):
    """An escaped newline after a repeated-x example must not turn it into a provider leak."""

    source = tmp_path / "tests" / "test_docs.py"
    source.parent.mkdir()
    openai_placeholder = "".join(("sk-", "x" * 21))
    source.write_text(
        f'EXAMPLE = "OPENAI_API_KEY={openai_placeholder}\\n"\n',
        encoding="utf-8",
    )

    assert SecretScanner().scan_file(source, tmp_path) == []


def test_readable_dotted_placeholder_is_low_signal_only(tmp_path):
    """Dotted prose placeholders are safe in docs but the same literal is suspicious in config."""

    docs = tmp_path / "docs" / "api.md"
    docs.parent.mkdir()
    docs.write_text("token=replace.with.credential\n", encoding="utf-8")
    production = tmp_path / ".env"
    production.write_text("TOKEN=replace.with.credential\n", encoding="utf-8")

    assert SecretScanner().scan_file(docs, tmp_path) == []
    assert SecretScanner().scan_file(production, tmp_path)


def test_skips_truncated_tokens_and_named_key_placeholders(tmp_path):
    """Documentation truncation and key-type labels do not contain usable credentials."""

    docs = tmp_path / "docs" / "api.md"
    docs.parent.mkdir()
    docs.write_text(
        'access_token: "eyJhbGciOiJIUzI1NiJ9..."\n'
        'private_key_hex: "ed25519_private_key"\n'
        'signing_key_id: "ed25519:ruv-signing-v1"\n',
        encoding="utf-8",
    )

    assert SecretScanner().scan_file(docs, tmp_path) == []


def test_dry_run_token_is_safe_but_production_slug_stays_actionable(tmp_path):
    """An explicit dry-run sentinel is harmless; production config keeps the stricter policy."""

    script = tmp_path / "publish.py"
    script.write_text('token = "dry-run-no-token-needed"\n', encoding="utf-8")
    production = tmp_path / ".env"
    production.write_text("TOKEN=worker-review-token\n", encoding="utf-8")

    assert SecretScanner().scan_file(script, tmp_path) == []
    assert SecretScanner().scan_file(production, tmp_path)


def test_entropy_filter_skips_paths_and_cli_secret_names(tmp_path):
    """Paths and secret-name arguments are identifiers, while random literals still alert."""

    docs = tmp_path / "audit.json"
    docs.write_text('"route": "/broker/security/alerts/list"\n', encoding="utf-8")
    makefile = tmp_path / "Makefile"
    makefile.write_text(
        "command --secret=COGNITUM_OWNER_SIGNING_KEY\n",
        encoding="utf-8",
    )
    production = tmp_path / ".env"
    random_value = "".join(("Q7mP2xR9", "L4vN8cT1", "K6wD3sF5", "H2jB9zU4"))
    production.write_text(f"UNRELATED_SECRET={random_value}\n", encoding="utf-8")

    assert SecretScanner(entropy_threshold=3.5).scan_file(docs, tmp_path) == []
    assert SecretScanner(entropy_threshold=3.5).scan_file(makefile, tmp_path) == []
    assert SecretScanner(entropy_threshold=3.5).scan_file(production, tmp_path)
