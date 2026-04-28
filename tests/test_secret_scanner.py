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
    sample.write_text('password = "SuperSecretDemo123!"\n', encoding="utf-8")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert findings
    assert findings[0].detector == "generic_password"
    assert "..." in findings[0].excerpt


def test_detects_high_entropy_string(tmp_path):
    sample = tmp_path / "settings.txt"
    sample.write_text('api_key = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"\n', encoding="utf-8")

    findings = SecretScanner(entropy_threshold=3.5).scan_file(sample, tmp_path)

    assert any(finding.detector == "high_entropy" for finding in findings)


def test_detects_generic_api_key_assignment_without_quotes(tmp_path):
    sample = tmp_path / ".env"
    sample.write_text("API_KEY=DemoSignal_1234Abcd5678Value\n", encoding="utf-8")

    findings = SecretScanner().scan_file(sample, tmp_path)

    assert any(finding.detector == "generic_token_assignment" for finding in findings)


def test_skips_environment_reference_assignments(tmp_path):
    sample = tmp_path / ".env.example"
    sample.write_text("API_KEY=process.env.OPENAI_API_KEY\n", encoding="utf-8")

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
    monkeypatch.setattr(
        scanner,
        "_iter_git_history_lines",
        lambda root_path: iter(
            [
                "__COMMIT__abc123def456\n",
                "diff --git a/.env b/.env\n",
                "+++ b/.env\n",
                "@@ -0,0 +1 @@\n",
                '+API_KEY="DemoHistory_1234Abcd5678Value"\n',
            ]
        ),
    )

    findings = scanner.scan_git_history(repo)

    assert findings
    assert all(finding.content_source == "git_history" for finding in findings)
    assert any(finding.commit_sha == "abc123def456" for finding in findings)
