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
    sample.write_text("payload = A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6\n", encoding="utf-8")

    findings = SecretScanner(entropy_threshold=3.5).scan_file(sample, tmp_path)

    assert any(finding.detector == "high_entropy" for finding in findings)
