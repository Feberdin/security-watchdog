"""
Purpose: Verify container scanner command construction without running heavy external scanners.
Input/Output: Creates temporary Dockerfiles and monkeypatches command execution.
Important invariants: Dockerfile scans run with the Dockerfile directory as cwd, so the command
must pass a path relative to that cwd to avoid duplicated paths inside Trivy.
Debugging: If Trivy logs `lstat ... no such file or directory`, inspect this test and
`ContainerScanner.scan_dockerfile()` together.
"""

from __future__ import annotations

from pathlib import Path

from app.scanners.container_scanner import ContainerScanner


def test_scan_dockerfile_uses_filename_relative_to_working_directory(tmp_path, monkeypatch) -> None:
    """Trivy should receive `Dockerfile` when cwd already points at the Dockerfile directory."""

    dockerfile_path = tmp_path / "service" / "Dockerfile"
    dockerfile_path.parent.mkdir()
    dockerfile_path.write_text("FROM python:3.12-slim\n", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_run_command(command: list[str], **kwargs) -> str:
        captured["command"] = command
        captured["cwd"] = kwargs["cwd"]
        return "{}"

    monkeypatch.setattr("app.scanners.container_scanner.run_command", fake_run_command)

    findings = ContainerScanner().scan_dockerfile(dockerfile_path)

    assert findings == []
    assert captured["command"] == ["trivy", "config", "--format", "json", "Dockerfile"]
    assert captured["cwd"] == Path(dockerfile_path.parent)
