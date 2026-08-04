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


def test_scan_image_uses_bounded_trivy_only_by_default(monkeypatch) -> None:
    """Default runtime image scans should avoid the slower secondary scanner."""

    commands: list[list[str]] = []

    def fake_run_command(command: list[str], **kwargs) -> str:
        commands.append(command)
        assert kwargs["timeout"] == 180
        return "{}"

    monkeypatch.setattr("app.scanners.container_scanner.run_command", fake_run_command)

    findings = ContainerScanner().scan_image("example/app:latest")

    assert findings == []
    assert commands == [["trivy", "image", "--scanners", "vuln", "--format", "json", "example/app:latest"]]


def test_scan_image_can_enable_optional_grype(monkeypatch) -> None:
    """Operators can opt into the slower secondary scanner for deep image reviews."""

    commands: list[tuple[list[str], int]] = []

    def fake_run_command(command: list[str], **kwargs) -> str:
        commands.append((command, kwargs["timeout"]))
        return "{}"

    monkeypatch.setattr("app.scanners.container_scanner.run_command", fake_run_command)

    scanner = ContainerScanner()
    scanner.grype_image_enabled = True
    scanner.grype_image_timeout_seconds = 240

    findings = scanner.scan_image("example/app:latest")

    assert findings == []
    assert commands == [
        (["trivy", "image", "--scanners", "vuln", "--format", "json", "example/app:latest"], 180),
        (["grype", "example/app:latest", "-o", "json"], 240),
    ]
