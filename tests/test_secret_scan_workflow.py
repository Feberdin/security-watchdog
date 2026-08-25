"""Contract test for the portfolio-wide reusable Gitleaks workflow.

Purpose: Prevent accidental removal, mutable action references, or over-broad permissions.
Input/Output: Reads the tracked workflow and asserts its immutable security contract.
Invariants: Pushes, pull requests, and cross-repository callers use the same pinned scanner.
Debugging: Run `pytest tests/test_secret_scan_workflow.py -q` from the repository root.
"""

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "reusable-secret-scan.yml"


def test_reusable_secret_scan_has_pinned_read_only_contract() -> None:
    """Require immutable actions, minimal permissions, and every supported trigger."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    required_fragments = (
        "workflow_call:",
        "push:",
        "pull_request:",
        "contents: read",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e",
        'GITLEAKS_VERSION: "8.30.1"',
        "GITHUB_TOKEN: ${{ github.token }}",
        'GITLEAKS_ENABLE_COMMENTS: "false"',
        'GITLEAKS_ENABLE_UPLOAD_ARTIFACT: "false"',
    )

    for fragment in required_fragments:
        assert fragment in workflow
