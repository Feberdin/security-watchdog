"""
Purpose: Verify version matching and risk scoring for correlation logic.
Input/Output: Exercises pure helper functions with deterministic inputs.
Important invariants: Version matches should remain explainable and risk scores should stay bounded.
Debugging: If alert severity changes unexpectedly, start with these unit tests.
"""

from __future__ import annotations

from app.services.matching import version_matches
from app.services.risk import calculate_risk_score


def test_version_matches_specifier_range():
    assert version_matches("1.2.5", [">=1.2.0,<1.3.0"])


def test_version_does_not_match_different_exact_version():
    assert not version_matches("1.2.5", ["1.2.4"])


def test_risk_score_prioritizes_kev_and_exploit_signals():
    risk = calculate_risk_score(
        cvss_score=8.8,
        kev=True,
        exploit_available=True,
        malicious_package=False,
    )

    assert risk.score > 80
    assert risk.severity in {"high", "critical"}
    assert "Listed in CISA KEV" in risk.reasons
