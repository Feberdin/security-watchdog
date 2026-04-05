"""
Purpose: Convert raw vulnerability traits into explainable risk scores and severity bands.
Input/Output: Accepts normalized vulnerability metadata and returns a `RiskScore`.
Important invariants: Scores stay within 0-100 and always include plain-language reasons so alerts
can explain themselves to operators who are not security specialists.
Debugging: If a score looks unintuitive, inspect the `reasons` list before changing the formula.
"""

from __future__ import annotations

from app.models.schemas import RiskScore


def calculate_risk_score(
    *,
    cvss_score: float | None,
    kev: bool,
    exploit_available: bool,
    malicious_package: bool,
) -> RiskScore:
    """Calculate a deterministic, explainable risk score."""

    score = min(max(cvss_score or 0.0, 0.0), 10.0) * 6
    reasons: list[str] = []

    if cvss_score is not None:
        reasons.append(f"CVSS base score {cvss_score}")
    if kev:
        score += 20
        reasons.append("Listed in CISA KEV")
    if exploit_available:
        score += 12
        reasons.append("Exploit or weaponization signal detected")
    if malicious_package:
        score += 18
        reasons.append("Package is flagged as malicious or compromised")

    score = min(score, 100.0)
    if score >= 90:
        severity = "critical"
    elif score >= 70:
        severity = "high"
    elif score >= 40:
        severity = "medium"
    else:
        severity = "low"

    return RiskScore(score=round(score, 2), severity=severity, reasons=reasons or ["No risk signals"])
