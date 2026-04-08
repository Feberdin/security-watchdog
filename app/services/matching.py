"""
Purpose: Normalize ecosystem names and compare dependency versions against version hints.
Input/Output: Accepts package metadata from scanners or threat feeds and returns booleans/aliases.
Important invariants: Matching favors explainability over clever heuristics; exact or specifier-based
matches are preferred because false positives create noisy security alerts.
Debugging: If an alert should or should not have fired, test the relevant version string here first.
"""

from __future__ import annotations

import re

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

ECOSYSTEM_ALIASES = {
    "pypi": {"osv": "PyPI", "github": "pip"},
    "npm": {"osv": "npm", "github": "npm"},
    "maven": {"osv": "Maven", "github": "maven"},
    "gradle": {"osv": "Maven", "github": "maven"},
    "packagist": {"osv": "Packagist", "github": "composer"},
    "crates.io": {"osv": "crates.io", "github": "rust"},
    "go": {"osv": "Go", "github": "go"},
    "docker": {"osv": "OSS-Fuzz", "github": "docker"},
}

NON_ACTIONABLE_VERSIONS = {"", "latest", "unspecified", "*"}


def normalize_ecosystem_for_source(ecosystem: str, source: str) -> str:
    """Map internal ecosystem names to vendor-specific identifiers."""

    return ECOSYSTEM_ALIASES.get(ecosystem, {}).get(source, ecosystem)


def normalize_version(value: str) -> str:
    """Trim common prefixes so specifier comparison works more often."""

    cleaned = value.strip()
    for prefix in ("==", ">=", "<=", "~=", "!=", "=", "v"):
        if cleaned.startswith(prefix):
            cleaned = cleaned.removeprefix(prefix)
    return cleaned.strip()


def is_exact_version(value: str) -> bool:
    """
    Return True when a dependency string represents one concrete installed version.

    Why this exists:
    Manifest constraints such as `>=1.2,<2.0` or `^7.0.0` are useful for upgrade visibility, but
    they are not proof that the running or locked dependency is vulnerable. Correlation should be
    conservative and prefer exact versions to avoid false positives.
    """

    cleaned = value.strip()
    if cleaned.lower() in NON_ACTIONABLE_VERSIONS:
        return False
    if "||" in cleaned or "," in cleaned or "*" in cleaned:
        return False
    if cleaned.startswith((">=", "<=", ">", "<", "!=", "~=", "^", "~")):
        return False
    normalized = normalize_version(cleaned)
    if not normalized:
        return False
    try:
        Version(normalized)
    except InvalidVersion:
        return False
    return True


def is_constraint_version(value: str) -> bool:
    """Return True when a dependency string is a range, selector, or non-concrete placeholder."""

    return not is_exact_version(value)


def version_matches(version: str, constraints: list[str]) -> bool:
    """Return True when a concrete version matches at least one constraint."""

    normalized_version = normalize_version(version)
    if not constraints:
        return False
    for constraint in constraints:
        if not constraint:
            continue
        cleaned_constraint = constraint.strip()
        if cleaned_constraint.endswith("*"):
            if normalized_version.startswith(cleaned_constraint[:-1]):
                return True
            continue
        if any(cleaned_constraint.startswith(prefix) for prefix in (">", "<", "=", "!", "~")):
            if _specifier_constraint_matches(normalized_version, cleaned_constraint):
                return True
            continue
        if normalize_version(cleaned_constraint) == normalized_version:
            return True
    return False


def _specifier_constraint_matches(version: str, constraint: str) -> bool:
    """
    Evaluate one specifier expression against a concrete version.

    Example inputs:
    - version=`1.2.5`, constraint=`>=1.2.0,<1.3.0`
    - version=`0.28.1`, constraint=`<0.29.0 || >=0.30.0,<0.30.2`
    """

    for expression in _split_constraint_expressions(constraint):
        try:
            specifier = SpecifierSet(expression)
            if Version(version) in specifier:
                return True
        except (InvalidSpecifier, InvalidVersion):
            if normalize_version(expression) == version:
                return True
    return False


def _split_constraint_expressions(constraint: str) -> list[str]:
    """Normalize common multi-part comparator formats into packaging-compatible expressions."""

    expressions: list[str] = []
    for raw_expression in constraint.split("||"):
        expression = raw_expression.strip()
        if not expression:
            continue
        expression = re.sub(r"([<>=!~]+)\s+", r"\1", expression)
        expression = re.sub(r"\s+(?=[<>=!~])", ",", expression)
        expression = expression.replace(" ", "")
        if expression:
            expressions.append(expression)
    return expressions
