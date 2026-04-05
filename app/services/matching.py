"""
Purpose: Normalize ecosystem names and compare dependency versions against version hints.
Input/Output: Accepts package metadata from scanners or threat feeds and returns booleans/aliases.
Important invariants: Matching favors explainability over clever heuristics; exact or specifier-based
matches are preferred because false positives create noisy security alerts.
Debugging: If an alert should or should not have fired, test the relevant version string here first.
"""

from __future__ import annotations

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
            try:
                specifier = SpecifierSet(cleaned_constraint.replace(" ", ""))
                if Version(normalized_version) in specifier:
                    return True
            except (InvalidSpecifier, InvalidVersion):
                if cleaned_constraint == version or cleaned_constraint == normalized_version:
                    return True
            continue
        if normalize_version(cleaned_constraint) == normalized_version:
            return True
    return False
