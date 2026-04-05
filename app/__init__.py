"""
Purpose: Mark the application package and expose the semantic version in one place.
Input/Output: Imported by runtime entry points and packaging tools; exports `__version__`.
Important invariants: Keep this file side-effect free so imports never start network or DB work.
Debugging: If version metadata looks wrong, inspect this file first before checking Docker labels.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
