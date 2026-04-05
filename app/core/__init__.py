"""
Purpose: Group shared runtime utilities that are reused across API, worker, and scanners.
Input/Output: Pure package marker; no runtime side effects.
Important invariants: Shared helpers should stay framework-agnostic where possible.
Debugging: If imports fail early, start by confirming this package exists and is on PYTHONPATH.
"""
