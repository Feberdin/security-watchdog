"""
Purpose: Group all scanner modules that collect evidence from code, containers, and platforms.
Input/Output: Package marker only; real logic lives in the scanner modules below.
Important invariants: Scanner modules should focus on collection and normalization, not alerting.
Debugging: If one source stops yielding findings, inspect the corresponding scanner first.
"""
