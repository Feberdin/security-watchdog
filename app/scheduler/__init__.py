"""
Purpose: Package marker for background job scheduling helpers.
Input/Output: No side effects.
Important invariants: Scheduling should only happen in the worker process.
Debugging: If jobs appear to run twice, verify only one worker imports this package at runtime.
"""
