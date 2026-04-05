"""
Purpose: Group ORM entities and Pydantic schemas under a predictable import path.
Input/Output: Pure package marker with no side effects.
Important invariants: Keep imports explicit in entry points to avoid accidental circular imports.
Debugging: If a type is not found, verify whether it belongs to entities or schemas.
"""
