"""
Purpose: Authenticate machine-to-machine API calls without exposing credential values.
Input/Output: Reads an HTTP Bearer token and either authorizes the request or raises a safe error.
Important invariants: Missing server configuration fails closed; token comparisons are constant-time.
Debugging: A 503 means the server token is not configured, while a 401 means the caller credential
is missing or invalid. Never log or return the credential itself.
"""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Settings, get_settings

deployment_gate_bearer = HTTPBearer(auto_error=False)


def require_deployment_gate_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(deployment_gate_bearer),
    settings: Settings = Depends(get_settings),
) -> None:
    """Require the dedicated Deployment Broker credential for security-gate requests."""

    configured_token = settings.deployment_gate_token
    if not configured_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Deployment security gate is not configured. "
                "Set DEPLOYMENT_GATE_TOKEN through the secure Broker secret flow."
            ),
        )

    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or not secrets.compare_digest(credentials.credentials, configured_token)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid deployment security gate credential.",
            headers={"WWW-Authenticate": "Bearer"},
        )
