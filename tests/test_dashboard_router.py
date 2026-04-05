"""
Purpose: Guard the dashboard shell route against template-rendering regressions.
Input/Output: Builds a tiny FastAPI app with the dashboard router and checks that `/` renders HTML.
Important invariants: The template response call must stay compatible with the FastAPI/Starlette
version pinned by this project, because signature changes have broken the dashboard before.
Debugging: If this test fails, inspect `app/dashboard/router.py` and the current
`Jinja2Templates.TemplateResponse` signature first.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.dashboard.router import router as dashboard_router


def test_dashboard_root_renders_html() -> None:
    """The dashboard root should return HTML instead of a 500 template error."""

    app = FastAPI()
    app.include_router(dashboard_router)

    client = TestClient(app)
    response = client.get("/")

    assert response.status_code == 200
    assert "security-watchdog" in response.text
