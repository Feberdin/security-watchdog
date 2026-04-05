"""
Purpose: Render the operator dashboard with server-side templates and static assets.
Input/Output: Accepts browser requests and returns HTML plus referenced static files.
Important invariants: The dashboard should remain mostly read-only and rely on API endpoints for
live data so the browser and automation clients see the same underlying numbers.
Debugging: If the page loads but widgets are empty, inspect the browser requests to `/reports`,
`/alerts`, and `/repositories` before touching the template itself.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))
router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    """Render the main dashboard shell."""

    return templates.TemplateResponse(request, "dashboard.html", {"request": request})
