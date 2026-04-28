# Contributing

Purpose: Explain how to make safe changes to `security-watchdog` and verify them locally.  
Input/Output: Follow these steps before opening a pull request or deploying a change.  
Important invariants: Keep modules small, preserve structured logging, and extend tests when behavior changes.  
How to debug: If your change spans multiple services, verify it through unit tests first and then via the REST API or worker logs.

## Development Workflow

1. Create a branch for one focused change.
2. Install dependencies in a virtual environment.
3. Run tests before and after your change.
4. Keep comments up to date when you change intent or invariants.
5. Add or adjust documentation when configuration or operational behavior changes.

## Setup

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e .[dev]
.venv/bin/pytest
```

## Code Style

- Prefer readability over compactness.
- Use explicit names and type hints.
- Keep error messages actionable: what failed, why it matters, and what to check next.
- Mask secrets in logs and examples.

## Testing Expectations

- Add unit tests for new parsing or correlation logic.
- Cover one happy path and at least one important error or edge case.
- When refactoring, use tests as a safety net and mention the preserved behavior in your PR description.

## Manual Validation

- `GET /health` should return `{"status": "ok"}`.
- `GET /reports` should load without server errors.
- A manual `POST /scan` should return `202 Accepted`, create a `manual_scan_jobs` row, and
  eventually populate fresh `scan_results`.
- If you change Docker or Home Assistant integration behavior, validate mounted-path assumptions in `deployment.md`.
- If you need to validate unpublished Docker changes, use `docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build` so production-style Compose remains image-based and stable.
