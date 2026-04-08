# security-watchdog

Purpose: `security-watchdog` is a self-hosted security monitoring platform for GitHub repositories, Unraid Docker workloads, and Home Assistant integrations.  
Input/Output: It ingests repository code, dependency manifests, Docker/runtime metadata, and threat feeds, then produces vulnerabilities, SBOMs, and alerts.  
Important invariants: Secrets live only in environment variables, PostgreSQL is the source of truth, and mounted infrastructure paths should be read-only where possible.  
How to debug: Start with `LOG_LEVEL=DEBUG`, inspect `/health`, `/reports`, worker logs, and the `scan_results` table if a scan looks incomplete.

## Features

- Inventories all GitHub repositories available to the configured user token.
- Clones or updates repositories and extracts dependencies from Python, Node.js, Java, PHP, Rust, Go, and Docker manifests.
- Scans repositories for likely leaked secrets with regex and entropy heuristics.
- Scans Docker images and Dockerfiles with Trivy and Grype.
- Discovers running Unraid Docker containers through the Docker API or socket.
- Discovers Home Assistant integrations from mounted config/component paths or from a remote Home Assistant REST API.
- Correlates dependencies with OSV, NVD, GitHub Security Advisories, and CISA KEV.
- Collects threat intelligence from RSS, Reddit `r/netsec`, Hacker News RSS, and GitHub issues.
- Uses an OpenAI-compatible API to extract structured malicious-package signals from unstructured articles.
- Generates CycloneDX and SPDX SBOMs for every scanned asset.
- Exposes REST endpoints and a browser dashboard.
- Sends alerts to Slack, email, and GitHub issues.

## Quickstart

```bash
cp .env.example .env
docker compose up --build
open http://localhost:31337
```

## Local Development

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e .[dev]
.venv/bin/uvicorn app.main:app --reload --port 31337
```

## Run Tests

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e .[dev]
.venv/bin/pytest
```

## Configuration

Key environment variables:

- `PUID`, `PGID`: Optional container runtime user/group mapping. On Unraid, `99`/`100` usually matches `nobody:users`.
- `GITHUB_TOKEN`: GitHub token with access to the repositories you want to monitor.
- `DATABASE_URL`: PostgreSQL connection string.
- `REDIS_URL`: Redis instance for lightweight dedupe and job heartbeats.
- `UNRAID_DOCKER_HOST`: Usually `unix:///var/run/docker.sock` when deployed on Unraid.
- `HOMEASSISTANT_CONFIG_PATH`: Mounted Home Assistant config directory.
- `HOMEASSISTANT_CORE_COMPONENTS_PATH`: Optional mounted path for built-in component manifests.
- `HOMEASSISTANT_REMOTE_*`: Remote Home Assistant URL, long-lived access token, TLS handling, and request timeout.
- `AI_ENABLED`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`: AI extraction controls.
- `SLACK_WEBHOOK_URL`, `EMAIL_*`, `GITHUB_ALERT_REPOSITORY`: Alert destinations.

## API Overview

- `POST /scan`: Run an immediate full scan.
- `GET /reports`: Aggregated dashboard/report data.
- `GET /alerts`: Latest alerts.
- `GET /threats`: Recent threat articles and AI-extracted threat records.
- `GET /dependencies`: Recently scanned dependencies.
- `GET /repositories`: Repository-like assets, including Unraid and Home Assistant.
- `GET /systems`: System-centric inventory for the dashboard with expandable dependency details and latest-version hints.
- `GET /health`: Liveness check.
- Default port: `31337` because it is a memorable security-themed port and was free on the current host during setup.

## Unraid and Home Assistant

For Unraid Docker coverage:

- Run the stack on Unraid or mount the Unraid Docker socket into the containers.
- Leave `UNRAID_DOCKER_ENABLED=true`.
- Set `PUID=99` and `PGID=100` on Unraid unless your share permissions require different values.
- The entrypoint maps the service user to those IDs and adds docker socket group access automatically when `/var/run/docker.sock` is mounted.
- For a simpler Unraid single-container install, use [unraid/security-watchdog.xml](unraid/security-watchdog.xml) with `RUN_EMBEDDED_SCHEDULER=true`.
- The repository also contains a GitHub Actions workflow that publishes `ghcr.io/feberdin/security-watchdog:latest` after pushes to `main`.

For Home Assistant coverage:

- Local mount mode:
  - Mount your Home Assistant config directory to `HOMEASSISTANT_CONFIG_PATH`.
  - Mount Home Assistant core components to `HOMEASSISTANT_CORE_COMPONENTS_PATH` if you also want built-in integration manifests resolved.
  - The scanner reads `.storage/core.config_entries` plus `custom_components/*/manifest.json`.
- Remote API mode:
  - Set `HOMEASSISTANT_REMOTE_ENABLED=true`.
  - Set `HOMEASSISTANT_REMOTE_BASE_URL` to the Home Assistant root URL, for example `https://homeassistant.local:8123`.
  - Create a long-lived access token in the Home Assistant profile page and place it in `HOMEASSISTANT_REMOTE_TOKEN`.
  - Leave `HOMEASSISTANT_SCAN_ENABLED=false` if you do not mount any Home Assistant files into the container.
- Remote mode inventories loaded integration domains through the official `/api/config` and `/api/components` endpoints. Deep dependency extraction for custom integrations still works best when manifests are mounted locally.

## Troubleshooting

- `GitHub repos not syncing`: verify `GITHUB_TOKEN` scope and check worker logs for Git clone errors.
- `Unraid containers missing`: verify `/var/run/docker.sock` is mounted and readable inside `watchdog` and `worker`.
- `PermissionError: data/repos`: on Unraid, set `PUID=99` and `PGID=100` or another UID/GID pair that can write to your mapped appdata directory.
- `Home Assistant integrations missing`: check that `.storage/core.config_entries` exists in the mounted config path.
- `Remote Home Assistant scan fails with 401`: create a fresh long-lived access token and verify `HOMEASSISTANT_REMOTE_TOKEN`.
- `Remote Home Assistant scan fails with TLS errors`: if you use a self-signed certificate, set `HOMEASSISTANT_REMOTE_VERIFY_TLS=false` or install the CA certificate into the container.
- `Container findings empty`: confirm `trivy` and `grype` are installed inside the image and the worker can reach image registries.
- `AI extraction not running`: set `AI_ENABLED=true`, provide `OPENAI_API_KEY`, and inspect worker logs.

## Logs and Debugging

- Increase verbosity with `LOG_LEVEL=DEBUG`.
- API logs: `docker compose logs -f watchdog`
- Worker logs: `docker compose logs -f worker`
- Database state: inspect `repositories`, `dependencies`, `vulnerabilities`, `scan_results`, `threat_articles`, `ai_extracted_threats`, and `alerts`.
- SBOM output: `data/sbom/<asset>/cyclonedx.json` and `data/sbom/<asset>/spdx.json`

## Security Notes

- Do not commit `.env`.
- Prefer read-only mounts for Home Assistant paths.
- Mounting the Docker socket grants powerful host access; restrict access to this stack accordingly.
- Rotate any secret immediately if the secret scanner reports a real credential.

## License Note

No formal `LICENSE` file is included yet. Treat the repository as internal/proprietary until you choose and add a license.
