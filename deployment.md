# Deployment

Purpose: Explain how to deploy `security-watchdog` as a self-hosted Docker stack, especially on Unraid.  
Input/Output: Follow these steps to provide required volumes, tokens, and network access.  
Important invariants: PostgreSQL and Redis must be reachable from both `watchdog` and `worker`; Docker and Home Assistant mounts should be explicit and reviewed.  
How to debug: Validate each step in order and use the health endpoint before debugging deeper code paths.

## Recommended Deployment Model

- `watchdog`: FastAPI API + dashboard
- `worker`: APScheduler recurring jobs
- `postgres`: persistent relational storage
- `redis`: dedupe and job heartbeat cache

## Step-by-Step

1. Copy `.env.example` to `.env` and fill in GitHub, alerting, and optional AI settings.
2. Adjust the Unraid and Home Assistant volume mounts in `docker-compose.yml` to match your host paths.
3. Pull the published image and start the stack:

```bash
docker compose pull
docker compose up -d
```

4. Verify service health:

```bash
docker compose ps
curl -fsS http://localhost:31337/health
```

5. Trigger the first scan:

```bash
curl -X POST http://localhost:31337/scan \
  -H "Content-Type: application/json" \
  -d '{"include_archived": false, "force": true}'
```

6. Follow the queued scan until it reaches a terminal state:

```bash
curl -fsS http://localhost:31337/scan-jobs/latest
```

## Unraid Notes

- If you run this stack directly on Unraid, mount `/var/run/docker.sock` into both `watchdog` and `worker`.
- On Unraid, prefer `PUID=99` and `PGID=100` unless your share uses different ownership.
- The base `docker-compose.yml` uses the published GHCR image by default, which makes updates on Unraid practical even when there is no Git checkout in `/Users/...`.
- If you prefer a remote Docker TCP endpoint, set `UNRAID_DOCKER_HOST=tcp://<unraid-host>:2375` and secure it with TLS before using it outside a trusted network.
- Store persistent Compose data on an Unraid share, not inside ephemeral container layers.
- If you want a simpler Unraid Community Applications setup, use [unraid/security-watchdog.xml](unraid/security-watchdog.xml). That template enables `RUN_EMBEDDED_SCHEDULER=true`, so one container can handle both the API and scheduled scans.
- In this template-driven Unraid mode, `/mnt/user/appdata/security-watchdog` is only the mounted data directory. It is not the place where `docker compose pull` works unless you also created a separate Compose project there.

## Local Source Build Mode

Use the build override only when you explicitly want unpublished local code instead of the stable
published image:

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml build
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d
```

## Home Assistant Notes

- Local mount mode:
  - Mount the Home Assistant config directory to `HOMEASSISTANT_CONFIG_PATH`.
  - If you want built-in integration manifests resolved too, mount the Home Assistant core components directory to `HOMEASSISTANT_CORE_COMPONENTS_PATH`.
  - `custom_components` and `.storage/core.config_entries` should be readable by the container user.
- Remote API mode for Home Assistant on another device:
  - Set `HOMEASSISTANT_REMOTE_ENABLED=true`.
  - Set `HOMEASSISTANT_REMOTE_BASE_URL=https://<your-home-assistant>:8123`.
  - Create a long-lived access token in the Home Assistant profile page and set `HOMEASSISTANT_REMOTE_TOKEN`.
  - If your Home Assistant uses a self-signed certificate, either install the CA certificate in the image or set `HOMEASSISTANT_REMOTE_VERIFY_TLS=false`.
  - In remote mode, `security-watchdog` inventories integrations via `/api/config` and `/api/components`, so no filesystem mount is required.

## Backup Strategy

- Back up PostgreSQL volumes regularly.
- Back up `data/sbom` if you want historical SBOM artifacts outside the database.
- Keep a secure backup of `.env` in your secret management process, not in Git.

## Upgrade Process

```bash
docker compose pull
docker compose up -d
```

## Upgrade Process On Unraid With The Template

1. Open the container in the Unraid Docker or Apps UI.
2. Verify that the template uses `ghcr.io/feberdin/security-watchdog:latest`.
3. Keep `/mnt/user/appdata/security-watchdog` as the persistent data path.
4. Add or verify these variables if you want full public repository secret-history scans:
   - `SECRET_HISTORY_SCAN_ENABLED=true`
   - `SECRET_HISTORY_MAX_COMMITS_PER_REPO=0`
5. Apply the template update or pull the latest image from the UI.
6. After the container restarts, verify the API:

```bash
curl -fsS http://localhost:31337/health
curl -X POST http://localhost:31337/scan -H "Content-Type: application/json" -d '{"include_archived": false, "force": true}'
curl -fsS http://localhost:31337/scan-jobs/latest
```

If you intentionally deploy from local source instead of the published image:

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml build --pull
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d
```

After upgrading:

- Check `/health`
- Review worker logs
- Run one manual `/scan`
- Confirm `/scan-jobs/latest` moves from `queued` to `running` to `succeeded` or `failed`
