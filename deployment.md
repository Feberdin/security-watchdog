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
3. Start the stack:

```bash
docker compose up --build -d
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

## Unraid Notes

- If you run this stack directly on Unraid, mount `/var/run/docker.sock` into both `watchdog` and `worker`.
- If you prefer a remote Docker TCP endpoint, set `UNRAID_DOCKER_HOST=tcp://<unraid-host>:2375` and secure it with TLS before using it outside a trusted network.
- Store persistent Compose data on an Unraid share, not inside ephemeral container layers.
- If you want a simpler Unraid Community Applications setup, use [unraid/security-watchdog.xml](unraid/security-watchdog.xml). That template enables `RUN_EMBEDDED_SCHEDULER=true`, so one container can handle both the API and scheduled scans.

## Home Assistant Notes

- Mount the Home Assistant config directory to `HOMEASSISTANT_CONFIG_PATH`.
- If you want built-in integration manifests resolved too, mount the Home Assistant core components directory to `HOMEASSISTANT_CORE_COMPONENTS_PATH`.
- `custom_components` and `.storage/core.config_entries` should be readable by the container user.

## Backup Strategy

- Back up PostgreSQL volumes regularly.
- Back up `data/sbom` if you want historical SBOM artifacts outside the database.
- Keep a secure backup of `.env` in your secret management process, not in Git.

## Upgrade Process

```bash
docker compose pull
docker compose build --no-cache
docker compose up -d
```

After upgrading:

- Check `/health`
- Review worker logs
- Run one manual `/scan`
