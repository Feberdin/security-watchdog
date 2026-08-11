# security-watchdog

Purpose: `security-watchdog` is a self-hosted security monitoring platform for GitHub repositories, Unraid Docker workloads, and Home Assistant integrations.  
Input/Output: It ingests repository code, dependency manifests, Docker/runtime metadata, and threat feeds, then produces vulnerabilities, SBOMs, and alerts.  
Important invariants: Secrets live only in environment variables, PostgreSQL is the source of truth, and mounted infrastructure paths should be read-only where possible.  
How to debug: Start with `LOG_LEVEL=DEBUG`, inspect `/health`, `/reports`, worker logs, and the `scan_results` table if a scan looks incomplete.

## Features

- Inventories all GitHub repositories available to the configured user token.
- Clones or updates repositories and extracts dependencies from Python, Node.js, Java, PHP, Rust, Go, and Docker manifests.
- Scans repositories for likely leaked secrets with regex and entropy heuristics, including public git history for owned public repositories.
- Scans Docker images and Dockerfiles with Trivy and Grype, and reuses cached image findings for the same immutable digest or image ID.
- Discovers running Unraid Docker containers through the Docker API or socket.
- Discovers Home Assistant integrations from mounted config/component paths or from a remote Home Assistant REST API.
- Correlates dependencies with OSV, NVD, GitHub Security Advisories, and CISA KEV.
- Collects threat intelligence from RSS, Reddit `r/netsec`, Hacker News RSS, and GitHub issues.
- Uses an OpenAI-compatible API to extract structured malicious-package signals from unstructured articles.
- Generates CycloneDX and SPDX SBOMs for every scanned asset.
- Exports active alerts as SARIF 2.1.0 JSON for GitHub Code Scanning-compatible tooling.
- Exposes REST endpoints and a browser dashboard.
- Lets operators start full, source-specific, single-asset, and pre-deploy scans; pause, resume, or cancel manual scans; and disable irrelevant assets individually or in batches without deleting historical findings.
- Classifies remediation ownership so Codex prompts only suggest Issue/PR work for owned repos or owned images with a mapped source repo; forks, external images, and unknown sources stay advisory-only or exclusion candidates.
- Generates a grouped Codex remediation prompt after full scans: owned GitHub repos plus matching owned Unraid containers first, external or unmapped Unraid containers next, Home Assistant assets after that, and every group sorted by severity.
- Sends alerts to Slack, email, and GitHub issues.

## Quickstart

```bash
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.local.yml pull
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d
open http://localhost:31337
```

## Local Development

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e .[dev]
.venv/bin/uvicorn app.main:app --reload --port 31337
```

## Local Docker Build From Source

```bash
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.local.yml -f docker-compose.build.yml build
docker compose -f docker-compose.yml -f docker-compose.local.yml -f docker-compose.build.yml up -d
```

## Run Tests

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e .[dev]
.venv/bin/pytest
```

## Configuration

Key environment variables:

- `SECURITY_WATCHDOG_IMAGE`: Immutable image reference for Compose deployments. Production defaults to the reviewed manifest digest in `docker-compose.yml`; review and rollback deployments can override it with another pinned digest.
- `SECURITY_WATCHDOG_DATA_PATH`: Host path for `/app/data`. Local default is `./data`; Broker/Unraid default is `/mnt/user/appdata/security-watchdog`.
- `LOG_MAX_SIZE`, `LOG_MAX_FILE`: Docker JSON log rotation limits used by the Compose stack.
- `PUID`, `PGID`: Optional container runtime user/group mapping. On Unraid, `99`/`100` usually matches `nobody:users`.
- `POSTGRES_PASSWORD`: Local Docker password for PostgreSQL. In Broker GitOps deployments this must be provided as the Broker secret `SECURITY_WATCHDOG_POSTGRES_PASSWORD`.
- `SECURITY_WATCHDOG_DATABASE_URL`: Broker secret containing the PostgreSQL connection string for the application.
- `SECURITY_WATCHDOG_DEPLOYMENT_GATE_TOKEN`: Dedicated Broker secret for authenticating pre-deployment security checks. Do not reuse the Broker administration token.
- `DEPLOYMENT_GATE_MAX_SCAN_AGE_HOURS`: Maximum age of successful exact-commit scan evidence; default `24`.
- `DEPLOYMENT_GATE_MAX_BLOCKERS`: Maximum blocker details returned per response; counts always cover all findings.
- `GITHUB_TOKEN`: GitHub token with access to the repositories you want to monitor.
- `GITHUB_INCLUDE_FORKS`: Include forked GitHub repositories in repository scans and reports. Defaults to `false`, so forks such as large upstream mirrors stay out of the normal security queue.
- `MANAGED_GITHUB_OWNERS`: Comma-separated GitHub owners where Codex may propose managed Issue/PR remediation. Defaults to `Feberdin`.
- `MANAGED_CONTAINER_NAMESPACES`: Comma-separated container namespaces treated as owned images, for example `feberdin` for `ghcr.io/feberdin/...`. Owned images still need an OCI source label or manual mapping before PRs are allowed.
- `CONTAINER_TRIVY_IMAGE_TIMEOUT_SECONDS`: Runtime image scan timeout for Trivy. Default `180` keeps full estate scans moving when a registry or scanner stalls.
- `CONTAINER_GRYPE_IMAGE_ENABLED`: Optional secondary runtime image scan with Grype. Default `false` because Trivy already provides the primary image vulnerability signal and Grype can add several minutes per uncached image.
- `CONTAINER_GRYPE_IMAGE_TIMEOUT_SECONDS`: Runtime image scan timeout for the optional Grype pass. Default `180`.
- `SECRET_HISTORY_SCAN_ENABLED`: When `true`, public GitHub repositories are fetched with full history and scanned for secrets in old commits as well as the current tree.
- `SECRET_HISTORY_MAX_COMMITS_PER_REPO`: Optional safety limit for history scanning. `0` means scan the full reachable history.
- `DATABASE_URL`: PostgreSQL connection string.
- `REDIS_URL`: Redis instance for lightweight dedupe and job heartbeats.
- `VULNERABILITY_CACHE_TTL_HOURS`: Reuse successful per-provider package/version responses; defaults to `24` hours.
- `UNRAID_DOCKER_HOST`: Usually `unix:///var/run/docker.sock` when deployed on Unraid.
- `HOMEASSISTANT_CONFIG_PATH`: Mounted Home Assistant config directory.
- `HOMEASSISTANT_CORE_COMPONENTS_PATH`: Optional mounted path for built-in component manifests.
- `HOMEASSISTANT_REMOTE_*`: Remote Home Assistant URL, long-lived access token, TLS handling, and request timeout.
- `AI_ENABLED`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`: AI extraction controls.
- `SLACK_WEBHOOK_URL`, `EMAIL_*`, `GITHUB_ALERT_REPOSITORY`: Alert destinations.

### Broker Secret Classification

The repository secret scanner treats Broker-managed references as secret names, not leaked values.
Compose and stack values such as `secret://NAME`, `*_secret_ref`, `*_secret_refs`,
`database_url_secret_name`, and `password_secret_name` are expected to point at values that the
Unraid Deployment Broker injects at runtime. Known Broker configuration variables such as
`BROKER_CONFIG`, `BROKER_DATA_DIR`, `BROKER_LOG_LEVEL`, `BROKER_STACKS_HOST_DIR`, `RUST_LOG`,
`CSI_SOURCE`, `MODELS_DIR`, and `SENSING_ALLOWED_HOSTS` are treated as normal runtime settings.
Literal values assigned to credential-bearing names such as `BROKER_MCP_TOKEN`,
`BROKER_SECRET_KEY`, `UNRAID_API_KEY`, `UNIFI_PASSWORD`, `SECURITY_WATCHDOG_GATE_TOKEN`,
`BITWARDEN_CLIENT_SECRET`, `SMTP_PASSWORD`, or dynamic names like `APP_DATABASE_URL` still produce
critical secret findings and must be moved into Broker-managed secrets.

The scanner skips generated Rust `target/` and Vite `.vite/` trees in both the
working tree and Git history. It also recognizes non-literal Terraform/HCL and
source-code references plus explicit example placeholders. Provider-shaped
credentials, private-key markers, realistic mixed-class literals, and random
production values remain findings. To debug a suspected false positive, use the
redacted alert metadata (`file_path`, `line_number`, and `detector`) and add a
positive and negative regression test before changing a detector.

## API Overview

- `POST /scan`: Queue an immediate scan and return `202 Accepted` plus a status URL. Optional JSON fields: `repository_full_name` for one asset, `scan_sources` with `github`, `unraid`, and/or `homeassistant`, `force`, `include_archived`, `priority`, `pause_active`, `purpose`, `target_commit_sha`, and `refresh_image_cache`.
- `GET /scan-jobs/latest`: Latest manual scan including lifecycle state, percentage, phase, and recent progress events.
- `GET /scan-jobs/{job_id}`: One manual scan job with timestamps, counts, error details, the
  measured `scanned_commit_sha` for commit-bound scans, and a bounded operator log.
- `POST /scan-jobs/{job_id}/cancel`: Request cooperative cancellation for a queued or running scan. Running scans stop at the next safe checkpoint; already committed asset results stay stored.
- `POST /scan-jobs/{job_id}/pause`: Request cooperative pause for a queued or running scan. Running scans pause at the next safe checkpoint; already committed asset results stay stored.
- `POST /scan-jobs/{job_id}/resume`: Return a paused scan to the prioritized queue.

Manual scans are stored in PostgreSQL before execution. The dedicated `worker`, or the API's
embedded scheduler in single-container installations, claims queued work. Running jobs persist
progress counters after each asset and resume from the newest durable asset outcome after a worker
restart or deployment. Queued work is claimed by descending `priority`, then request time.
Recurring repository scans are also inserted into the same queue with `purpose=scheduled`, so a
deploy restart cannot start a hidden, non-cancellable full scan beside an operator-triggered run.
- `GET /reports`: Aggregated dashboard/report data.
- `GET /reports/sarif`: Active alerts as SARIF 2.1.0 JSON. Add `?include_resolved=true` for audit exports.
- `GET /alerts`: Latest alerts.
- `GET /threats`: Recent threat articles and AI-extracted threat records.
- `GET /dependencies`: Recently scanned dependencies.
- `GET /repositories`: Repository-like assets, including Unraid and Home Assistant.
- `PATCH /repositories/{repository_id}/scan-settings`: Set `scan_enabled` to include or exclude one asset from future scans and normal reports without deleting its history.
- `PATCH /repositories/scan-settings/bulk`: Set `scan_enabled` for up to 500 selected assets in one operator action.
- `GET /systems`: System-centric inventory for the dashboard with expandable dependency details, latest-version hints, and a backend remediation policy per system.
- `GET /automation/high-risk-updates`: Prioritized update queue for high-risk and outdated dependencies. Each task includes the same remediation policy so Codex can distinguish managed fixes from advisory-only work.
- `GET /automation/high-risk-updates/codex-prompt`: Master prompt for a controlled Codex update run across queued repositories.
- `GET /automation/grouped-remediation/codex-prompt`: Full-scan Codex prompt grouped by ownership and source repository. Use this after a broad scan when one agent should process owned repos, related owned Unraid images, external containers, and Home Assistant findings in a deterministic order.
- `GET /automation/daily-security-check`: Machine-readable runbook for the recurring Codex security task.
- `GET /automation/deployment-security-gate/status`: Dashboard-safe gate status for one exact commit; no Broker token required.
- `POST /automation/deployment-security-gate`: Authenticated, fail-closed pre-deployment decision for one exact Git commit. See [Deployment Broker security gate](docs/deployment-broker-security-gate.md).
- `POST /automation/pre-deploy-scan`: Queue a high-priority, commit-bound GitHub scan that can satisfy the deployment gate. It can pause the currently running scan first.
- `GET /health`: Liveness check.
- Default port: `31337` because it is a memorable security-themed port and was free on the current host during setup.

## Unraid and Home Assistant

For Unraid Docker coverage:

- Run the stack on Unraid or mount the Unraid Docker socket into the containers.
- Deploy the GitOps stack through the Unraid Deployment Broker with `docker-compose.yml`; it contains `secret://...` references that the Broker resolves at runtime.
- Required Broker secrets are `SECURITY_WATCHDOG_POSTGRES_PASSWORD`, `SECURITY_WATCHDOG_DATABASE_URL`, `SECURITY_WATCHDOG_GITHUB_TOKEN`, and `SECURITY_WATCHDOG_DEPLOYMENT_GATE_TOKEN`.
- The Compose default network is pinned to `10.200.9.0/24` so the Broker can verify that Docker networking does not overlap LAN/VLAN ranges.
- For local Docker usage outside the Broker, always add `docker-compose.local.yml` so `.env` values replace the Broker secret references.
- Leave `UNRAID_DOCKER_ENABLED=true`.
- Set `PUID=99` and `PGID=100` on Unraid unless your share permissions require different values.
- The entrypoint maps the service user to those IDs and adds docker socket group access automatically when `/var/run/docker.sock` is mounted.
- For a simpler Unraid single-container install, use [unraid/security-watchdog.xml](unraid/security-watchdog.xml) with `RUN_EMBEDDED_SCHEDULER=true`.
- In this Unraid template mode, `/mnt/user/appdata/security-watchdog` is your persistent data directory only. The container update itself comes from the image `ghcr.io/feberdin/security-watchdog:latest`, not from `docker compose` inside that appdata path.
- After a new image is published, update it from the Unraid Docker or Apps UI by refreshing the template or applying the image update. The bundled template already points to `ghcr.io/feberdin/security-watchdog:latest`.
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

- `Tower update failed with a macOS path`: the path `/Users/...` is only valid on the development machine. On Unraid, switch into the real Compose project directory first and then run `docker compose pull && docker compose up -d`.
- `docker compose pull` says `no configuration file provided`: you are probably in `/mnt/user/appdata/security-watchdog`, which is only the persistent data directory for the Unraid template. Update the container through the Unraid template or switch into the actual Compose project directory first.
- `secret://...` appears as the runtime password locally: start local Compose with `-f docker-compose.yml -f docker-compose.local.yml` and verify that `.env` exists.
- `Broker blocks /var/run/docker.sock`: add a stack-scoped Broker policy allowance for `security-watchdog` before registering the stack source. Do not hide the mount behind a Compose variable.
- `GitHub repos not syncing`: verify `GITHUB_TOKEN` scope and check worker logs for Git clone errors.
- `Public repo history scan is too slow`: set `SECRET_HISTORY_MAX_COMMITS_PER_REPO` to a smaller number temporarily, or disable `SECRET_HISTORY_SCAN_ENABLED` while you triage the largest repositories.
- `Unraid containers missing`: verify `/var/run/docker.sock` is mounted and readable inside `watchdog` and `worker`.
- `PermissionError: data/repos`: on Unraid, set `PUID=99` and `PGID=100` or another UID/GID pair that can write to your mapped appdata directory.
- `Home Assistant integrations missing`: check that `.storage/core.config_entries` exists in the mounted config path.
- `Remote Home Assistant scan fails with 401`: create a fresh long-lived access token and verify `HOMEASSISTANT_REMOTE_TOKEN`.
- `Remote Home Assistant scan fails with TLS errors`: if you use a self-signed certificate, set `HOMEASSISTANT_REMOTE_VERIFY_TLS=false` or install the CA certificate into the container.
- `Container findings empty`: confirm `trivy` is installed inside the image and the worker can reach image registries. If you enabled the optional Grype pass, verify `grype` separately.
- `Container image scan repeats too often`: verify the Unraid inventory exposes `image_identity` in repository metadata. Set `refresh_image_cache=true` on `POST /scan` only when you intentionally want to refresh digest-level image findings.
- `Repository sync failed` with `Not possible to fast-forward`: the scanner treats `data/repos/...` as disposable cache and resets the checkout to `origin/<default_branch>` on the next scan. If it keeps failing, delete the cached checkout path shown in the logs and rerun the scan.
- `AI extraction not running`: set `AI_ENABLED=true`, provide `OPENAI_API_KEY`, and inspect worker logs.
- `Manual scan remains queued`: verify the `worker` is healthy, or enable
  `RUN_EMBEDDED_SCHEDULER=true` for a supported single-container installation.
- `Manual scan takes a long time`: open the dashboard progress log or query `/scan-jobs/latest`.
  Full-estate runs query multiple advisory providers for exact dependency versions and can take
  several minutes. Successful OSV, GitHub, and NVD package/version responses are cached in
  PostgreSQL for 24 hours by default. Provider errors are not cached; NVD is paused briefly after a
  `429` response while OSV and GitHub checks continue.
- `Manual scan should stop`: click `Scan abbrechen` in the dashboard or call `POST /scan-jobs/{id}/cancel`. If an external scanner binary is running, the worker stops after that command returns or times out.
- `Manual scan should make room for a targeted scan`: click `Scan pausieren` or queue a pre-deploy scan with `pause_active=true`. The current scan pauses at the next checkpoint and can be resumed with `POST /scan-jobs/{id}/resume`.
- `Manual scan resumed after a restart`: this is expected. Running jobs stay resumable and continue from committed asset outcomes after the worker restarts.
- `Irrelevant repo keeps appearing`: disable it from the dashboard target selector or call `PATCH /repositories/{id}/scan-settings` with `{"scan_enabled": false}`. Disabled assets stay visible in `/repositories` so they can be re-enabled later.
- `Many irrelevant repos keep appearing`: select them in the System Inventory and use `Auswahl ausschließen`, or call `PATCH /repositories/scan-settings/bulk` with the selected repository IDs.
- `Codex prompt is advisory-only`: the system is external, a fork, or an owned image without a mapped source repository. Add an OCI label such as `org.opencontainers.image.source=https://github.com/Feberdin/<repo>` to owned images, or disable irrelevant forks from scanning.
- `Deployment gate returns 401`: verify that the Broker sends the dedicated Bearer token configured through the secure secret flow.
- `Deployment gate returns 503`: configure `SECURITY_WATCHDOG_DEPLOYMENT_GATE_TOKEN` or inspect API/database errors in the watchdog logs.
- `Deployment gate returns indeterminate`: scan the exact requested full commit and ensure the aggregate scan is fresh and successful.
- `Dashboard gate status says no matching evidence`: enter the full deploy commit SHA and start `Pre-Deploy-Scan`. The dashboard queues a high-priority GitHub-only scan for the selected repo, defaulting to `Feberdin/security-watchdog` when no target is selected.

## Logs and Debugging

- Increase verbosity with `LOG_LEVEL=DEBUG`.
- API logs: `docker compose logs -f watchdog`
- Worker logs: `docker compose logs -f worker`
- Manual scan progress: `curl -fsS http://localhost:31337/scan-jobs/latest`
- Dashboard-safe deployment gate status: `curl -fsS "http://localhost:31337/automation/deployment-security-gate/status?stack_name=security-watchdog&repository_full_name=Feberdin/security-watchdog&commit_sha=<40-char-sha>&compose_file=docker-compose.yml"`
- SARIF export: `curl -fsS http://localhost:31337/reports/sarif > security-watchdog.sarif`
- Stable local image upgrade: `docker compose -f docker-compose.yml -f docker-compose.local.yml pull && docker compose -f docker-compose.yml -f docker-compose.local.yml up -d`
- Local source rebuild: `docker compose -f docker-compose.yml -f docker-compose.local.yml -f docker-compose.build.yml up -d --build`
- Database state: inspect `repositories`, `dependencies`, `vulnerabilities`, `scan_results`,
  `manual_scan_jobs`, `manual_scan_progress_events`, `vulnerability_provider_cache`,
  `container_image_scan_cache`, `threat_articles`, `ai_extracted_threats`, and `alerts`.
- SBOM output: `data/sbom/<asset>/cyclonedx.json` and `data/sbom/<asset>/spdx.json`

## Security Notes

- Do not commit `.env`.
- Prefer read-only mounts for Home Assistant paths.
- Mounting the Docker socket grants powerful host access; restrict access to this stack accordingly.
- Rotate any secret immediately if the secret scanner reports a real credential.
- The deployment gate returns only allowlisted alert metadata and never returns secret excerpts or raw scanner payloads.

## Acknowledgements

- Inspired in part by [m3lixir/chumdump](https://github.com/m3lixir/chumdump), especially its
  evidence-first security reporting and SARIF export ideas. Gruss und Danke an Melisa K. Savich
  fuer die oeffentlichen Research-Ideen.

## License Note

No formal `LICENSE` file is included yet. Treat the repository as internal/proprietary until you choose and add a license.
