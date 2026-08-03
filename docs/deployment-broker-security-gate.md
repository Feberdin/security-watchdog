# Deployment Broker Security Gate

Purpose: Define the authenticated contract that the Unraid Deployment Broker calls before changing a
stack.

Input/Output: The Broker submits an immutable stack, repository, Compose path, and full Git commit.
Security Watchdog returns `allow`, `deny`, or `indeterminate` plus actionable blockers.

Important invariants:

- The service allows only fresh, successful `repository_asset_scan` evidence for the exact requested
  40-character commit SHA.
- Unresolved HIGH or CRITICAL alerts deny deployment, including acknowledged alerts.
- Missing, failed, stale, or mismatched scan evidence is `indeterminate` and always blocks deployment.
- The endpoint never starts a deployment and never returns secret excerpts or raw scanner payloads.
- Authentication uses a dedicated Bearer token. Do not reuse the Broker administration token.
- The result proves compliance with the configured Security Watchdog policy and scanner coverage; it
  is not a claim that software can be proven free of every unknown vulnerability.

Debugging: Correlate the response `request_id` and `evidence.scan_result_id` with API logs and the
`scan_results` table. Enable `LOG_LEVEL=DEBUG` only in a controlled environment.

## Endpoint

`POST /automation/deployment-security-gate`

Required header:

```text
Authorization: Bearer <dedicated deployment-gate token>
Content-Type: application/json
```

Request:

```json
{
  "api_version": "2026-08-03",
  "stack_name": "security-watchdog",
  "repository_full_name": "Feberdin/security-watchdog",
  "commit_sha": "0123456789abcdef0123456789abcdef01234567",
  "compose_file": "docker-compose.yml"
}
```

The Broker must derive these values from the immutable deployment plan. It must not accept a
different repository or commit from an untrusted apply request.

Response:

```json
{
  "api_version": "2026-08-03",
  "request_id": "4c0cebd4-f75e-4de2-ad2d-7f429f7bf251",
  "checked_at": "2026-08-03T15:00:00Z",
  "decision": "deny",
  "deploy_allowed": false,
  "reason_codes": ["UNRESOLVED_CRITICAL_ALERT"],
  "stack_name": "security-watchdog",
  "repository_full_name": "Feberdin/security-watchdog",
  "requested_commit_sha": "0123456789abcdef0123456789abcdef01234567",
  "compose_file": "docker-compose.yml",
  "policy": {
    "max_scan_age_hours": 24,
    "blocked_severities": ["critical", "high"],
    "unresolved_statuses": ["open", "acknowledged"],
    "max_returned_blockers": 50
  },
  "evidence": {
    "scan_result_id": 123,
    "scanner_name": "repository_asset_scan",
    "status": "success",
    "scanned_commit_sha": "0123456789abcdef0123456789abcdef01234567",
    "completed_at": "2026-08-03T14:55:00Z",
    "age_hours": 0.083,
    "commit_matches": true
  },
  "summary": {
    "blocker_count": 1,
    "returned_blocker_count": 1,
    "critical_count": 1,
    "high_count": 0,
    "evidence_blocker_count": 0,
    "results_truncated": false
  },
  "blockers": [
    {
      "code": "UNRESOLVED_CRITICAL_ALERT",
      "finding_id": "alert:123",
      "severity": "critical",
      "title": "Potential secret in Feberdin/security-watchdog",
      "source_type": "secret_scanner",
      "remediation": "Remove the credential from code and Git history, rotate it through the secure secret flow, rerun the scan, and confirm the alert resolves.",
      "context": {
        "file_path": "src/settings.py",
        "line_number": 12,
        "detector": "generic-api-key"
      }
    }
  ],
  "warnings": []
}
```

Decision handling:

- Continue only when HTTP is `200`, `api_version` is supported, `decision` is `allow`,
  `deploy_allowed` is `true`, and every echoed candidate field exactly matches the deployment plan.
- Treat `deny` and `indeterminate` as hard blocks.
- Treat timeout, DNS/connect failure, TLS failure, `401`, `503`, non-JSON, schema errors, and unknown
  API versions as hard blocks.
- Show the remediation text to the operator, but never log the Bearer token.
- If `results_truncated` is true, direct the operator to Security Watchdog for the complete list.

## Broker Placement

Use this order:

```text
stack_validate
-> deploy_plan
-> deployment_security_gate (derived from immutable plan)
-> approval_request when required
-> deploy_apply
-> deployment_status
-> logs_tail
```

At `deploy_apply`, require a successful gate result bound to the same plan, repository, commit, and
Compose file. Either call the gate immediately before apply or cache it for at most five minutes.
Any plan mutation invalidates the result.

## Configuration

Security Watchdog:

```text
DEPLOYMENT_GATE_TOKEN=<secure secret>
DEPLOYMENT_GATE_MAX_SCAN_AGE_HOURS=24
DEPLOYMENT_GATE_MAX_BLOCKERS=50
```

Broker:

```text
SECURITY_WATCHDOG_GATE_URL=http://192.168.57.10:31337/automation/deployment-security-gate
SECURITY_WATCHDOG_GATE_TOKEN=<same dedicated secret, injected securely>
SECURITY_WATCHDOG_GATE_TIMEOUT_SECONDS=10
```

Keep both token values in the existing Broker secret flow. Never place them in Git, chat, plan
payloads, audit details, or exception strings.

## Local Contract Check

```bash
curl --fail-with-body \
  --request POST \
  --header "Authorization: Bearer ${DEPLOYMENT_GATE_TOKEN}" \
  --header "Content-Type: application/json" \
  --data '{
    "api_version": "2026-08-03",
    "stack_name": "security-watchdog",
    "repository_full_name": "Feberdin/security-watchdog",
    "commit_sha": "0123456789abcdef0123456789abcdef01234567",
    "compose_file": "docker-compose.yml"
  }' \
  http://localhost:31337/automation/deployment-security-gate
```

Do not place a real token directly in shell history; use a secure environment injection mechanism.
