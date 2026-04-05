# Security

Purpose: Document the security assumptions and hardening guidance for operating `security-watchdog`.  
Input/Output: Use this as an operator checklist when deploying in production.  
Important invariants: The platform processes sensitive code and potentially real credentials, so log hygiene and volume permissions matter as much as scanner correctness.  
How to debug: When in doubt, review mount permissions, token scopes, and alerting destinations before changing code.

## Threat Model Summary

- The system reads private source code, Docker metadata, and Home Assistant configuration.
- It may encounter real secrets during scans.
- It can optionally access the Docker socket, which is a privileged host interface.
- It can create outbound notifications to Slack, SMTP, GitHub, and AI providers.

## Hardening Recommendations

- Use a dedicated GitHub token with the least repository scope required.
- Use a dedicated Home Assistant long-lived access token if you enable remote API inventory.
- Restrict network egress if your environment requires approved outbound destinations only.
- Mount Home Assistant paths read-only.
- Protect the Docker socket carefully; anyone controlling the container with that mount can influence the host.
- Store `.env` in a secret manager or encrypted backup, never in source control.
- Limit access to the dashboard behind a reverse proxy, VPN, or SSO if it will be reachable outside a trusted LAN.

## Logging and Secret Handling

- Structured JSON logs are emitted to stdout.
- Known secret-like keys are masked before logging.
- Secret scanner findings include only redacted excerpts, not full credentials.
- If a real secret is found, rotate it first, then clean the repository history if needed.

## Failure Modes

- External advisory or feed sources may be unavailable or rate-limited.
- AI extraction may be disabled or fail due to invalid credentials.
- Docker image scanning may fail if registries are unreachable.
- Home Assistant built-in integration manifests may be unavailable unless the core components path is mounted.
- Remote Home Assistant inventory depends on a reachable `/api/config` and `/api/components` endpoint plus a valid bearer token.

## Operational Response

When a high-confidence alert appears:

1. Confirm the affected repository, container, or Home Assistant integration.
2. Verify the exact package version or secret finding.
3. Rotate credentials immediately for secret leaks.
4. Patch or pin away from affected dependency versions.
5. Re-run `/scan` and verify the alert resolves.
