#!/usr/bin/env bash
#
# Purpose: Prepare writable runtime directories on bind mounts and then drop privileges safely.
# Input/Output: Reads Unraid-style PUID/PGID environment variables and launches the requested
# command as the service user.
# Important invariants: The script must stay fail-fast, should not mutate read-only mounts, and
# should only chown the writable `/app/data` area plus the service home directory.
# Debugging: If startup fails, inspect the stdout/stderr lines from this script first because they
# explain UID/GID alignment and docker socket group handling.

set -euo pipefail

WATCHDOG_USER="${WATCHDOG_USER:-watchdog}"
WATCHDOG_GROUP="${WATCHDOG_GROUP:-watchdog}"
PUID="${PUID:-99}"
PGID="${PGID:-100}"

echo "[entrypoint] Preparing runtime user '${WATCHDOG_USER}' with uid=${PUID} gid=${PGID}"

if getent group "${WATCHDOG_GROUP}" >/dev/null 2>&1; then
  CURRENT_GID="$(getent group "${WATCHDOG_GROUP}" | cut -d: -f3)"
  if [ "${CURRENT_GID}" != "${PGID}" ]; then
    groupmod -o -g "${PGID}" "${WATCHDOG_GROUP}"
  fi
else
  groupadd -o -g "${PGID}" "${WATCHDOG_GROUP}"
fi

if id "${WATCHDOG_USER}" >/dev/null 2>&1; then
  CURRENT_UID="$(id -u "${WATCHDOG_USER}")"
  CURRENT_GID="$(id -g "${WATCHDOG_USER}")"
  if [ "${CURRENT_UID}" != "${PUID}" ] || [ "${CURRENT_GID}" != "${PGID}" ]; then
    usermod -o -u "${PUID}" -g "${PGID}" "${WATCHDOG_USER}"
  fi
else
  useradd -o -u "${PUID}" -g "${PGID}" --create-home --shell /bin/bash "${WATCHDOG_USER}"
fi

mkdir -p /app/data /app/data/repos /app/data/sbom /app/data/scan-results
chown -R "${PUID}:${PGID}" /app/data "/home/${WATCHDOG_USER}"

if [ -S /var/run/docker.sock ]; then
  DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)"
  EXISTING_DOCKER_GROUP="$(getent group "${DOCKER_SOCKET_GID}" | cut -d: -f1 || true)"
  if [ -z "${EXISTING_DOCKER_GROUP}" ]; then
    EXISTING_DOCKER_GROUP="dockersock"
    groupadd -o -g "${DOCKER_SOCKET_GID}" "${EXISTING_DOCKER_GROUP}" || true
  fi
  usermod -aG "${EXISTING_DOCKER_GROUP}" "${WATCHDOG_USER}" || true
  echo "[entrypoint] Added '${WATCHDOG_USER}' to docker socket group '${EXISTING_DOCKER_GROUP}' (${DOCKER_SOCKET_GID})"
fi

echo "[entrypoint] Starting application command: $*"
exec gosu "${WATCHDOG_USER}" "$@"
