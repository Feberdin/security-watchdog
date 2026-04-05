# Purpose: Build a self-contained runtime image for the API and worker services.
# Input/Output: Installs Python dependencies plus Trivy, Grype, and Git for scanners.
# Important invariants: Scanner tool versions are pinned with build args; the runtime entrypoint
# aligns the internal service user with Unraid-style `PUID`/`PGID` values before dropping
# privileges so mounted appdata paths stay writable.
# Debugging: If builds fail, verify the pinned release URLs for Trivy and Grype first. If runtime
# fails on Unraid, inspect entrypoint logs for UID/GID or docker socket group setup errors.

FROM python:3.12-bookworm

ARG TRIVY_VERSION=0.51.4
ARG GRYPE_VERSION=0.76.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git tar wget apt-transport-https gnupg lsb-release gosu \
    && rm -rf /var/lib/apt/lists/*

RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
    > /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends trivy \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
    -o /tmp/grype.tar.gz \
    && tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype \
    && rm /tmp/grype.tar.gz

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN pip install --upgrade pip setuptools wheel \
    && pip install .

RUN useradd --create-home --shell /bin/bash watchdog \
    && mkdir -p /app/data \
    && chown -R watchdog:watchdog /app \
    && chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 31337

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "31337"]
