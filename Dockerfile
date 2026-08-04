# Purpose: Build a self-contained runtime image for the API and worker services.
# Input/Output: Installs Python dependencies plus Trivy, Grype, and Git for scanners.
# Important invariants: Scanner tool versions are pinned with build args; the runtime entrypoint
# aligns the internal service user with Unraid-style `PUID`/`PGID` values before dropping
# privileges so mounted appdata paths stay writable.
# Debugging: If builds fail, verify the pinned release URLs for Trivy and Grype first. If runtime
# fails on Unraid, inspect entrypoint logs for UID/GID or docker socket group setup errors.

FROM python:3.12.13-slim-trixie

ARG TRIVY_VERSION=0.73.0
ARG TRIVY_SHA256=2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b
ARG GRYPE_VERSION=0.116.1
ARG GRYPE_SHA256=0122df7b655981abe547ad3d2190d65551dac6a2bfc80b4dc2a989b5d0587458

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates curl git gosu tar \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    -o /tmp/trivy.tar.gz \
    && echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz

RUN curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
    -o /tmp/grype.tar.gz \
    && echo "${GRYPE_SHA256}  /tmp/grype.tar.gz" | sha256sum -c - \
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
