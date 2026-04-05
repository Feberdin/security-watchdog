# Purpose: Build a self-contained runtime image for the API and worker services.
# Input/Output: Installs Python dependencies plus Trivy, Grype, and Git for scanners.
# Important invariants: Scanner tool versions are pinned with build args; the final image runs as a
# non-root user while still being able to read mounted volumes and the Docker socket when allowed.
# Debugging: If builds fail, verify the pinned release URLs for Trivy and Grype first.

FROM python:3.12-slim

ARG TRIVY_VERSION=0.51.4
ARG GRYPE_VERSION=0.76.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git tar \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"

RUN curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
    -o /tmp/grype.tar.gz \
    && tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype \
    && rm /tmp/grype.tar.gz

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --upgrade pip setuptools wheel \
    && pip install .

RUN useradd --create-home --shell /bin/bash watchdog \
    && mkdir -p /app/data \
    && chown -R watchdog:watchdog /app

USER watchdog

EXPOSE 31337

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "31337"]
