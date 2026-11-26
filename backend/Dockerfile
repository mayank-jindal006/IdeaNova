ARG PYTHON_IMAGE=python:3.13-slim-bookworm@sha256:f0fa218d5b06f9b9235024fa061cde2cb141f726de52134471053d2d9b5324a3

FROM ${PYTHON_IMAGE} AS gitleaks
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) archive="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; checksum="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" ;; \
      arm64) archive="gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz"; checksum="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" ;; \
      *) echo "Unsupported Gitleaks target architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${archive}"; \
    printf '%s  %s\n' "$checksum" /tmp/gitleaks.tar.gz | sha256sum --check --status; \
    mkdir -p /out; \
    tar -xzf /tmp/gitleaks.tar.gz -C /out gitleaks; \
    rm /tmp/gitleaks.tar.gz

FROM ${PYTHON_IMAGE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    REPOGUARD_ENV=production \
    REPOGUARD_SCAN_ROOT=/var/lib/repoguard/scans
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 repoguard \
    && useradd --system --uid 10001 --gid repoguard --home-dir /nonexistent --shell /usr/sbin/nologin repoguard \
    && mkdir -p "$REPOGUARD_SCAN_ROOT" \
    && chown -R repoguard:repoguard "$REPOGUARD_SCAN_ROOT"
COPY --from=gitleaks /out/gitleaks /usr/local/bin/gitleaks
COPY requirements.lock ./
RUN pip install --no-cache-dir --no-deps -r requirements.lock
COPY --chown=10001:10001 app ./app
COPY --chown=10001:10001 alembic ./alembic
COPY --chown=10001:10001 alembic.ini main.py ./
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=3)"]
CMD ["sh", "-c", "python -m alembic upgrade head && exec python -m uvicorn main:app --host 0.0.0.0 --port 8000 --no-proxy-headers"]
