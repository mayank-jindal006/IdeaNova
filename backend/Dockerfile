FROM python:3.11-slim
WORKDIR /app
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
ENV REPOGUARD_SCAN_ROOT=/var/lib/repoguard/scans
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$REPOGUARD_SCAN_ROOT" \
    && chmod 700 "$REPOGUARD_SCAN_ROOT"
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) archive="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; checksum="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" ;; \
      arm64) archive="gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz"; checksum="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" ;; \
      *) echo "Unsupported Gitleaks target architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${archive}"; \
    printf '%s  %s\n' "$checksum" /tmp/gitleaks.tar.gz | sha256sum --check --status; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    rm /tmp/gitleaks.tar.gz
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port 8000"]
