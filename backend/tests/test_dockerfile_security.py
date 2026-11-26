from pathlib import Path
import re


def test_dockerfile_uses_a_versioned_checksum_verified_gitleaks_release():
    dockerfile = Path(__file__).parents[1].joinpath("Dockerfile").read_text(encoding="utf-8")

    assert "ARG GITLEAKS_VERSION=8.30.1" in dockerfile
    assert "releases/download/v${GITLEAKS_VERSION}/${archive}" in dockerfile
    assert "sha256sum --check --status" in dockerfile
    assert "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" in dockerfile
    assert "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" in dockerfile
    assert not re.search(r"raw\.githubusercontent\.com/.+/(?:main|master)/", dockerfile)
    assert not re.search(r"curl[^\n]*\|\s*(?:sh|bash)", dockerfile)
    assert "FROM ${PYTHON_IMAGE} AS runtime" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "pip install --no-cache-dir --no-deps -r requirements.lock" in dockerfile
    assert "COPY --from=gitleaks /out/gitleaks /usr/local/bin/gitleaks" in dockerfile


def test_runtime_dependencies_are_fully_pinned_without_pytest():
    requirements = Path(__file__).parents[1].joinpath("requirements.txt").read_text(encoding="utf-8")
    lock = Path(__file__).parents[1].joinpath("requirements.lock").read_text(encoding="utf-8")

    assert all("==" in line for line in requirements.splitlines() if line.strip())
    assert all("==" in line for line in lock.splitlines() if line.strip())
    assert not re.search(r"(?im)^pytest(?:\[|=|<|>|!|~)", requirements)
    assert not re.search(r"(?im)^pytest(?:\[|=|<|>|!|~)", lock)


def test_compose_uses_persistent_postgres_and_protected_internal_backend():
    root = Path(__file__).parents[2]
    compose = root.joinpath("docker-compose.yml").read_text(encoding="utf-8")
    dockerignore = root.joinpath(".dockerignore").read_text(encoding="utf-8")

    assert "postgres:18-alpine@sha256:" in compose
    assert "postgres_data:/var/lib/postgresql" in compose
    assert "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?" in compose
    assert "condition: service_healthy" in compose
    assert "REPOGUARD_ENV: production" in compose
    assert "REPOGUARD_SCAN_ROOT: /var/lib/repoguard/scans" in compose
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "backend-node" in dockerignore
    assert not re.search(r"(?m)^\s+ports:", compose.split("  backend:", 1)[1].split("  frontend:", 1)[0])


def test_frontend_image_is_digest_pinned_and_proxies_api_to_backend():
    root = Path(__file__).parents[2]
    dockerfile = root.joinpath("frontend.Dockerfile").read_text(encoding="utf-8")
    nginx = root.joinpath("nginx.conf").read_text(encoding="utf-8")

    assert "node:22-alpine@sha256:" in dockerfile
    assert "nginx:1.28-alpine@sha256:" in dockerfile
    assert "npm ci" in dockerfile
    assert "USER 101:101" in dockerfile
    assert 'CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1' in dockerfile
    assert 'CMD ["CMD-SHELL"' not in dockerfile
    assert "proxy_pass http://backend:8000/api/" in nginx
    assert "proxy_pass http://backend:8000/health" in nginx
