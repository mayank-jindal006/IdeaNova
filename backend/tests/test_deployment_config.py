import asyncio
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import httpx
import pytest

from app import main
from app.settings import load_settings


_PRODUCTION_ENV = {
    "REPOGUARD_ENV": "production",
    "REPOGUARD_JWT_SECRET": "test-only-production-jwt-secret-0123456789",
    "DATABASE_URL": "postgresql+psycopg://test:test@localhost:5432/repoguard",
    "REPOGUARD_SCAN_ROOT": "",
    "GITHUB_TOKEN": "test-only-github-token",
    "GITHUB_WEBHOOK_SECRET": "test-only-webhook-secret",
    "CORS_ORIGINS": "https://repoguard.example.test",
    "REPOGUARD_ALLOWED_HOSTS": "repoguard-api.example.test,localhost",
}


def _set_production_environment(monkeypatch, tmp_path):
    for key, value in _PRODUCTION_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("REPOGUARD_SCAN_ROOT", str(tmp_path))


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("REPOGUARD_JWT_SECRET", "development-only-change-me", "REPOGUARD_JWT_SECRET"),
        ("REPOGUARD_JWT_SECRET", "repoguard-development-key-do-not-deploy", "REPOGUARD_JWT_SECRET"),
        ("REPOGUARD_ENV", "staging", "REPOGUARD_ENV"),
        ("DATABASE_URL", "sqlite:///./repoguard.db", "DATABASE_URL must configure PostgreSQL"),
        ("REPOGUARD_SCAN_ROOT", "", "REPOGUARD_SCAN_ROOT"),
        ("GITHUB_TOKEN", "", "GITHUB_TOKEN"),
        ("GITHUB_WEBHOOK_SECRET", "", "GITHUB_WEBHOOK_SECRET"),
        ("CORS_ORIGINS", "*", "CORS_ORIGINS"),
        ("CORS_ORIGINS", "http://repoguard.example.test", "CORS_ORIGINS"),
        ("CORS_ORIGINS", "https://*", "CORS_ORIGINS"),
        ("REPOGUARD_ALLOWED_HOSTS", "*", "REPOGUARD_ALLOWED_HOSTS"),
        ("DATABASE_URL", "postgresql+psycopg:///missing-host", "DATABASE_URL must configure PostgreSQL"),
        ("REPOGUARD_JWT_SECRET", "a" * 64, "high-entropy"),
        ("DB_POOL_SIZE", "0", "DB_POOL_SIZE"),
        ("REPOGUARD_AUTH_GLOBAL_RATE_LIMIT_PER_MINUTE", "0", "REPOGUARD_AUTH_GLOBAL_RATE_LIMIT_PER_MINUTE"),
    ],
)
def test_production_settings_fail_closed(monkeypatch, tmp_path, name, value, message):
    _set_production_environment(monkeypatch, tmp_path)
    monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError, match=message):
        load_settings()


def test_production_settings_accept_complete_postgresql_configuration(monkeypatch, tmp_path):
    _set_production_environment(monkeypatch, tmp_path)

    settings = load_settings()

    assert settings.environment == "production"
    assert settings.database_url.startswith("postgresql+psycopg://")
    assert settings.github_token == "test-only-github-token"
    assert settings.github_webhook_secret == "test-only-webhook-secret"
    assert settings.cors_origins == ("https://repoguard.example.test",)
    assert settings.allowed_hosts == ("repoguard-api.example.test", "localhost")
    assert settings.auth_rate_limit_per_minute == 10
    assert settings.auth_global_rate_limit_per_minute == 120


def test_production_settings_normalize_render_postgresql_url(monkeypatch, tmp_path):
    _set_production_environment(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgres://repoguard-test:synthetic-password@127.0.0.1:5432/repoguard",
    )

    settings = load_settings()

    assert settings.database_url.startswith("postgresql+psycopg://")


def test_production_settings_allow_loopback_http_for_local_compose(monkeypatch, tmp_path):
    _set_production_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:8080")

    settings = load_settings()

    assert settings.cors_origins == ("http://localhost:8080",)


def test_production_settings_reject_a_non_loopback_http_origin(monkeypatch, tmp_path):
    _set_production_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("CORS_ORIGINS", "http://dashboard.example.test")

    with pytest.raises(RuntimeError, match="HTTPS origins"):
        load_settings()


def test_docker_compose_jwt_generator_produces_a_production_valid_secret(tmp_path, monkeypatch):
    repository_root = Path(__file__).resolve().parents[2]
    workflow = (repository_root / ".github" / "workflows" / "phase7-deployment.yml").read_text(encoding="utf-8")
    step_match = re.search(
        r"(?ms)^      - name: Generate ephemeral container JWT key\n        run: \|\n(?P<body>.*?)(?=^      - name:|\Z)",
        workflow,
    )
    assert step_match is not None, "ephemeral JWT generation workflow step is missing"
    step_body = textwrap.dedent(step_match.group("body"))
    script_match = re.search(r"(?ms)^python - <<'PY'\n(?P<script>.*?)^PY$", step_body)
    assert script_match is not None, "JWT generation must use the tested Python generator"

    github_env = tmp_path / "github-env"
    environment = os.environ.copy()
    environment["GITHUB_ENV"] = str(github_env)
    result = subprocess.run(
        [sys.executable, "-c", script_match.group("script")],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == ""
    assert result.stderr == ""

    generated = re.fullmatch(r"REPOGUARD_JWT_SECRET=([^\r\n]+)\n", github_env.read_text(encoding="utf-8"))
    assert generated is not None
    secret = generated.group(1)
    assert len(secret.encode("utf-8")) >= 32
    assert len(set(secret)) >= 16

    _set_production_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("REPOGUARD_JWT_SECRET", secret)
    settings = load_settings()
    if settings.jwt_secret != secret:
        pytest.fail("Generated CI JWT secret was not preserved")


def test_docker_compose_smoke_workflow_supplies_required_compose_variables():
    repository_root = Path(__file__).resolve().parents[2]
    workflow = (repository_root / ".github" / "workflows" / "phase7-deployment.yml").read_text(encoding="utf-8")
    compose = (repository_root / "docker-compose.yml").read_text(encoding="utf-8")

    job_match = re.search(
        r"(?ms)^  docker-compose-smoke:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    assert job_match is not None, "docker-compose-smoke job is missing"
    job_body = job_match.group("body")
    env_match = re.search(r"(?ms)^    env:\n(?P<env>.*?)(?=^    steps:|\Z)", job_body)
    assert env_match is not None, "docker-compose-smoke job-level environment is missing"
    workflow_variables = set(re.findall(r"(?m)^      ([A-Z_][A-Z0-9_]*):", env_match.group("env")))

    required_compose_variables = set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*):\?", compose))
    assert required_compose_variables == {
        "POSTGRES_USER",
        "POSTGRES_DB",
        "POSTGRES_PASSWORD",
        "REPOGUARD_JWT_SECRET",
        "CORS_ORIGINS",
        "REPOGUARD_ALLOWED_HOSTS",
        "GITHUB_TOKEN",
        "GITHUB_WEBHOOK_SECRET",
    }
    assert re.search(
        r"(?ms)^      - name: Generate ephemeral container JWT key\n        run: \|\n.*?secrets\.token_urlsafe\(48\).*?GITHUB_ENV.*?production requirements.*?(?=^      - name:)",
        workflow,
    ), "docker-compose-smoke must securely generate and validate an ephemeral JWT key"
    assert required_compose_variables <= workflow_variables | {"REPOGUARD_JWT_SECRET"}

    allowed_hosts_match = re.search(
        r"(?m)^      REPOGUARD_ALLOWED_HOSTS:\s*(\S.*?)\s*$",
        env_match.group("env"),
    )
    assert allowed_hosts_match is not None
    assert allowed_hosts_match.group(1) == "localhost,127.0.0.1"


@pytest.mark.parametrize(
    ("location", "upstream_path"),
    [("= /health", "/health"), ("^~ /health/", "/health/")],
)
def test_nginx_health_proxy_forwards_validated_host(location, upstream_path, monkeypatch, tmp_path):
    repository_root = Path(__file__).resolve().parents[2]
    nginx = (repository_root / "nginx.conf").read_text(encoding="utf-8")
    location_match = re.search(
        rf"(?ms)^        location {re.escape(location)} \{{(?P<body>.*?)^        \}}",
        nginx,
    )
    assert location_match is not None, f"Nginx health location {location} is missing"
    location_body = location_match.group("body")

    assert f"proxy_pass http://backend:8000{upstream_path};" in location_body
    assert "proxy_http_version 1.1;" in location_body
    assert "proxy_set_header Host $host;" in location_body
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in location_body
    assert "proxy_set_header X-Forwarded-Host $host;" in location_body
    assert "proxy_set_header X-Forwarded-Proto $scheme;" in location_body

    _set_production_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:8080")
    monkeypatch.setenv("REPOGUARD_ALLOWED_HOSTS", "localhost,127.0.0.1")
    settings = load_settings()
    assert "127.0.0.1" in settings.allowed_hosts
    assert "localhost" in settings.allowed_hosts
    assert "*" not in settings.allowed_hosts

    dockerfile = (repository_root / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "--no-proxy-headers" in dockerfile


def test_production_trusted_host_accepts_nginx_host_and_rejects_upstream_host(monkeypatch, tmp_path):
    _set_production_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:8080")
    monkeypatch.setenv("REPOGUARD_ALLOWED_HOSTS", "localhost,127.0.0.1")
    production_settings = load_settings()
    monkeypatch.setattr(main, "settings", production_settings)
    app = main.create_app()

    async def exercise():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            accepted = await client.get(
                "/health/live",
                headers={"Host": "127.0.0.1", "X-Forwarded-Host": "spoofed.invalid"},
            )
            rejected = await client.get("/health/live", headers={"Host": "backend:8000"})

        assert accepted.status_code == 200
        assert rejected.status_code == 400

    asyncio.run(exercise())


def test_compose_smoke_probes_all_health_endpoints_through_nginx():
    repository_root = Path(__file__).resolve().parents[2]
    workflow = (repository_root / ".github" / "workflows" / "phase7-deployment.yml").read_text(encoding="utf-8")
    smoke_match = re.search(
        r"(?ms)^      - name: Run container deployment smoke test\n        run: \|\n(?P<body>.*?)(?=^      - name:|\Z)",
        workflow,
    )
    assert smoke_match is not None, "Compose deployment smoke step is missing"
    smoke_body = smoke_match.group("body")
    for path in ("/health", "/health/live", "/health/ready"):
        assert re.search(
            rf"(?m)^\s*curl --fail --silent --show-error http://127\.0\.0\.1:8080{re.escape(path)}$",
            smoke_body,
        )
