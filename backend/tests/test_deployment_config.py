import re
from pathlib import Path

import pytest

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
    jwt_key_generation = re.search(
        r'(?m)^\s*run:\s*echo "REPOGUARD_JWT_SECRET=\$\(openssl rand -hex 32\)" >> "\$GITHUB_ENV"$',
        job_body,
    )
    assert jwt_key_generation is not None, "docker-compose-smoke must generate its JWT key before Compose validation"
    assert required_compose_variables <= workflow_variables | {"REPOGUARD_JWT_SECRET"}

    allowed_hosts_match = re.search(
        r"(?m)^      REPOGUARD_ALLOWED_HOSTS:\s*(\S.*?)\s*$",
        env_match.group("env"),
    )
    assert allowed_hosts_match is not None
    assert allowed_hosts_match.group(1) == "localhost,127.0.0.1"
