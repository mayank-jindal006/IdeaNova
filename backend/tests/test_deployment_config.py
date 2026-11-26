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
}


def _set_production_environment(monkeypatch, tmp_path):
    for key, value in _PRODUCTION_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("REPOGUARD_SCAN_ROOT", str(tmp_path))


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("REPOGUARD_JWT_SECRET", "development-only-change-me", "REPOGUARD_JWT_SECRET"),
        ("DATABASE_URL", "sqlite:///./repoguard.db", "DATABASE_URL must configure PostgreSQL"),
        ("REPOGUARD_SCAN_ROOT", "", "REPOGUARD_SCAN_ROOT"),
        ("GITHUB_TOKEN", "", "GITHUB_TOKEN"),
        ("GITHUB_WEBHOOK_SECRET", "", "GITHUB_WEBHOOK_SECRET"),
        ("CORS_ORIGINS", "*", "CORS_ORIGINS"),
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
