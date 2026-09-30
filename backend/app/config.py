from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _normalize_postgres_url(value: str) -> str:
    """Encode reserved password characters in legacy local DATABASE_URL values.

    SQLAlchemy URLs require an `@` in a password to be percent-encoded.  Using
    the final `@` as the authority separator preserves a local hostname such as
    `localhost` while fixing values copied directly from a password manager.
    """
    if not value.startswith(("postgresql://", "postgresql+psycopg://")):
        return value
    scheme, remainder = value.split("://", 1)
    authority, separator, path = remainder.partition("/")
    userinfo, at, host = authority.rpartition("@")
    if not at or ":" not in userinfo:
        return value
    user, password = userinfo.split(":", 1)
    return f"{scheme}://{user}:{quote(password, safe='%')}@{host}{separator}{path}"


class Settings(BaseSettings):
    # Local Windows development defaults to the local PostgreSQL service.
    # Docker supplies its own DATABASE_URL with the `postgres` hostname.
    database_url: str = "postgresql+psycopg://postgres@localhost:5432/repoguard"
    github_token: str | None = None
    github_webhook_secret: str | None = None
    gitleaks_bin: str = "gitleaks"
    osv_api_url: str = "https://api.osv.dev/v1/querybatch"
    cors_origins: str = "http://localhost:5173,http://localhost:5174"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=Path(__file__).resolve().parent.parent / ".env", extra="ignore")

    @field_validator("database_url", mode="before")
    @classmethod
    def normalize_database_url(cls, value: str) -> str:
        return _normalize_postgres_url(value)

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Canonical import for the app, Alembic, and local validation commands.
settings = get_settings()
