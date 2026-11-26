from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy.engine import make_url
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

_DEVELOPMENT_JWT_SECRET = "repoguard-development-key-do-not-deploy"


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    github_token: str | None
    github_webhook_secret: str | None
    llm_provider: str
    llm_model: str | None
    llm_api_key: str | None
    llm_base_url: str | None
    llm_timeout_seconds: float
    osv_timeout_seconds: float
    scan_timeout_seconds: int
    cors_origins: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    max_request_bytes: int
    auth_rate_limit_per_minute: int
    auth_global_rate_limit_per_minute: int
    database_pool_size: int
    database_max_overflow: int
    database_pool_timeout_seconds: int
    jwt_secret: str
    jwt_expiry_minutes: int
    environment: str


def _integer_setting(name: str, default: int, *, minimum: int = 1) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        raise RuntimeError(f"{name} must be an integer") from None
    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}")
    return value


def _normalize_database_url(value: str) -> str:
    try:
        url = make_url(value)
    except (ValueError, TypeError):
        raise RuntimeError("DATABASE_URL is invalid") from None
    if url.drivername in {"postgres", "postgresql"}:
        return url.set(drivername="postgresql+psycopg").render_as_string(hide_password=False)
    return value


def _is_secure_origin(origin: str) -> bool:
    try:
        parsed = urlsplit(origin)
        loopback_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        port = parsed.port
        return (
            (parsed.scheme == "https" or loopback_http)
            and bool(parsed.netloc)
            and bool(parsed.hostname)
            and "*" not in parsed.netloc
            and (port is None or 1 <= port <= 65535)
            and parsed.username is None
            and parsed.password is None
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


def load_settings() -> Settings:
    environment = os.getenv("REPOGUARD_ENV", "development").lower()
    if environment not in {"development", "test", "production", "prod"}:
        raise RuntimeError("REPOGUARD_ENV must be development, test, or production")
    jwt_secret = os.getenv("REPOGUARD_JWT_SECRET", _DEVELOPMENT_JWT_SECRET)
    database_url = _normalize_database_url(os.getenv("DATABASE_URL", "sqlite:///./repoguard.db"))
    cors_origins = tuple(
        value.strip()
        for value in os.getenv(
            "CORS_ORIGINS",
            os.getenv("REPOGUARD_CORS_ORIGINS", "http://localhost:5173"),
        ).split(",")
        if value.strip()
    )
    allowed_hosts = tuple(
        value.strip()
        for value in os.getenv("REPOGUARD_ALLOWED_HOSTS", "*").split(",")
        if value.strip()
    )
    scan_root = os.getenv("REPOGUARD_SCAN_ROOT", "").strip()
    github_token = os.getenv("GITHUB_TOKEN", "").strip() or None
    github_webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").strip() or None
    max_request_bytes = _integer_setting("REPOGUARD_MAX_REQUEST_BYTES", 25 * 1024 * 1024)
    auth_rate_limit = _integer_setting("REPOGUARD_AUTH_RATE_LIMIT_PER_MINUTE", 10)
    auth_global_rate_limit = _integer_setting("REPOGUARD_AUTH_GLOBAL_RATE_LIMIT_PER_MINUTE", 120)
    pool_size = _integer_setting("DB_POOL_SIZE", 5)
    max_overflow = _integer_setting("DB_MAX_OVERFLOW", 10, minimum=0)
    pool_timeout = _integer_setting("DB_POOL_TIMEOUT_SECONDS", 30)
    jwt_expiry_minutes = _integer_setting("JWT_EXPIRY_MINUTES", 30)
    if environment in {"production", "prod"}:
        if (
            jwt_secret == _DEVELOPMENT_JWT_SECRET
            or len(jwt_secret.encode("utf-8")) < 32
            or len(set(jwt_secret)) < 16
        ):
            raise RuntimeError("REPOGUARD_JWT_SECRET must be a high-entropy value in production")
        try:
            parsed_database_url = make_url(database_url)
        except (ValueError, TypeError):
            raise RuntimeError("DATABASE_URL must configure PostgreSQL in production") from None
        if (
            parsed_database_url.drivername != "postgresql+psycopg"
            or not parsed_database_url.host
            or not parsed_database_url.database
        ):
            raise RuntimeError("DATABASE_URL must configure PostgreSQL with psycopg in production")
        scan_path = Path(scan_root).expanduser() if scan_root else None
        if not scan_path or not scan_path.is_absolute() or not scan_path.is_dir() or not os.access(scan_path, os.W_OK):
            raise RuntimeError("REPOGUARD_SCAN_ROOT must be an existing writable directory in production")
        if not github_token:
            raise RuntimeError("GITHUB_TOKEN is required in production")
        if not github_webhook_secret:
            raise RuntimeError("GITHUB_WEBHOOK_SECRET is required in production")
        if not cors_origins or any(not _is_secure_origin(origin) for origin in cors_origins):
            raise RuntimeError("CORS_ORIGINS must contain HTTPS origins or explicit loopback HTTP origins")
        if not allowed_hosts or any("*" in host or "/" in host for host in allowed_hosts):
            raise RuntimeError("REPOGUARD_ALLOWED_HOSTS must contain explicit hostnames in production")
    return Settings(
        database_url=database_url,
        github_token=github_token,
        github_webhook_secret=github_webhook_secret,
        llm_provider=os.getenv("LLM_PROVIDER", "gemini").lower(),
        llm_model=os.getenv("LLM_MODEL") or None,
        llm_api_key=os.getenv("LLM_API_KEY") or None,
        llm_base_url=os.getenv("LLM_BASE_URL") or None,
        llm_timeout_seconds=float(os.getenv("LLM_TIMEOUT", "60")),
        osv_timeout_seconds=float(os.getenv("OSV_TIMEOUT_SECONDS", "15")),
        scan_timeout_seconds=int(os.getenv("SCAN_TIMEOUT_SECONDS", "120")),
        cors_origins=cors_origins,
        allowed_hosts=allowed_hosts,
        max_request_bytes=max_request_bytes,
        auth_rate_limit_per_minute=auth_rate_limit,
        auth_global_rate_limit_per_minute=auth_global_rate_limit,
        database_pool_size=pool_size,
        database_max_overflow=max_overflow,
        database_pool_timeout_seconds=pool_timeout,
        jwt_secret=jwt_secret,
        jwt_expiry_minutes=jwt_expiry_minutes,
        environment=environment,
    )


settings = load_settings()
