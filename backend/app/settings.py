from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


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
    jwt_secret: str
    jwt_expiry_minutes: int
    environment: str


def load_settings() -> Settings:
    environment = os.getenv("REPOGUARD_ENV", "development").lower()
    jwt_secret = os.getenv("REPOGUARD_JWT_SECRET", "development-only-change-me")
    if environment in {"production", "prod"} and (len(jwt_secret) < 32 or jwt_secret == "development-only-change-me"):
        raise RuntimeError("REPOGUARD_JWT_SECRET must be a high-entropy value in production")
    return Settings(
        database_url=os.getenv("DATABASE_URL", "sqlite:///./repoguard.db"),
        github_token=os.getenv("GITHUB_TOKEN") or None,
        github_webhook_secret=os.getenv("GITHUB_WEBHOOK_SECRET") or None,
        llm_provider=os.getenv("LLM_PROVIDER", "gemini").lower(),
        llm_model=os.getenv("GEMINI_MODEL") or os.getenv("LLM_MODEL") or None,
        llm_api_key=os.getenv("GEMINI_API_KEY") or os.getenv("LLM_API_KEY") or None,
        llm_base_url=os.getenv("LLM_BASE_URL") or None,
        llm_timeout_seconds=float(os.getenv("LLM_TIMEOUT", "60")),
        osv_timeout_seconds=float(os.getenv("OSV_TIMEOUT_SECONDS", "15")),
        scan_timeout_seconds=int(os.getenv("SCAN_TIMEOUT_SECONDS", "120")),
        cors_origins=tuple(value.strip() for value in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if value.strip()),
        jwt_secret=jwt_secret,
        jwt_expiry_minutes=int(os.getenv("JWT_EXPIRY_MINUTES", "30")),
        environment=environment,
    )


settings = load_settings()
