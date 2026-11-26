from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Load a backend-local file regardless of the directory uvicorn was started from.
load_dotenv(Path(__file__).resolve().parents[2] / ".env")


@dataclass(frozen=True, slots=True)
class Settings:
    app_name: str = "RepoGuard API"
    app_version: str = "1.1.0"
    scan_root: Path | None = None
    max_scan_file_bytes: int = 1_000_000
    max_source_context_chars: int = 20_000
    cors_origins: tuple[str, ...] = ("http://localhost:5173",)

    @classmethod
    def from_environment(cls) -> "Settings":
        root = os.getenv("REPOGUARD_SCAN_ROOT", "").strip()
        max_file_bytes = int(os.getenv("REPOGUARD_MAX_SCAN_FILE_BYTES", "1000000"))
        max_context_chars = int(os.getenv("REPOGUARD_MAX_SOURCE_CONTEXT_CHARS", "20000"))
        origins = tuple(origin.strip() for origin in os.getenv("REPOGUARD_CORS_ORIGINS", "http://localhost:5173").split(",") if origin.strip())
        return cls(
            scan_root=Path(root).expanduser() if root else None,
            max_scan_file_bytes=max(1, max_file_bytes),
            max_source_context_chars=max(1, max_context_chars),
            cors_origins=origins,
        )


settings = Settings.from_environment()
