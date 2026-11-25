# RepoGuard

RepoGuard is an AI-powered repository security dashboard for secret detection, dependency risk review, and developer-friendly remediation guidance.

## Overview

The stack combines:

- a React + Vite dashboard for repository and finding visibility
- a FastAPI backend for repository scanning and AI explanation
- Gitleaks-compatible scanning and report normalization
- secret redaction before any content reaches the LLM
- Gemini-backed remediation suggestions and risk summaries

## Architecture

Frontend -> API -> Repo scan service -> Gitleaks/regex scanning -> AI summarization

- Frontend: [src](src) provides repository, dashboard, and finding views.
- Backend: [backend/app](backend/app) exposes secure scan and explanation routes.
- Scan engine: [backend/app/services/gitleaks.py](backend/app/services/gitleaks.py) executes Gitleaks JSON reports when available and labels regex-only results as a fallback.
- Dependency engine: [backend/app/scanners/deps.py](backend/app/scanners/deps.py) discovers resolved npm/Python dependencies and queries the OSV QueryBatch API.
- Redaction: [backend/app/ai/redaction.py](backend/app/ai/redaction.py) masks variable-length secrets using exact line/column boundaries when available.
- AI prompt layer: [backend/app/services/ai_service.py](backend/app/services/ai_service.py) builds developer-safe prompt payloads.

## Local development

1. Start the backend:
   npm run dev:backend

2. Start the frontend:
   npm run dev

3. Open the dashboard at http://localhost:5173.

## Backend endpoints

- GET /health
- POST /api/repositories/scan
- POST /api/findings/explain

Interactive API documentation is available while the backend is running:

- Swagger UI: `http://localhost:8000/docs`
- OpenAPI schema: `http://localhost:8000/openapi.json`

## Environment

Set the following before enabling Gemini-backed recommendations:

- LLM_PROVIDER=gemini
- LLM_MODEL=<your Gemini model>
- LLM_API_KEY=<your API key>

The backend will gracefully fall back to safe rule-based guidance when the model configuration is not present.

Required scan isolation setting and optional hardening settings:

- REPOGUARD_SCAN_ROOT=<existing backend-managed directory for temporary repository clones>
- REPOGUARD_CORS_ORIGINS=<comma-separated frontend origins>
- REPOGUARD_MAX_SCAN_FILE_BYTES=1000000
- REPOGUARD_MAX_SOURCE_CONTEXT_CHARS=20000

For local development, create an operator-managed directory and set
`REPOGUARD_SCAN_ROOT` before starting the backend (for example, in
PowerShell: `$env:REPOGUARD_SCAN_ROOT = "D:\RepoGuardScans"`). The configured
directory must already exist and must not be writable by untrusted users.

The backend fails closed for scans when `REPOGUARD_SCAN_ROOT` is missing or
unavailable. Repository registration accepts a GitHub `owner/repository` name,
not a client filesystem path. The backend clones repositories into temporary
directories below the configured root, rejects canonical paths or symlinks
that escape it, and removes clones after scanning. Keep this directory
operator-managed and do not share it with untrusted writers.

## Test and validation

- Backend tests: pytest -q backend/tests
- Frontend build: npm run build

## Scanner prerequisites

RepoGuard first uses `GITLEAKS_BIN` when it is configured, then searches for
`gitleaks`/`gitleaks.exe` on `PATH`. To configure the Windows executable for the
current PowerShell session:

```powershell
$env:GITLEAKS_BIN = "$HOME\Downloads\gitleaks\gitleaks.exe"
& $env:GITLEAKS_BIN version
```

For persistent backend configuration, put the executable's absolute path in
`backend/.env`, for example:

```dotenv
GITLEAKS_BIN=C:\Users\<your-user>\Downloads\gitleaks\gitleaks.exe
```

The backend loads `backend/.env` at startup. A scan response identifies
`scanners.secrets.source` as `gitleaks` only when the binary actually ran and
its report was usable. When it is unavailable or its report cannot be used, the
response identifies `regex_fallback` and includes a safe reason; it never
presents fallback matches as Gitleaks output. Gitleaks exit code `1` is treated
as "leaks found" (not a process failure); other unexpected exit codes are
reported as fallback scans.

The backend Docker image installs Gitleaks `v8.30.1` from the official
[versioned release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
and verifies the amd64 or arm64 archive with the architecture-specific SHA-256
published in that release's `gitleaks_8.30.1_checksums.txt` before extraction.
To update it, review a versioned upstream release, copy its exact official
checksums into `backend/Dockerfile`, update the pinned version, and run the
Dockerfile verification test. Do not use the mutable `master` install script
or execute downloaded installer scripts.

OSV scans use `https://api.osv.dev/v1/querybatch`. They query exact versions from `package-lock.json`, `poetry.lock`, or `Pipfile.lock` first, plus pinned `requirements.txt` entries and exact `package.json` versions when no lockfile provides that package. The response reports `completed`, `skipped`, or `unavailable` for dependency scanning.

## Production notes

- Secret values are redacted before any LLM prompt is built.
- Findings are returned as redacted model objects to the UI.
- Column metadata is preserved and used when available for precise masking.
- The scan engine supports both real Gitleaks JSON and a safe repository fallback when the binary is unavailable.
