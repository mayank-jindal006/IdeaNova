# RepoGuard

RepoGuard is an authenticated repository security dashboard for secret
detection, dependency risk review, persisted scan history, and human-reviewed
AI-assisted remediation.

## Overview

The stack combines:

- an authenticated React + Vite dashboard for repositories, findings, scan
  history, remediation review, and security activity
- a FastAPI backend for tenant-scoped repository scanning, persistence, and AI
  explanations/proposals
- Gitleaks-compatible scanning and report normalization
- secret redaction before any content reaches the LLM
- Gemini-backed remediation proposals with explicit approval and validation
  gates, plus safe rule-based fallback guidance

## Architecture

Frontend -> authenticated API -> PostgreSQL -> isolated scan/fix checkout
                               -> Gitleaks + OSV -> Gemini guidance/proposals

- Frontend: [src](src) provides authenticated repository, dashboard, finding,
  remediation review, and audit history views.
- Backend: [backend/app](backend/app) exposes tenant-scoped scan, history,
  finding, review, audit, and GitHub integration routes.
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
- POST /api/auth/register and POST /api/auth/login
- GET /api/repos and POST /api/repos/{repo_id}/scan
- GET /api/repos/{repo_id}/scans and GET /api/scans/{scan_id}/findings
- POST /api/findings/{finding_id}/explain and POST /api/findings/{finding_id}/fix
- POST /api/fixes/{fix_id}/review, /validate, and /open-pr
- GET /api/audit-logs

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
unavailable. GitHub repository registration accepts an `owner/repository` name.
The backend clones GitHub repositories into temporary
directories below the configured root, rejects canonical paths or symlinks
that escape it, and removes clones after scanning. Keep this directory
operator-managed and do not share it with untrusted writers.

For a trusted single-user development installation, local Git repositories can
also be registered from the repository dialog. Set `REPOGUARD_LOCAL_SCAN_ENABLED`
to `true` and place the repository inside the existing `REPOGUARD_SCAN_ROOT`.
Every authenticated user of that server can request scanning of repositories
within that root, so do not enable this mode on a shared or public service.
The backend validates paths again at scan time and never removes a local checkout.

For a fresh local SQLite database, set `DATABASE_URL` to a SQLite URL and run
`$env:PYTHONPATH = 'backend'; .\.venv-py313\Scripts\python.exe -m alembic -c backend\alembic.ini upgrade head`
from the repository root. Back up an existing database before applying migrations.
The existing PostgreSQL database configuration remains supported. Database
connectivity can be checked at `/health/database`.

## Test and validation

- Backend tests (Python 3.13 environment): `Set-Location backend; python -m pytest -q tests`
- Frontend build: npm run build
- Frontend lint: npm run lint
- Database migration: `alembic upgrade head` from `backend/` with the
  deployment database configured. Migration `0007` adds per-scan finding
  history, fix reviews, AI-request metadata, and audit records.

## Persisted remediation lifecycle

The authenticated UI creates a database-backed, single-file remediation
proposal and shows its generated patch for review. A user must explicitly
approve or reject it. Only an approved proposal can be validated in a
disposable checkout; RepoGuard does not execute repository-provided test
commands. Opening a GitHub pull request requires a successful security rescan,
an unchanged source hash, and the explicit approval. The resulting pull request
is a real external review request and is never merged automatically.

For local repositories, proposal generation is limited to an exact-pinned
`requirements.txt` entry when OSV supplied a fixed version. The complete
manifest must contain only supported exact pins; the generated replacement is
checked against the single advisory-backed change. Dependency compatibility is
not established by that check. After explicit approval, validation copies the
repository into a temporary workspace and compares Gitleaks working-tree and
OSV results before and after the proposal. Repository test commands are not
run. A passing security rescan does not mark the original finding resolved or
apply the patch to the original repository; local patch application is not
implemented. Secret findings remain guidance-only and require rotation.
Local approvals created after migration `0009` are bound to the exact proposal
and source hash. Older local approvals without this digest cannot be validated;
generate and review a new proposal. The original-file apply action remains
disabled because atomic replacement alone does not prevent concurrent edits.
Approved and security-validated local exact-pin proposals may be downloaded as
a patch and integrity manifest for manual review; see [manual patch export](docs/MANUAL_PATCH_EXPORT.md).

The separate [`backend-node/`](backend-node) Commerce application is not part
of the RepoGuard security API or its authentication boundary.

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
