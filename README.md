# RepoGuard

RepoGuard scans tracked GitHub repositories for secrets and vulnerable Python/npm dependencies, records findings, integrates the team compliance/risk/AI modules, and opens review-only GitHub pull requests for generated fixes.

## Start locally

1. Copy `backend/.env.example` to `backend/.env` and configure the required values.
2. For local development, start PostgreSQL, then run the backend from `backend/` with `python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8002`.
3. In a second terminal at the project root, run `npm ci` and `npm run dev -- --host 0.0.0.0`.
4. Open `http://localhost:5173`; the frontend calls `http://localhost:8002/api`. The API health endpoint is `http://localhost:8002/health`.

Alternatively, run `docker compose up --build`. The backend is published on host port `8002`, PostgreSQL on `5432`, and Vite on `5173`. Set `VITE_API_BASE_URL` to override the frontend API origin; it defaults to `http://localhost:8002`.

The backend applies Alembic migration `0001_initial` on startup. The database volume is retained as `postgres_data`.

## Security guarantees

- Gitleaks runs in a temporary full-history clone; clone directories are removed after each scan.
- Raw secret values are never persisted. Only a masked value and SHA-256 hash are stored.
- Pull requests are never merged automatically.
- A history-only finding stays visible for credential rotation.

## Required environment variables

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | SQLAlchemy PostgreSQL connection URL |
| `GITHUB_TOKEN` | Fine-grained GitHub PAT |
| `GITHUB_WEBHOOK_SECRET` | HMAC secret for GitHub webhook verification |
| `GITLEAKS_BIN` | Gitleaks executable path |
| `OSV_API_URL` | OSV QueryBatch endpoint |
| `CORS_ORIGINS` | Comma-separated frontend origins |

## API

All product API endpoints are prefixed with `/api`. Scan requests return immediately with a queued scan identifier; clients poll `GET /api/scans/{id}`. Errors use `{"error":{"code":"...","message":"..."}}`.

## Team-owned modules

The scan pipeline imports `app.compliance.score.map_controls`, `compute_compliance`, and `app.risk.heuristic.compute_risk` when they are merged. The fix endpoint integrates `app.ai.fix.generate_fix` once the AI module and its safe repository-content/redaction adapter are merged. This backend does not implement those owners’ business logic.
