# RepoGuard deployment

This guide covers the PostgreSQL-backed FastAPI service and the React
dashboard. The unrelated `backend-node/` Commerce application is not included.
Do not treat a successful build or health check as proof of the live GitHub,
OSV, or AI provider integrations.

## Requirements

- Docker Engine with Docker Compose v2.
- Outbound HTTPS from the backend to GitHub and `https://api.osv.dev`.
- A GitHub token permitted to read the repositories that RepoGuard will scan.
- A private webhook secret if GitHub push webhooks are enabled.
- A TLS-terminating reverse proxy or platform ingress for deployments beyond
  local development.

The checked-in Compose file binds no PostgreSQL host port. PostgreSQL is
reachable only by services on the Compose network, and its data persists in
the `postgres_data` volume. The backend runs as UID/GID 10001, uses a
read-only root filesystem, and stores temporary checkouts in a bounded,
non-executable in-memory scan volume. The frontend runs as UID/GID 101 on
port 8080 and proxies `/api` and `/health` to FastAPI.

## Configure secrets

From the repository root in PowerShell, create a local-only `.env` file without
overwriting an existing one:

```powershell
if (Test-Path -LiteralPath .env) {
    throw "A .env file already exists; preserve it and update it using your secret manager."
}
Copy-Item -LiteralPath .env.example -Destination .env

function New-UrlSafeSecret {
    $bytes = [byte[]]::new(48)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$jwtSecret = New-UrlSafeSecret
$databasePassword = New-UrlSafeSecret
```

Set `POSTGRES_PASSWORD` to `$databasePassword` and `REPOGUARD_JWT_SECRET` to
`$jwtSecret` in the local `.env` using a protected editor. The generated
database password is URL-safe because Compose places it in `DATABASE_URL`.
Set `GITHUB_TOKEN` and `GITHUB_WEBHOOK_SECRET` from a secret manager or
protected editor; never commit `.env` or paste secret values into logs or
support tickets. A GitHub token and webhook secret are required by the current
production configuration even when webhooks are not yet enabled.

Keep `CORS_ORIGINS` aligned with the browser-visible dashboard origin (for
example, `http://localhost:8080` for local Compose). Use the final HTTPS origin
in production. `LLM_API_KEY` is optional; without provider configuration,
finding explanations use the rule-based fallback. OSV uses its public API and
does not require a key.

## Build, migrate, and start

The runtime images use pinned base-image digests. The backend image verifies
the pinned Gitleaks `v8.30.1` release checksum and installs the fully pinned
Python dependency closure from `backend/requirements.lock`. The frontend runs
`npm ci` against the checked-in `package-lock.json`.

```powershell
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
Invoke-RestMethod http://localhost:8080/health/live
Invoke-RestMethod http://localhost:8080/health/ready
docker compose exec backend python -m alembic current
```

The backend startup command runs `python -m alembic upgrade head` before starting
Uvicorn. The following explicit command is also available for a reviewed
maintenance window; take and verify a database backup before migrations:

```powershell
docker compose exec backend python -m alembic upgrade head
docker compose exec backend python -m alembic check
```

To follow service logs without exposing environment values:

```powershell
docker compose logs --tail 100 db backend frontend
```

The frontend is at `http://localhost:8080`. Register an account through the
login/register screen. The FastAPI docs are intentionally disabled in
production mode.

## CI deployment verification

The dedicated [Phase 7 GitHub Actions workflow](./.github/workflows/phase7-deployment.yml)
runs on pushes to `phase7-deployment-readiness`, pull requests targeting
`integration`, and manual dispatch. It uses synthetic credentials and a fresh
PostgreSQL service database to run migration checks, the backend suite, and the
live synthetic Gitleaks/OSV end-to-end test. A separate Ubuntu job builds both
images and starts the Compose stack to check health, database readiness,
migrations, frontend-to-API routing, backend restart, and graceful shutdown.
Treat these as verified only after the corresponding workflow run succeeds.

## PostgreSQL verification and backups

The backend requires `postgresql+psycopg` in production. Readiness executes a
database query and returns 503 until PostgreSQL is reachable. SQLAlchemy uses
`pool_pre_ping`; pool size and overflow can be tuned with `DB_POOL_SIZE` and
`DB_MAX_OVERFLOW`. Request sessions are closed by the FastAPI dependency.

The database volume is named `postgres_data`. Back up PostgreSQL before
upgrading the schema or changing volumes. Restore into a separate database
first and verify the restored migration head and application behavior. Do not
use `docker compose down -v` on a database containing data; that removes the
named database volume.

Migration downgrade is not part of routine deployment. Revision 0007 refuses
to restore global repository uniqueness while duplicate repository names
exist, and token revocation records are removed by downgrading. Review the
migration and backup before any downgrade.

## Scanner behavior

- **Gitleaks:** the backend image includes the versioned `v8.30.1` executable;
  its architecture-specific release checksum is verified during image build.
  Findings are redacted before persistence/API output. Temporary scan
  checkouts are removed after the scan.
- **OSV:** dependency resolution queries `https://api.osv.dev/v1/querybatch`.
  The backend needs outbound HTTPS. Advisory severity remains `null` when OSV
  supplies no severity. Timeouts and network errors are represented as a safe
  scanner-unavailable status rather than invented findings.
- **GitHub:** configure `GITHUB_TOKEN` and `GITHUB_WEBHOOK_SECRET`. Clone errors
  are sanitized; credentials must not appear in clone arguments, logs, or
  persistent Git configuration.
- **AI:** provider keys are optional. If unset or unavailable, explanation
  requests use the rule-based fallback. Do not treat fallback output as
  provider-generated advice.

Never scan a repository containing secrets for deployment smoke tests. Use
disposable repositories with synthetic data.

## Health checks and operations

| Endpoint | Meaning |
| --- | --- |
| `/health/live` | FastAPI process is responding. |
| `/health/ready` | FastAPI can connect to PostgreSQL. |
| `/health` | Backward-compatible liveness response. |

Compose waits for PostgreSQL health before starting FastAPI and waits for
backend readiness before starting the frontend. PostgreSQL is not exposed on
the host. Terminate TLS at a trusted ingress, restrict ingress to the frontend,
and keep database, JWT, GitHub, and AI secrets in the deployment platform's
secret manager for production.

## Development and test commands

From the repository root:

```powershell
npm ci
npm run lint
npm run build
```

For backend tests, use Python 3.13 and install the pinned development set from
`backend/requirements-dev.txt`. PostgreSQL integration tests only run when
`REPOGUARD_PG_TEST_URL` points to a disposable loopback database whose name
starts with `repoguard_phase7`. Live scanner end-to-end coverage additionally
requires `REPOGUARD_LIVE_SCANNER_TESTS=1` and `GITLEAKS_BIN` pointing to the
verified executable. Never point those tests at a production database.

```powershell
Push-Location backend
python -m pip install -r requirements-dev.txt
python -m pytest tests -q
Pop-Location
```

Run the PostgreSQL integration tests only after creating and migrating a
disposable database:

```powershell
$env:REPOGUARD_PG_TEST_URL = "postgresql+psycopg://<user>:<url-safe-password>@127.0.0.1:5432/repoguard_phase7_test"
$env:PYTHON_DOTENV_DISABLED = "1"
Push-Location backend
python -m alembic upgrade head
python -m pytest tests/test_postgresql_integration.py -q
Pop-Location
```

Add `REPOGUARD_LIVE_SCANNER_TESTS=1` and set `GITLEAKS_BIN` only when the
disposable test repository and the live OSV endpoint are intentionally
available. The end-to-end test executes Gitleaks and makes real OSV requests;
it does not clone a real GitHub repository or call a live LLM.

The GitHub client requires `GITHUB_TOKEN` for clone operations, including
public repositories; clone authentication is supplied only to the Git process
and is not stored in clone arguments or Git configuration. A live GitHub
transport test requires an authorized token and a safe read-only test
repository. Gemini verification requires an operator-provided authorized
provider configuration. Missing credentials must be reported as unverified;
the rule-based explanation fallback is not evidence of a live Gemini call.

## Troubleshooting

- **Compose rejects missing variables:** populate all required values in
  `.env`; Compose intentionally refuses empty database, JWT, GitHub, webhook,
  or CORS settings.
- **Backend is unhealthy:** check `docker compose logs backend db`, database
  health, connection settings, and whether Alembic reached the current head.
  Never publish the database port to work around an internal connection
  problem.
- **Scanning returns unavailable:** verify the scan volume is mounted and
  writable by UID 10001, GitHub access is allowed, and outbound HTTPS is
  available. Do not disable trusted-root checks.
- **Dependencies are unavailable:** allow outbound access to OSV or report the
  scanner as unavailable. Do not infer vulnerability results from package
  names or offline cache.
- **Docker is unavailable:** use a separately managed PostgreSQL instance and
  Python 3.13 for backend work, but report image build and container runtime as
  unverified until Docker Compose is actually run.

## Verification limitations

Image construction, Compose startup, and container health must be verified on
a machine with Docker/Compose. Live Gitleaks and OSV calls verify scanner
behavior, not production egress, throughput, or service availability. Review
and test the actual deployment environment, TLS ingress, secret manager,
backup/restore process, and GitHub permissions before describing a deployment
as production ready.
