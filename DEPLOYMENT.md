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

## Recommended live architecture: Render

The checked-in [Render Blueprint](./render.yaml) describes a public static
React site, a public FastAPI service, and a managed PostgreSQL database in the
same region. Render provides HTTPS for the public services; PostgreSQL is
restricted to private-network connections. The frontend calls the API over
HTTPS, and the same API URL is used for GitHub webhooks. This keeps the browser
and GitHub integrations reachable without exposing the database.

The Blueprint selects one 1-CPU/2-GB API instance and a 0.5-CPU/1-GB PostgreSQL
plan; the static site is hosted separately. These are starting resource sizes,
not a verified price estimate or capacity guarantee. Review current Render
pricing, database backup retention, region availability, and expected scan
load before creating resources. The Blueprint disables automatic deploys so
connecting the repository does not silently deploy every later commit.

Expected initial URLs are `https://repoguard-web.onrender.com` for the
dashboard and `https://repoguard-api.onrender.com` for the API. Service names
must be available in the Render workspace. If Render assigns different
domains or you add custom domains, update `VITE_API_BASE_URL` at the frontend,
`REPOGUARD_CORS_ORIGINS` and `REPOGUARD_ALLOWED_HOSTS` at the backend, and the
matching Content Security Policy before deploying.

### Required production configuration

Render generates `REPOGUARD_JWT_SECRET` and prompts for `GITHUB_TOKEN` and
`GITHUB_WEBHOOK_SECRET` through its protected environment-variable flow. Use a
read-only GitHub token with access only to repositories RepoGuard must scan.
Keep the webhook secret independent from the JWT and database credentials.
`LLM_API_KEY` is optional; the application keeps its rule-based explanation
fallback when no provider key is configured. OSV uses its public API.

The deployment uses the platform-provided PostgreSQL connection string. The
backend normalizes Render's `postgres://` / `postgresql://` schemes to the
existing `postgresql+psycopg` driver without logging the credentials. Do not
copy a production connection string into a file or terminal transcript.

FastAPI and Uvicorn do not trust forwarded client or scheme headers. The
application cannot be made to use a caller-supplied `X-Forwarded-For` value
as its client identity. The public Render endpoint supplies HTTPS; production
responses include HSTS independently of the internal HTTP connection.
Authentication limits are keyed by a SHA-256 digest of normalized account
email (10 attempts per account per minute by default) and also enforce a
process-wide ceiling (120 per minute by default). Render is configured for a
single API instance. Do not scale it horizontally unless the limiter is moved
to shared storage.

### Manual launch steps

1. Review and merge the deployment change into `integration` using the normal
   repository approval process. No deployment, commit, or push is performed
   by this local workflow.
2. Create/authorize a Render account, connect `mayank-jindal006/IdeaNova`, and
   create a Blueprint from the `integration` branch. Review the services and
   paid resource sizes before confirming resource creation.
3. Enter the GitHub token and webhook secret through Render's secret prompts.
   Never paste them into GitHub issues, build commands, or logs.
4. Confirm Render's actual API and frontend domains match the Blueprint
   origins. For custom domains, configure DNS and update the host, CORS,
   frontend API URL, and CSP settings together.
5. In GitHub, add a push webhook pointing to
   `https://repoguard-api.onrender.com/api/webhooks/github`, select
   `application/json`, enter the same private webhook secret, and enable the
   push event. Verify signature delivery in GitHub without printing payload
   secrets.
6. Confirm the managed database is private, backups are enabled with a
   retention policy suitable for the data, and the Render PostgreSQL internal
   connection is linked to `DATABASE_URL`.
7. Review the migration command and backup state, then explicitly deploy the
   API and frontend in Render. The API's pre-deploy step runs
   `python -m alembic upgrade head`; readiness remains unhealthy if PostgreSQL
   is unreachable.
8. Verify `https://repoguard-web.onrender.com/`, the backend
   `/health/live` and `/health/ready` endpoints, then complete a synthetic
   registration, login, repository scan, findings, tenant-isolation, and
   logout check before adding production users or repositories.

### Environment checklist

| Variable | Required | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | Yes | Render-managed PostgreSQL connection string. |
| `REPOGUARD_JWT_SECRET` | Yes | Generated high-entropy signing key, at least 32 bytes with diverse characters. |
| `GITHUB_TOKEN` | Yes | Read access for private/public repository clone operations. |
| `GITHUB_WEBHOOK_SECRET` | Yes | HMAC verification of push webhooks. |
| `REPOGUARD_CORS_ORIGINS` | Yes | Exact HTTPS frontend origin(s); no wildcard. |
| `REPOGUARD_ALLOWED_HOSTS` | Yes | Exact API hostnames, including any custom API domain. |
| `REPOGUARD_SCAN_ROOT` | Yes | Existing private directory for temporary checkouts. |
| `REPOGUARD_MAX_REQUEST_BYTES` | No | Request body ceiling; defaults to 25 MiB. |
| `REPOGUARD_AUTH_RATE_LIMIT_PER_MINUTE` | No | Login/registration limit per normalized account; defaults to 10 per minute. |
| `REPOGUARD_AUTH_GLOBAL_RATE_LIMIT_PER_MINUTE` | No | Additional process-wide login/registration ceiling; defaults to 120 per minute. |
| `DB_POOL_SIZE` | No | SQLAlchemy base connection pool size; defaults to 5. |
| `DB_MAX_OVERFLOW` | No | SQLAlchemy temporary overflow connections; defaults to 10. |
| `DB_POOL_TIMEOUT_SECONDS` | No | Maximum wait for a pooled connection; defaults to 30. |
| `LLM_API_KEY` | No | Optional provider credential for AI explanations. |

Authentication rate-limit state is in memory and resets on process restart.
The Render Blueprint sets `numInstances: 1`; do not increase it without
configuring a shared limiter or trusted edge rate-limit service. The backend
enforces the request-size limit even when called directly; the Compose Nginx
proxy applies the same 25 MiB ceiling and an additional auth-path limit.

### Deployment health and rollback

Use the public API URLs:

```text
https://repoguard-api.onrender.com/health/live
https://repoguard-api.onrender.com/health/ready
```

`/health/live` checks the process; `/health/ready` executes a PostgreSQL query.
The Render API health check uses readiness. A frontend page being served does
not prove database or scanner connectivity.

For an application rollback, select the last known-good API and frontend
deploys in Render. Do not automatically downgrade PostgreSQL. First inspect
the migration and current data, preserve a verified backup, and restore into a
separate database for validation. A database restore or downgrade is an
operator-approved recovery action; the migration may contain data whose
rollback is not lossless.

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
example, `http://localhost:8080` for local Compose). Production permits
loopback HTTP only for local Compose and requires HTTPS for non-loopback
origins. Set `REPOGUARD_ALLOWED_HOSTS` to the exact hostnames accepted by the
API. Compose's backend is not published; do not expose that backend port directly.
Nginx replaces rather than appends incoming forwarded-address values.
`LLM_API_KEY` is optional; without provider configuration,
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

The backend requires `postgresql+psycopg` in production. Render's
`postgres://` and `postgresql://` connection-string forms are normalized to
that driver without exposing the password. Readiness executes a database
query and returns 503 until PostgreSQL is reachable. SQLAlchemy uses
`pool_pre_ping`, a 30-minute connection recycle, configurable pool size and
overflow, and request sessions are closed by the FastAPI dependency. The
application disposes the pool on shutdown.

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
secret manager for production. The API does not consume forwarded headers.
Production error responses do not include stack traces or filesystem details;
logs identify unexpected errors by request ID and exception type only.

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
