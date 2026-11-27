# RepoGuard API Contracts

This document is the canonical description of the current RepoGuard security
application contract, including the authenticated React workflows, persistent
scan history, AI-assisted remediation review, and known validation limits.

## Ownership and architecture

| Component | Owner | Contractual responsibility |
| --- | --- | --- |
| `src/` | React + Vite | Authenticated repository, finding, scan, remediation review, and audit UI. |
| `backend/app/` | FastAPI | Security APIs, scan orchestration, persistence, AI guidance, and GitHub integration. |
| PostgreSQL | FastAPI + Alembic | Durable repositories, per-scan findings, fixes, reviews, AI request metadata, audit events, and scores. |
| Gitleaks | `app.services.gitleaks` | Canonical secret scanner execution and fallback labeling. |
| OSV | `app.scanners.deps` | Canonical dependency discovery and vulnerability normalization. |
| Gemini | `app.ai.llm` + `app.services.ai_service` | Structured security guidance with a rule-based fallback. |
| GitHub | `app.github_client` | Repository metadata, clone, webhook verification, branches, commits, and PRs. |
| `backend-node/` | Separate Express Commerce application | Commerce authentication, products, and orders. It is not part of the security API contract. |

The authenticated frontend uses the database-backed API as its source of
truth. The compatibility routes remain available to existing integrations.

## Base paths and endpoints

## Authentication and authorization

`POST /api/auth/register` and `POST /api/auth/login` accept an email and a
minimum 12-character password, returning a short-lived HS256 bearer token.
`GET /api/auth/me` requires that token. The browser keeps the access token in
sessionStorage (not localStorage) and sends it in the Authorization header;
closing the browser session requires sign-in again. There is no refresh token
or production SSO integration yet.

All repository, scan, finding, fix, dashboard, audit, compatibility scan, and
guidance routes require a verified bearer token. Repositories are owned by a
user; scans, findings, fixes, reviews, feedback, and scores inherit ownership
through their repository. Cross-tenant access returns 404. Existing unowned records
remain inaccessible until an administrator assigns their `repos.owner_id`
through a controlled database operation; they are never adopted automatically.

Passwords are stored as salted `scrypt` hashes. Tokens expire after
`JWT_EXPIRY_MINUTES` (30 minutes by default). In production, startup rejects a
missing, short, or known development `REPOGUARD_JWT_SECRET`; deploy a randomly
generated backend-only value of at least 32 characters. The development default
exists only for local development and automated tests.

The compatibility scan endpoint accepts an owned `repo_id` and clones the
tracked GitHub repository into a backend-managed temporary checkout. It never
accepts or persists a browser-supplied filesystem path. On sign-out the browser
clears the sessionStorage bearer token and all in-memory tenant data. There is
no refresh-token or cookie session; for production, replace the sessionStorage
bearer strategy with secure httpOnly sessions plus CSRF protection or managed
identity.

Every scan requires `REPOGUARD_SCAN_ROOT` to name an existing server-managed
directory. The backend canonicalizes the root and every checkout, requires
checkouts to be descendants of that root, and rejects symlinks in a checkout
that resolve outside it. If the setting is absent or unusable, scan requests
fail closed with a safe service-unavailable response; they do not fall back to
an unrestricted path. Repository clones are created beneath this root and
removed after scanning. Do not mount user-writable or mutually untrusted
directories as the scan root.

### FastAPI health and compatibility routes

| Method | Path | Current use |
| --- | --- | --- |
| `GET` | `/health` | Health check. |
| `POST` | `/api/repositories/scan` | Current React local-checkout scan flow. |
| `POST` | `/api/findings/explain` | Current React AI guidance flow. |

`POST /api/repositories/scan` request:

```json
{"repo_id":42}
```

The authenticated caller must own `repo_id`. The backend clones the tracked
GitHub repository into a temporary directory below `REPOGUARD_SCAN_ROOT` and
validates its canonical path before scanning. The endpoint returns a generic
503 response if the scan root is missing or unavailable.

Compatibility scan response:

```json
{
  "repo_name":"owner/repo",
  "findings":[],
  "count":0,
  "scanners":{
    "secrets":{"status":"empty","source":"gitleaks","reason":null,"count":0},
    "dependencies":{"status":"empty","source":"osv","reason":null,"count":0,"dependencies_queried":3}
  }
}
```

`POST /api/findings/explain` accepts a redaction-safe finding object and an
optional `source_context` capped at 20,000 characters. Its response contains
the redacted finding plus the AI guidance contract described below. This route
returns guidance only; it does not generate a patch, validation result, or PR.

### Database-backed FastAPI routes

| Method | Path | Behavior |
| --- | --- | --- |
| `GET`, `POST` | `/api/repos` | List or create tracked GitHub repositories. |
| `GET` | `/api/repos/{repo_id}` | Repository and latest score. |
| `GET` | `/api/repos/{repo_id}/scans` | Persisted scan history with finding counts. |
| `POST` | `/api/repos/{repo_id}/scan` | Queue a background clone-and-scan job. |
| `GET` | `/api/repos/{repo_id}/findings` | Persisted findings with optional filters. |
| `GET` | `/api/findings/{finding_id}` | Persisted finding, latest fix, and rotation checklist. |
| `POST` | `/api/findings/{finding_id}/explain` | Generate and log redaction-safe persisted-finding guidance. |
| `POST` | `/api/findings/{finding_id}/fix` | Generate and persist a review-only single-file proposal. |
| `POST` | `/api/findings/{finding_id}/feedback` | Record feedback; false-positive feedback changes finding status. |
| `GET` | `/api/fixes/{fix_id}` | Read an owned persisted proposal and its review history. |
| `POST` | `/api/fixes/{fix_id}/review` | Record an explicit approval or rejection. |
| `POST` | `/api/fixes/{fix_id}/validate` | Validate an approved proposal in a disposable checkout. |
| `POST` | `/api/fixes/{fix_id}/open-pr` | Create a GitHub branch, commit edits, and open a PR. |
| `GET` | `/api/audit-logs` | List tenant-scoped security activity. |
| `GET` | `/api/scans/{scan_id}` | Persisted scan state. |
| `GET` | `/api/scans/{scan_id}/findings` | Persisted findings belonging to one scan. |
| `GET` | `/api/dashboard/summary` | Persisted aggregate summary. |
| `POST` | `/api/webhooks/github` | Verify GitHub push webhook and queue a scan for tracked repositories. |

All database-backed routes require a verified bearer token and scope
repository-derived data and audit events to the authenticated owner. The GitHub webhook route
is the exception: it uses a valid `X-Hub-Signature-256` signature instead of a
user token.

`POST /api/repos` accepts `full_name` and an optional `default_branch`.
Client-supplied filesystem paths are rejected. Background and compatibility
scans clone the repository through the backend's configured GitHub access
into an ephemeral checkout under `REPOGUARD_SCAN_ROOT`. Only supported GitHub
`owner/repository` names are accepted.

## Standard errors

FastAPI error responses use:

```json
{
  "error": {
    "code":"REQUEST_FAILED",
    "message":"Safe user-facing message",
    "request_id":"uuid"
  }
}
```

Validation errors use `VALIDATION_ERROR`; missing resources use `NOT_FOUND`.
Error messages and persisted scan errors must not contain raw secrets, API
keys, tokens, credential-bearing clone URLs, raw source context, or provider
error bodies.

## Repository and scan lifecycle

Database scan states are `queued`, `running`, `done`, and `failed`. Scanner
sub-status is persisted as `scans.scanner_status`:

```json
{
  "secrets":{"status":"completed|empty|fallback|unavailable|failed","source":"gitleaks|regex_fallback","reason":null,"count":0},
  "dependencies":{"status":"completed|empty|skipped|unavailable|failed","source":"osv","reason":null,"count":0,"dependencies_queried":0}
}
```

`fallback` means regex matching produced results after Gitleaks was not usable;
it is never a successful Gitleaks result. `unavailable` means a dependency
provider could not be used. `empty` means a completed scanner found no
findings. Reasons are bounded safe identifiers, not tool stderr or secrets.

## Finding contract

All finding representations distinguish secret and dependency findings. Raw
secret values are never returned by an API, browser state, logs, or Gemini
prompts.

```json
{
  "id":501,
  "repo_id":42,
  "type":"secret|dependency",
  "scanner":"gitleaks|regex_fallback|osv",
  "rule_id":"rule-or-advisory-id",
  "title":"Safe description",
  "severity":"critical|high|medium|low|null",
  "file_path":"path/or/null",
  "line":14,
  "secret_masked":"masked-or-null",
  "package":"package-or-null",
  "ecosystem":"npm|PyPI|null",
  "installed_version":"version-or-null",
  "affected_versions":"verified range-or-null",
  "fixed_version":"verified version-or-null",
  "advisory_id":"OSV/GHSA/CVE id or null",
  "aliases":[],
  "references":[],
  "cvss_score":null,
  "in_history_only":false,
  "confidence":0.9,
  "status":"open|fix_proposed|pr_opened|fixed|false_positive|needs_rotation",
  "owasp_ids":[],
  "asvs_ids":[]
}
```

Unknown OSV severity remains `null`; consumers must not invent or coerce a
severity. The compatibility scan response is a subset of this contract and
uses `file` rather than persisted `file_path`; this naming difference is a
documented migration concern for frontend database adoption. The current
database finding API does not serialize `scan_id`.

## Scanner contracts

### Gitleaks

`app.services.gitleaks.scan_repository_secrets` is the canonical executor for
all FastAPI scan entry points. It honors `GITLEAKS_BIN`, then PATH discovery,
validates repository paths, uses a temporary JSON report, enforces
`SCAN_TIMEOUT_SECONDS`, parses structured JSON, and labels failures safely.

When Gitleaks is unavailable or its report cannot be trusted, the canonical
service returns `source: "regex_fallback"` and `status: "fallback"`. The
database adapter in `app.scanners.secrets` performs no execution; it only
masks and hashes canonical findings for persistence.

### OSV

`app.scanners.deps.scan_dependencies_with_status` is the canonical OSV
implementation. It discovers exact resolved versions from `package-lock.json`,
`poetry.lock`, `Pipfile.lock`, pinned `requirements.txt`, and exact
`package.json` versions. It uses OSV QueryBatch then official advisory detail
responses, preserving only verified package, version, advisory, alias,
reference, fixed-version, affected-range, and severity data.

## Gemini guidance contract

```json
{
  "guidance_source":"gemini|rule_based_fallback",
  "guidance_failure_reason":"safe-category-or-null",
  "summary":"text",
  "risk_assessment":"text",
  "remediation":"text",
  "developer_summary":"text",
  "requires_rotation":true,
  "confidence":0.0
}
```

Gemini output is accepted only after structured response validation. Provider
failures return clearly labelled rule-based guidance. A fallback is never
described as Gemini-generated.

## Fix, validation, and GitHub PR lifecycle

The compatibility guidance endpoint does not create code changes. The
database-backed fix endpoint proposes one existing repository file. The
backend chooses and validates the target path, redacts source context before
the provider call, constructs the diff itself, and persists the patch as
`pending_review`; it never writes generated content to the source repository.
Secret findings receive rotation/removal guidance only; their source is not
sent to the model and no patch is generated. For other findings, source is
shared only after a successful Gitleaks scan and matching secret lines are
redacted. If Gitleaks is unavailable or incomplete, source context fails
closed and no patch is offered.
Unsupported syntax types, unsafe paths, oversized files, malformed responses,
or unavailable source context result in guidance without a patch.

The state progression requires separate user actions:

1. `POST /api/findings/{finding_id}/fix` creates a persisted proposal.
2. `POST /api/fixes/{fix_id}/review` records an explicit approval or rejection.
   Approval requires a present patch and safe target/patch checks.
3. `POST /api/fixes/{fix_id}/validate` is available only after approval. It
   checks the source hash, applies the change in a disposable clone, runs the
   relevant Gitleaks/OSV scans, and records the result. Repository-provided
   tests or commands are deliberately not executed.
4. `POST /api/fixes/{fix_id}/open-pr` requires the latest review to be
   approved, a successful validation, one target file, and an unchanged base
   hash. The operation opens a real GitHub PR; RepoGuard does not merge it.

`validation_passed` means only that the supported syntax and security-rescan
gates passed in the disposable checkout; it does not certify application
correctness or replace the repository's own test suite. AI usage metadata and
safe lifecycle events are stored separately from source context and raw
credentials. Risk ranking is deterministic and reports its evidence; it does
not claim reachability or exploitability.

Migration `0007_reviews_audit_and_scan_findings` makes findings unique per
scan so older scans remain queryable, and adds review, AI-request, and audit
records. Apply it with the normal Alembic deployment procedure before enabling
the new endpoints. A live PostgreSQL migration must be validated in the
deployment environment; local SQLite tests do not substitute for that check.

GitHub requires `GITHUB_TOKEN`; webhook verification also requires
`GITHUB_WEBHOOK_SECRET`. Clone/PR failures must be sanitized before storage or
API return.

## Authentication expectations

The RepoGuard FastAPI routes require end-user bearer authentication, except
`GET /health` and the signed GitHub webhook. Repository-derived API data is
scoped to the authenticated owner. `backend-node` authentication is a
separate Commerce concern and is not accepted as FastAPI authorization.

All checkout paths are server-generated. `REPOGUARD_SCAN_ROOT` is required at
scan time and must refer to an existing directory controlled by the backend
operator. Repository clones are created under it, canonicalized before use,
and removed after the scan. Any checkout path or symlink resolving outside the
trusted root is rejected without returning the server path to the caller.

The backend Docker image pins Gitleaks `v8.30.1` from its official GitHub
release and verifies the Linux amd64/arm64 archive against the official
release checksum before extracting it. When updating, select a reviewed
versioned Gitleaks release, copy the exact architecture-specific SHA-256 values
from that release's `gitleaks_<version>_checksums.txt`, update the Dockerfile
version and checksums together, and run `backend/tests/test_dockerfile_security.py`.

## Secret redaction requirements

- Never return raw `secret` or `match` values.
- Never include raw findings or source context in logs.
- Redact before Gemini prompts and before browser persistence.
- Persist only a masked secret and a one-way hash when a secret finding is
  stored.
- Never include credentials in Git clone URLs in logs, errors, or API output.
