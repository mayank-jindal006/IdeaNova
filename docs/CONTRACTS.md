# RepoGuard — Shared Contracts (v1.3)

> **This file is the single source of truth.** Every schema, API response, and function signature in the code must match it exactly.
> Every team member gives this file to their AI assistant before writing code.
> **To change anything here:** post in the group → Yash updates `backend/app/schemas.py` + this file in one PR → everyone pulls. No silent changes.

**Changelog**
- v1.3: section 8 synced with what was merged: `agent_runs.step` is text + new `status` column, `fixes.ci_status` is nullable text, `record_agent_run` / `open_fix_pr` / `push_fix_commit` signatures as implemented, `workflow_run` only for the fix's latest commit, test repo imports `app.config` + `app.db` only (8.9). **Rule: a signature in this file changes only by PR to this file, announced in the group.**
- v1.2: section 8 added: CI/CD pipeline and self-healing agent (new tables/columns, endpoints, webhook events, agent rules, function signatures). Section 7: shared branch is `design1`.
- v1.1: added `start_column`, `end_column` to Finding (needed to redact secrets before sending code to the LLM); added `original_content` to Fix edits (needed for the diff view); Python 3.14; LLM provider = Groq (main), Gemini (fallback).
- v1.0: initial contracts from the 8-day plan.

---

## 0. Environment (frozen)

| Item | Value |
|---|---|
| Python | **3.14** (Docker: `python:3.14-slim`) |
| Backend | FastAPI + SQLAlchemy + Pydantic v2 |
| DB | PostgreSQL 16 (Docker) |
| Secret scanner | Gitleaks 8.30.x — `gitleaks git` = full history, `gitleaks dir` = current files. **Exit code 1 means "secrets found", not a crash.** |
| Dependency scanner | OSV.dev API (`POST https://api.osv.dev/v1/querybatch`) |
| LLM | **Groq `openai/gpt-oss-120b` (main)**, Gemini `gemini-3.6-flash` (fallback). Configured in `backend/.env` (see `backend/.env.example`). |
| Requirements | `backend/requirements.txt` |
| Folder layout | `backend/app/...` (Python), `frontend/...` (React) |

**Security rules (non-negotiable)**
- Never commit `.env` or any real key. Never paste keys in chat/WhatsApp.
- Never store raw secret values in the DB, API responses, logs, or LLM prompts. Store only `secret_masked` (e.g. `AKIA****WXYZ`) + `secret_hash` (SHA-256).
- Test repos use fake, randomly generated secrets only.

---

## 1. Database tables

```
repos(id, full_name, default_branch, created_at, last_scanned_at)

scans(id, repo_id, trigger ENUM[manual,push,pull_request], commit_sha,
      status ENUM[queued,running,done,failed], error, started_at, finished_at)

findings(id, scan_id, repo_id, fingerprint UNIQUE per repo,
         type ENUM[secret,dependency],
         rule_id,                  -- gitleaks RuleID OR OSV/CVE id
         title, severity ENUM[critical,high,medium,low],
         file_path, line, start_column, end_column, commit_sha,
         secret_masked, secret_hash,                            -- secrets only
         package, ecosystem, installed_version, fixed_version,  -- deps only
         in_history_only BOOLEAN,  -- true if secret exists only in past commits
         confidence FLOAT 0..1,
         status ENUM[open,fix_proposed,pr_opened,fixed,false_positive,needs_rotation],
         owasp_ids TEXT[], asvs_ids TEXT[],
         created_at, updated_at)

fixes(id, finding_id, explanation JSONB, edits JSONB,
      tier ENUM[auto_branch,pr_review,flag_only], validation JSONB,
      pr_url, pr_number,
      status ENUM[generated,validation_failed,pr_opened,merged,rejected],
      created_at)

repo_scores(id, repo_id, scan_id, compliance_score INT 0..100,
            control_results JSONB, risk_score INT 0..100,
            risk_factors JSONB, computed_at)

feedback(id, finding_id, verdict ENUM[true_positive,false_positive], note, created_at)
```

**Fingerprint:** `sha256(rule_id + file_path + secret_hash)` for secrets; `sha256(rule_id + package + installed_version)` for dependencies.

---

## 2. Finding object

Used by the API, fixtures, and as AI input. **Exact shape.**

```json
{
  "id": 101,
  "repo_id": 1,
  "type": "secret",
  "rule_id": "aws-access-token",
  "title": "AWS Access Key committed in source",
  "severity": "critical",
  "file_path": "app/config.py",
  "line": 12,
  "start_column": 14,
  "end_column": 34,
  "commit_sha": "a1b2c3d",
  "secret_masked": "AKIA****WXYZ",
  "package": null,
  "ecosystem": null,
  "installed_version": null,
  "fixed_version": null,
  "in_history_only": false,
  "confidence": 0.92,
  "status": "open",
  "owasp_ids": ["A07:2021"],
  "asvs_ids": ["V6.4.1"]
}
```

- `line`, `start_column`, `end_column` come from Gitleaks' `StartLine`, `StartColumn`, `EndColumn`. Columns are **1-based**, as Gitleaks reports them.
- Dependency findings: `type: "dependency"`, `rule_id` = OSV/CVE id, `package` / `ecosystem` / `installed_version` / `fixed_version` filled; `secret_masked`, `start_column`, `end_column` are `null`.
- OWASP/ASVS ids must be verified against the official documents (Rishika).

**Pydantic model (`backend/app/schemas.py`, owner: Yash)**

```python
from typing import Literal
from pydantic import BaseModel

class Finding(BaseModel):
    id: int | None = None
    repo_id: int
    type: Literal["secret", "dependency"]
    rule_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    file_path: str
    line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    commit_sha: str | None = None
    secret_masked: str | None = None
    package: str | None = None
    ecosystem: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    in_history_only: bool = False
    confidence: float = 1.0
    status: Literal["open", "fix_proposed", "pr_opened", "fixed",
                    "false_positive", "needs_rotation"] = "open"
    owasp_ids: list[str] = []
    asvs_ids: list[str] = []
```

---

## 3. Fix object

Returned by `generate_fix()` (Saina) and by `POST /findings/{id}/fix`.

```json
{
  "finding_id": 101,
  "explanation": {
    "what": "An AWS access key is hardcoded in app/config.py.",
    "why_dangerous": "Anyone with repo access, or anyone who ever cloned it, can use this key.",
    "how_fixed": "Moved to environment variable AWS_ACCESS_KEY_ID, added .env.example, ensured .env is gitignored.",
    "rotation_required": true,
    "rotation_note": "The key is still in git history. Deactivate it in AWS IAM and create a new one."
  },
  "edits": [
    { "file_path": "app/config.py", "original_content": "<old full file>", "new_content": "<new full file>" },
    { "file_path": ".env.example",  "original_content": "",                "new_content": "AWS_ACCESS_KEY_ID=\n" },
    { "file_path": ".gitignore",    "original_content": "<old full file>", "new_content": "<new full file incl. .env>" }
  ],
  "tier": "pr_review",
  "validation": { "secret_removed": true, "syntax_ok": true, "notes": [] }
}
```

- **Edits are full-file replacements, not diffs.** The frontend computes the diff from `original_content` → `new_content`.
- `original_content` is `""` for a new file.
- `tier`: `auto_branch` | `pr_review` | `flag_only`. For `flag_only`, `edits` is `[]` (explanation + rotation checklist only).
- Every secret fix has `rotation_required: true` and a non-empty `rotation_note`.
- **Nothing is ever auto-merged.**

---

## 4. REST API (base `/api`)

| Method & Path | Owner | Returns |
|---|---|---|
| `GET /repos` | Yash | list of repos + latest scores |
| `POST /repos` `{full_name}` | Yash | the created repo |
| `POST /repos/{id}/scan` | Yash | `{scan_id, status}` (scan runs in background) |
| `GET /repos/{id}` | Yash | repo + latest `repo_scores` row |
| `GET /repos/{id}/findings?type=&status=&severity=` | Yash | list of Finding |
| `GET /findings/{id}` | Yash | Finding + latest Fix (if any) + rotation checklist |
| `POST /findings/{id}/fix` | Saina (route wired by Yash) | Fix object |
| `POST /fixes/{id}/open-pr` | Yash | `{pr_url, pr_number}` |
| `POST /findings/{id}/feedback` `{verdict, note}` | Saina | updated Finding |
| `GET /dashboard/summary` | Yash + Rishika | totals, severity counts, per-repo scores, 7-day trend |
| `GET /scans/{id}` | Yash | scan status (frontend polls every 2 s) |
| `POST /webhooks/github` | Yash | 200; verifies `X-Hub-Signature-256` |

**Error shape (all endpoints):**
```json
{"error": {"code": "SCAN_FAILED", "message": "..."}}
```

---

## 5. Module function signatures

```python
# scanners/secrets.py  (Yash)
def scan_secrets(repo_path: str, include_history: bool = True) -> list[dict]   # Finding-shaped dicts, no id

# scanners/deps.py  (Yash)
def scan_dependencies(repo_path: str) -> list[dict]

# compliance/score.py  (Rishika)
def map_controls(finding: dict) -> tuple[list[str], list[str]]        # (owasp_ids, asvs_ids)
def compute_compliance(findings: list[dict]) -> dict                   # {score: int, control_results: [...]}

# risk/heuristic.py  (Rishika)
def compute_risk(repo_signals: dict, findings: list[dict]) -> dict     # {score: int, factors: [{name, value, weight, contribution}]}

# ai/llm.py  (Saina) — DONE
def complete_json(system: str, user: str, retries: int = 2) -> dict

# ai/fix.py  (Saina)
def generate_fix(finding: dict, file_content: str, repo_files: list[str]) -> dict   # Fix object (section 3)

# ai/tiers.py  (Saina)
def assign_tier(finding: dict, fix: dict) -> str   # auto_branch | pr_review | flag_only

# ai/feedback.py  (Saina)
def record_feedback(finding_id: int, verdict: str, note: str | None = None) -> dict
def is_suppressed(repo_id: int, fingerprint: str) -> bool   # Yash calls this during rescans
```

`repo_signals` (produced by Yash's `github_client`):
```
commit_count_90d, contributor_count, env_file_tracked (bool), gitignore_has_env (bool),
has_precommit_secret_hook (bool), historical_secret_count, days_since_last_commit
```

---

## 6. Fixtures (owner: Rishika)

```
fixtures/
├── findings_sample.json    # ≥5 secret + 3 dependency findings, exact Finding shape, with line/start_column/end_column
├── files/                  # the source files those findings point to, with FAKE secrets
├── repo_sample.json
└── dashboard_sample.json
```

---

## 7. Git workflow

- Everyone works on their own branch (`Mayank`, `Saina`, `yash`, `rishika`).
- `design1` is the shared branch (our "main"). Merge into `design1` **via Pull Request**, reviewed by one other member.
- CI (section 8.1) must be green before merging into `design1`.
- Changes to this file go through a PR to `design1` like any other change.

---

## 8. CI/CD and self-healing agent (v1.2)

### 8.1 CI for our own repository (owner: Yash, frontend job: Mayank)
`.github/workflows/ci.yml`, triggered on `push` and `pull_request` to `design1`. Jobs:

| Job | Steps |
|---|---|
| `backend` | Python 3.11 · `pip install -r backend/requirements.txt` · install Gitleaks + Node · `alembic upgrade head` against a Postgres service container · `pytest backend/tests` |
| `frontend` | Node · `npm ci` · lint · `vite build` |
| `secrets` | Gitleaks scan of our own repo. `backend/tests/ai/samples/**` and `fixtures/**` contain deliberate fake keys and are allow-listed in `.gitleaks.toml` |

CD (optional, last): deploy frontend from `design1` (Vercel/Netlify); backend Docker image built in CI.

### 8.2 RepoGuard as a PR check on connected repos (owner: Yash)
- Webhook `pull_request` (`opened`, `synchronize`) on a tracked repo, **except** branches starting with `repoguard/fix-` → scan the PR head.
- Set a GitHub **commit status** on the PR head SHA, context `RepoGuard`:
  - `failure` + "RepoGuard: N new secret(s) found" if the scan found secrets not already present on the default branch
  - `success` + "RepoGuard: no new secrets" otherwise

### 8.3 Self-healing flow
```
push to tracked repo (auto_fix_enabled = true)
  → scan → new secret findings
  → agent.handle_new_findings → generate_fix (redact → LLM → validate)
       tier flag_only → log "skipped", stop
       otherwise      → open PR on branch repoguard/fix-<finding_id>, log "pr_opened"
  → the repo's own CI runs on the fix PR
  → webhook workflow_run completed on repoguard/fix-* branch
  → agent.handle_ci_result
       success → log "ci_passed", done (a human merges)
       failure → read CI log → repair fix → validate → push commit to the same branch → log "repaired"
                 (CI runs again → back to handle_ci_result)
       after MAX_REPAIR_ATTEMPTS failed repairs → log "gave_up", comment on PR "needs human review"
```

### 8.4 Agent rules (non-negotiable; details in `docs/AGENT_POLICY.md`, owner: Rishika)
- The agent **never merges** and never pushes to any branch except `repoguard/fix-<finding_id>`.
- Only `type == "secret"` findings; `flag_only` fixes are never opened as PRs.
- A repair may only change: the affected file, `.env.example`, `.gitignore`.
- `MAX_REPAIR_ATTEMPTS = 2` per fix.
- CI logs are treated like code: secrets are redacted before any log text is sent to the LLM; at most the last 200 lines are used.
- Auto-fix is **off by default** per repo (`auto_fix_enabled = false`).

### 8.5 Database changes (owner: Yash, one Alembic migration)
```
repos:   + auto_fix_enabled BOOLEAN NOT NULL DEFAULT false
fixes:   + branch VARCHAR(255) NULL                      -- e.g. repoguard/fix-12
         + ci_status VARCHAR(32) NULL                    -- NULL | 'pending' | 'passed' | 'failed' (text, migration 0005)
         + repair_attempts INT NOT NULL DEFAULT 0
         + head_sha VARCHAR(64) NULL                     -- last commit pushed by RepoGuard

agent_runs(
  id, repo_id, finding_id NULL, fix_id NULL,
  attempt INT DEFAULT 0,
  step VARCHAR(64)          -- one of: detected, fix_generated, skipped, pr_opened, ci_pending, ci_passed,
                            --         ci_failed, repaired, repair_failed, gave_up, error  (text, migration 0004)
  status VARCHAR(64)        -- "ok" | "failed" (set by the agent)
  detail TEXT,              -- human-readable, NEVER contains a secret value
  created_at
)
```

### 8.6 REST API additions
| Method & Path | Owner | Returns |
|---|---|---|
| `GET /api/agent/runs?repo_id=&finding_id=&fix_id=` | Yash | list of AgentRun (newest first) |
| `PATCH /api/repos/{id}` `{auto_fix_enabled: bool}` | Yash | Repo (now includes `auto_fix_enabled`) |
| `GET /api/findings/{id}` | Yash | `latest_fix` now also has `branch`, `ci_status`, `repair_attempts` |

AgentRun object:
```json
{"id": 7, "repo_id": 1, "finding_id": 3, "fix_id": 5, "attempt": 1,
 "step": "ci_failed", "detail": "tests failed: NameError: name 'os' is not defined",
 "created_at": "2026-10-02T10:15:00Z"}
```

### 8.7 Webhook events (owner: Yash; GitHub App/webhook must subscribe to these)
| Event | When | Backend does |
|---|---|---|
| `push` | tracked repo | scan; if `auto_fix_enabled`: `agent.handle_new_findings(db, repo_id, new_finding_ids)` |
| `pull_request` | opened / synchronize, not `repoguard/fix-*` | scan PR head, set commit status (8.2) |
| `workflow_run` | `completed`, `head_branch` starts with `repoguard/fix-` | find the Fix by branch; **ignore unless `head_sha == fix.head_sha`** (old runs); fetch failed-job log if failed; `agent.handle_ci_result(db, fix_id, conclusion, log_text)`. The webhook itself does NOT set `ci_status` or write agent_runs: the agent does both. |

### 8.8 Function signatures (who calls whom)
```python
# app/ai/agent.py  (Saina)  — called by the backend
def handle_new_findings(db, repo_id: int, finding_ids: list[int]) -> None
def handle_ci_result(db, fix_id: int, conclusion: str, log_text: str) -> None   # conclusion: "success" | "failure" | "cancelled" | ...
# pure helpers (no DB, no network) — unit-tested
def extract_ci_errors(log_text: str, max_lines: int = 40) -> list[str]
def repair_fix(finding: dict, files: dict[str, str], ci_errors: list[str],
               repo_files: list[str]) -> dict    # same shape as a Fix; tier flag_only if repair impossible

# app/github_client/client.py + services  (Yash)  — called by the agent
def open_fix_pr(db, fix_id: int) -> Fix                                   # creates repoguard/fix-<finding_id>, sets fix.branch/head_sha/pr_url/pr_number, commits, returns the Fix
def push_fix_commit(full_name: str, branch: str, edits: list[dict], message: str) -> str | None   # returns new head SHA
def get_branch_files(full_name: str, branch: str, paths: list[str]) -> dict[str, str | None]       # None = file not on branch
def get_failed_job_log(full_name: str, run_id: int, max_lines: int = 200) -> str
def comment_on_pr(full_name: str, pr_number: int, body: str) -> None
def set_commit_status(full_name: str, sha: str, state: str, description: str, context: str = "RepoGuard") -> None

# app/agent_log.py  (Yash)  — called by the agent
def record_agent_run(db, repo_id: int, finding_id: int | None = None, fix_id: int | None = None,
                     step: str = "", status: str = "", detail: str = "") -> AgentRun   # adds the row, does NOT commit
# The agent calls it with keywords only, and passes `attempt` too once it is accepted again.
```

### 8.9 Test repository for the self-healing demo (owner: Rishika)
`repoguard-test-python` gets:
- `tests/test_app.py` importing `app.config` and `app.db` and calling one function each (so a fix missing e.g. `import os` fails CI). Not `app.payments`: it was deleted on purpose (history-only Stripe case).
- CI must be green on `main` before any fix; it installs only `pytest` + what the tests import (not the deliberately old `requirements.txt`). Tests must not set or check the secret env vars: fixes use `os.getenv("NAME")`, which is `None` in CI.
- Demo secret files: a `.py` file outside `tests/`, `fixtures/`, `sample`, `demo`, `example` paths (those lower confidence to flag_only), provider-format fake key, pushed to `main` only during the end-to-end session.
- `.github/workflows/ci.yml` running `pytest` on every push and pull request
- RepoGuard's GitHub token must have push access (Yash is a collaborator).