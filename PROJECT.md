# RepoGuard (AI Secure DevOps Copilot)
> **Comprehensive Project Analysis, Git Provenance, Architecture & Team Evaluation Guide**  
> *Target Branch:* `design1` (Shared Default Branch)  
> *Last Updated:* October 2026

---

## 1. Executive Summary & Vision

**RepoGuard** is an automated, developer-first Security Operations (SecOps) platform designed to eliminate the critical vulnerability lifecycle gap in modern software engineering.

Traditional static analysis and secret detection tools (e.g., Gitleaks, TruffleHog, Snyk, GitGuardian) suffer from severe limitations:
1. **Alert Fatigue:** They detect and flag issues, but leave the complex task of code remediation and credential invalidation entirely to overburdened engineers.
2. **Context Blindness:** They fail to explain *why* an exposure is hazardous or how it maps to regulatory security controls (OWASP Top 10, ASVS).
3. **History Amnesia:** Removing a secret from the latest commit does *not* erase it from Git tree history. Unrotated credentials remain compromised indefinitely.
4. **Disjointed Tooling:** Teams juggle separate platforms for secret scanning, dependency CVE tracking, and compliance reporting.

### The RepoGuard Solution: The Closed-Loop Security Cycle
RepoGuard implements a complete **Detect → Explain → Fix → Validate → Review → Rotate** workflow:
- **Detect:** Full git tree and history secret scanning via Gitleaks 8.30.x + dependency CVE analysis via OSV.dev batch API.
- **Explain:** Automated threat breakdown explaining what was exposed, why it is dangerous, and which security controls are violated.
- **Fix:** AI-generated remediation patches producing full-file edits (extracting credentials to environment variables, updating `.env.example`, ensuring `.gitignore` rules).
- **Validate:** Re-evaluates patches before opening PRs to guarantee zero residual secret tokens (via Gitleaks re-scan) and syntactically clean code (Python `compile()`, JS `node --check`).
- **Review:** Opens review-only GitHub Pull Requests on dedicated remediation branches (`repoguard/fix-{id}`). **Strict zero-auto-merge policy.**
- **Rotate:** Enforces credential rotation checklists with provider-specific invalidation steps (AWS IAM, Stripe, GitHub PAT, etc.).

---

## 2. Git Provenance & Commit Audit Trail

Every feature, schema, algorithm, and UI component in RepoGuard is backed by verified Git commits and pull requests on the `design1` branch:

### Git Commit & Provenance Matrix

| Commit | Author | Date | Branch / PR | Key Deliverables & Code Changes |
|---|---|---|---|---|
| `1265350` | Saina Sharma | 2026-10-01 | PR #3 (Merged) | Merge multi-secret redaction and `try_repo.py` end-to-end scanner into `design1`. |
| `f077077` | Saina Sharma | 2026-10-01 | `Saina` | Handle multiple/repeated secrets per file (`extract_secret`, `hide_other_secrets`, `restore_other_secrets`), test repo validation, and `try_repo.py`. |
| `a15295e` | Yash | 2026-10-01 | `design1` | AI integrations, finding column metadata, Alembic migration `0002_add_finding_columns.py`, OSV CVE detail enrichment (`/v1/vulns/{id}`). |
| `bedb94e` | Saina Sharma | 2026-09-30 | PR #2 (Merged) | Merge AI Remediation Engine into `design1`: Groq LLM client, Gemini fallback, prompt templates, fix generation, safe redaction, tiers, and validation tests. |
| `fc80f99` | Mayank | 2026-09-30 | `design1` | Frontend remediation: removed silent mock fallbacks, added offline sample banners, enforced strict `fix_id` parameter passing for `/fixes/{id}/open-pr`. |
| `fde3e54` | Mayank | 2026-09-30 | `design1` | Updated `fixes.json` with `auto_branch` tier and validation records for AWS, Stripe, and GitHub credentials. |
| `3347b7f` | Saina Sharma | 2026-09-30 | `Saina` | Added Groq→Gemini fallback, fix tiers (`auto_branch`, `pr_review`, `flag_only`), and unit tests for 3/3 validated samples. |
| `1612f80` | Mayank | 2026-09-30 | `design1` | Merged complete RepoGuard Dark SecOps console UI into `design1` and connected to backend REST API. |
| `5fb45a9` | Saina Sharma | 2026-09-30 | `Saina` | Added AI engine dependencies (`groq`, `google-genai`, `openai`) to `backend/requirements.txt`. |
| `6817b61` | Saina Sharma | 2026-09-30 | `Saina` | Added `validate.py`: Gitleaks directory re-scan + syntax check with one-shot retry. |
| `04a0f82` | Saina Sharma | 2026-09-30 | `Saina` | Rebased and merged `design1` into `Saina`. |
| `82faac1` | Yash | 2026-09-30 | `design1` | Complete backend implementation: FastAPI routes (`backend/app/api/routes.py`), PostgreSQL models (`models.py`), Alembic initial migration, GitHub client, Gitleaks scanner, OSV scanner. |
| `1ff905c` | Mayank | 2026-09-29 | `design1` | Added `fixes.json` with AI proposed patches for AWS, Stripe, and GitHub credentials. |
| `38cdf6b` | Rishika | 2026-09-29 | `rishika` | Created test fixtures: `findings_sample.json`, `repo_sample.json`, `dashboard_sample.json`, and sample vulnerable source files. |
| `f732926` | Rishika | 2026-09-29 | `rishika` | Updated `CONTRACTS.md.txt` with column numbers, diff specs, and risk models. |
| `1e2576e` | Saina Sharma | 2026-09-25 | `Saina` | Added `generate_fix()` in `fix.py` + prompt engineering (`prompts.py`) + `try_fix.py` script (3/3 samples fixed). |
| `d87e7bc` | Saina Sharma | 2026-09-24 | `Saina` | Added `redact()` with column safety check (`redact.py`), sample vulnerable data, and redaction unit tests. |
| `0a274ac` | Saina Sharma | 2026-09-24 | PR #1 (Merged) | Merged shared `CONTRACTS.md` (v1.1) into `design1`. |
| `6157a74` | Saina Sharma | 2026-09-24 | `contracts` | Added shared `docs/CONTRACTS.md` (v1.1). |
| `a9ab0f8` | Saina Sharma | 2026-09-24 | `Saina` | Completed LLM client (`llm.py`) with Groq primary and Gemini fallback + test scripts. |
| `811f628` | Rishika | 2026-09-24 | `rishika` | Added initial contracts specification document from project plan. |
| `cde9386` | Mayank | 2026-09-24 | `Mayank` | Completed SecOps console design system, scan pipeline views, diff viewer, and rotation checklists. |
| `d605043` | Yash | 2026-09-23 | `yash` | Initialized backend skeleton and dependencies. |
| `6ac76a2` | Mayank | 2026-09-23 | `Mayank` | Established RepoGuard foundational architecture, initial mock schemas, and navigation layout. |
| `2242900` | Mayank | 2026-09-22 | `Mayank` | Added AI Secure DevOps Copilot overview and IdeaNova pitch presentation. |
| `1d34683` | Mayank | 2026-08-06 | `design1` | Initialized Vite + React frontend workspace with base dependencies. |

---

## 3. System Architecture & Tech Stack

```
                                  +-----------------------------+
                                  |     GitHub Repositories     |
                                  +--------------+--------------+
                                                 | Clone / Webhooks
                                                 v
+------------------------+        +--------------+--------------+        +------------------------+
|  Vite + React Frontend | <----> |   FastAPI Backend (8002)   | <----> |  PostgreSQL 16 (DB)    |
|  - Dark Console SecOps |  REST  |   - Scan Orchestrator       |  SQL   |  - repos, scans        |
|  - Multi-File DiffView |  JSON  |   - GitHub Client (PRs)     |        |  - findings, fixes     |
|  - Zero-Raw-Secret UI  |        |   - Webhook Verifier (HMAC) |        |  - repo_scores, feedbk |
+------------------------+        +--------------+--------------+        +------------------------+
                                                 |
                       +-------------------------+-------------------------+
                       |                         |                         |
                       v                         v                         v
            +--------------------+    +--------------------+    +--------------------+
            | Security Scanners  |    | AI Remediation     |    | Security Standards |
            | - Gitleaks 8.30.x  |    | - Groq GPT-OSS     |    | - OWASP Top 10     |
            | - OSV.dev Batch API|    | - Gemini Fallback  |    | - OWASP ASVS v4.0  |
            +--------------------+    +--------------------+    +--------------------+
```

### Core Technologies
| Component | Technology | Description |
|---|---|---|
| **Frontend** | React 19, React Router v7, Vite 8, Vanilla CSS | Custom dark-console SecOps interface, multi-file LCS diff viewer, zero-raw-secret masking. |
| **Backend** | Python 3.14, FastAPI, SQLAlchemy 2.0, Pydantic v2 | Asynchronous REST API, background task runner, GitHub API client, Alembic migrations. |
| **Database** | PostgreSQL 16 (Docker) | Relational storage for repos, scans, findings, fixes, scores, and feedback. |
| **Scanners** | Gitleaks 8.30.x, OSV.dev Batch API | High-entropy regex secret scanning and open-source dependency CVE analysis. |
| **AI / LLM** | Groq (`openai/gpt-oss-120b`), Gemini (`gemini-3.6-flash`) | Context-aware code remediation, explanation synthesis, multi-secret preservation, and review tier classification. |
| **Contracts** | `docs/CONTRACTS.md` (v1.1) | Single source of truth for all database schemas, API shapes, and snake_case models. |

---

## 4. Team Member Division of Labor & Completed Work

### 1. Mayank (Frontend Architect & Lead)
*Branches:* `design1`, `Mayank`  
*Commits:* 14 commits (`1d34683`, `7402362`, `2242900`, `6ac76a2`, `be41d6d`, `cde9386`, `9169066`, `a4f972e`, `827b920`, `1ff905c`, `1612f80`, `fde3e54`, `fc80f99`, `ff31997`)  
*Focus:* Complete User Interface, API Client Integration, Multi-file Diffs, State Management, and Contract Adherence.

**Key Deliverables & Completed Work:**
- **SecOps Console Design System:** Created a high-density, anti-AI console theme using pure Vanilla CSS (`src/index.css`, 2,600+ lines) with curated HSL palettes (`--bg-primary: #0a0d14`, `--border-color: #1e2640`, `--accent: #00e5ff`), glassmorphism, terminal output blocks, and zero placeholder fluff.
- **API Client Layer (`src/api/client.js`):** Built a centralized HTTP client rooted at `/api` handling error normalization, headers, and endpoints for repos, scans, findings, fixes, PRs, and summaries.
- **Remediation Review & PR Screen (`src/pages/FixReview.jsx`):**
  - Consumes `POST /api/findings/{id}/fix` to render structured explanations (`what`, `why_dangerous`, `how_fixed`), review tier badges (`auto_branch`, `pr_review`, `flag_only`), and validation status.
  - Implemented multi-file diff tab switching for full-file edit replacements.
  - Consumes `POST /api/fixes/{id}/open-pr` and directly renders the returned clickable GitHub PR link (`pr_url`, `pr_number`).
  - Added strict `fix_id` enforcement (guards against sending finding IDs to the PR endpoint).
- **Multi-File Diff Engine (`src/components/DiffViewer.jsx`):** Developed an in-browser Longest Common Subsequence (LCS) line diffing algorithm supporting Unified Diff and Side-by-Side views, addition/deletion line counters, and empty-file creation notes.
- **Security Finding Detail (`src/pages/FindingDetail.jsx`):**
  - Adheres strictly to Zero-Raw-Secret policy: only displays `secret_masked` tokens (e.g. `AKIA****WXYZ`) and fingerprints.
  - Visualizes OWASP Top 10 and ASVS v4.0.3 security control mappings.
  - Integrated false-positive feedback submission (`POST /api/findings/{id}/feedback`).
- **Interactive Rotation Checklists (`src/components/RotationChecklist.jsx`):** Interactive checklists for key invalidation (AWS IAM, Stripe, GitHub PAT, generic API keys) with step progress indicators.
- **Operations Dashboard (`src/pages/Dashboard.jsx`):** Consumes `GET /api/dashboard/summary` to render KPI statistics, repository security postures, severity distributions, and a 7-day detection trend graph.
- **Repository Inventory & Posture (`src/pages/Repositories.jsx`, `src/pages/RepositoryDetail.jsx`):** Searchable, sortable repo lists with transparent Heuristic Risk Factor breakdowns (`RiskFactorBreakdown.jsx`).
- **Live Scan Pipeline (`src/pages/ScanProgress.jsx`):** Triggers `POST /api/repos/{id}/scan` and polls `GET /api/scans/{id}` every 2 seconds with live terminal log streaming and stage progression.
- **Sanitization & Quality:** Completely purged unsupported claims (removed "AST scanner" and "signs the commit" references); removed all silent mock fallbacks; passed `oxlint` (0 errors, 0 warnings) and production Vite build.

---

### 2. Yash (Backend & DevOps Infrastructure Lead)
*Branches:* `design1`, `yash`  
*Commits:* 3 commits (`d605043`, `82faac1`, `a15295e`)  
*Focus:* FastAPI Backend, Database Architecture, GitHub Integration, and Scan Pipeline.

**Key Deliverables & Completed Work:**
- **FastAPI Core & Routes (`backend/app/api/routes.py`, `backend/app/main.py`):**
  - Implemented 12 RESTful endpoints covering repos, scans, findings, fixes, feedback, and dashboard summaries.
  - Normalized error schema across all endpoints: `{"error": {"code": "...", "message": "..."}}`.
  - Added Fix ID to `/api/findings/{id}/fix` response payload for clean frontend PR dispatch.
- **Database Schema & Migrations (`backend/app/models.py`, `backend/alembic/`):**
  - Designed relational tables: `repos`, `scans`, `findings`, `fixes`, `repo_scores`, `feedback`.
  - Created Alembic migrations:
    - `0001_initial.py`: Baseline tables and relationships.
    - `0002_add_finding_columns.py`: Added `start_column`, `end_column`, `in_history_only` columns to support LLM redaction and git history detection.
- **GitHub Client Integration (`backend/app/github_client/client.py`):**
  - Git repository cloning into isolated temporary directories (`tempfile.mkdtemp(prefix="repoguard-")`) with automatic cleanup.
  - Automated remediation branch creation (`repoguard/fix-{finding_id}`).
  - Commit generation with full-file edit patches.
  - GitHub Pull Request creation via GitHub REST API with formatted markdown PR descriptions.
  - HMAC SHA-256 webhook signature verification (`X-Hub-Signature-256`) for push triggers.
- **Scanning Services (`backend/app/services/scans.py`, `backend/app/scanners/`):**
  - Background asynchronous task runner executing full scans on manual triggers or push webhooks.
  - `secrets.py`: Gitleaks 8.30 wrapper scanning working tree and historical commits, generating deterministic finding fingerprints (`sha256(rule_id + file_path + secret_hash)`).
  - `deps.py`: Dependency parser checking Python `requirements.txt` and Node `package.json` against OSV.dev QueryBatch API (`POST https://api.osv.dev/v1/querybatch`), enriched via `/v1/vulns/{id}`.
- **Containerization (`Dockerfile`, `docker-compose.yml`):** Multi-service Docker setup running FastAPI (Python 3.14-slim), PostgreSQL 16, and Vite frontend.

---

### 3. Saina (AI Remediation & LLM Engineering Lead)
*Branches:* `Saina`, `contracts`  
*Commits:* 15 commits (`a695010`, `50af6fc`, `bf4cfde`, `a9ab0f8`, `6157a74`, `0a274ac`, `34cfcd6`, `d87e7bc`, `1e2576e`, `04a0f82`, `6817b61`, `5fb45a9`, `3347b7f`, `bedb94e`, `f077077`, `1265350`)  
*Focus:* LLM Prompting, Safe Code Redaction, Multi-Secret Preservation, Fix Generation, Review Tiers, and Automated Validation.

**Key Deliverables & Completed Work:**
- **Inference Engine (`backend/app/ai/llm.py`):**
  - Multi-provider structured JSON completion engine: Groq `openai/gpt-oss-120b` (primary) with automatic fallback to Gemini `gemini-3.6-flash`.
  - Configurable timeout, exponential backoff retries, and markdown code fence stripping.
- **Zero-Raw-Secret Code Redaction (`backend/app/ai/redact.py`):**
  - `extract_secret`: Extracts exact secret text using 1-based columns and performs verification checks against `secret_masked`.
  - `redact`: Replaces every occurrence of the exposed secret with `<<REDACTED_SECRET>>` across the file.
  - `hide_other_secrets` & `restore_other_secrets` (PR #3): When a file contains multiple or repeated secrets (e.g., both DB credentials or multiple API tokens), secondary secrets are safely masked with `<<OTHER_SECRET_{n}>>` so the LLM leaves them untouched, and they are automatically restored post-generation.
- **Automated Fix Generation (`backend/app/ai/fix.py`):**
  - Structured prompt engineering (`prompts.py`) generating full-file replacements for affected code, `.env.example`, and `.gitignore`.
  - Synthesizes educational explanations (`what`, `why_dangerous`, `how_fixed`, `rotation_note`).
- **Post-Generation Validation (`backend/app/ai/validate.py`):**
  - `check_secret_removed`: Writes proposed edits to a temporary folder and runs Gitleaks to verify zero residual leaks.
  - `check_syntax`: Compiles Python code via `compile()` and JavaScript via `node --check`.
  - Automated one-shot retry if the LLM produces a syntax error or leaves a secret token.
- **Tier Classification (`backend/app/ai/tiers.py`):**
  - `auto_branch`: Validation passed, confidence >= 0.85, and change is <= 2 lines (`AUTO_MAX_CHANGED_LINES`).
  - `pr_review`: Changes modifying application logic or environment configs requiring peer review.
  - `flag_only`: Architectural exposures or unvalidated patches (generates explanation and rotation checklist only).
- **End-to-End Test Repo Runner (`backend/scripts/try_repo.py`):** Standalone end-to-end testing script that clones a public GitHub repo, scans secrets via Gitleaks, feeds findings through the live LLM fix engine, validates results, and outputs a formatted summary.
- **AI Test Suite (`backend/tests/ai/`):** 68 unit tests (`test_fix.py`, `test_llm.py`, `test_prompts.py`, `test_redact.py`, `test_tiers.py`, `test_validate.py`) passing with 61 passed and 7 skipped (isolated external CLIs).

---

### 4. Rishika (Security Standards, Compliance & Heuristic Risk Lead)
*Branch:* `rishika`  
*Commits:* 3 commits (`811f628`, `f732926`, `38cdf6b`)  
*Focus:* OWASP & ASVS Control Mapping, Heuristic Risk Formula, Contract Specification, and Evaluation Fixtures.

**Key Deliverables & Completed Work:**
- **Contract Specifications (`docs/CONTRACTS.md`, `docs/CONTRACTS.md.txt`):**
  - Defined database schemas, Pydantic models, REST API paths, and function signatures.
  - Enforced single source of truth across frontend and backend implementations.
- **Regulatory Standards Mapping (`backend/app/compliance/score.py`):**
  - Mapped secret and dependency rules to **OWASP Top 10 (2021)**:
    - Secrets → `A07:2021-Identification and Authentication Failures` / `A01:2021-Broken Access Control`.
    - Vulnerable Dependencies → `A06:2021-Vulnerable and Outdated Components`.
  - Mapped to **OWASP ASVS v4.0.3**:
    - Secrets → `V3.1.1` / `V6.4.1` (Secret Architecture and Storage).
    - Dependencies → `V14.2.1` (Third-Party Component Dependency Management).
- **Compliance Index Algorithm:** Calculates repo compliance score (0–100%) based on finding severity deductions (Critical: -25, High: -15, Medium: -5, Low: -2).
- **Heuristic Risk Model (`backend/app/risk/heuristic.py`):**
  - Replaced ambiguous "predictive AI" claims with a transparent, explainable heuristic risk score based on measurable Git signals:
    $$\text{Risk Score} = 0.35 \times S_{\text{history}} + 0.25 \times E_{\text{tracked}} + 0.15 \times V_{\text{velocity}} + 0.15 \times G_{\text{gitignore}} + 0.10 \times C_{\text{churn}}$$
- **Rotation Guides (`backend/app/compliance/rotation.py`):** Formulated provider-specific operational checklists to guide engineers through IAM invalidation, key rolling, and audit log inspection.
- **Evaluation Fixtures & Test Repositories:** Created realistic repository samples, fake credential fixtures, and JSON schemas for integration testing (`findings_sample.json`, `repo_sample.json`, `dashboard_sample.json`, and sample test repo `https://github.com/gargrishika2005-cell/repoguard-test-python`).

---

## 5. Key Architectural Guarantees & Contracts

| Principle | Enforcement Mechanism |
|---|---|
| **Zero-Raw-Secret Policy** | Raw secrets are never stored in PostgreSQL, never returned in API responses, never shown in UI, and never sent to external LLM providers. Only `secret_masked` and SHA-256 hashes are persisted. |
| **Strict Zero-Auto-Merge** | Pull requests are created on dedicated branches (`repoguard/fix-{id}`) for human peer review. Nothing is ever auto-merged into default branches. |
| **Multi-Secret Isolation** | Secondary secrets in the same file are preserved via `hide_other_secrets` and restored post-generation so remediation focuses exclusively on the target finding. |
| **Rotation-Aware Remediations** | Every secret fix enforces `rotation_required: true` and includes provider-specific rotation guidance because code patching does not purge exposed keys from past commits. |
| **Ephemeral Disk Isolation** | Scans execute in isolated temporary clones that are purged immediately after execution (`shutil.rmtree`). |
| **Contract Consistency** | All models and endpoints adhere strictly to `snake_case` naming defined in [`CONTRACTS.md`](file:///c:/proj/ideanova/docs/CONTRACTS.md). |

---

## 6. End-to-End Workflow Demonstration

```
Step 1: Ingestion
  User registers repository (e.g. `mayank-jindal006/IdeaNova`).
  Backend queries GitHub for default branch and stores repo record.

Step 2: Security Scan Execution
  User clicks "Run Security Scan" -> Frontend sends POST /api/repos/{id}/scan.
  Backend queues background scan task.
  Frontend navigates to /repositories/{id}/scan and polls GET /api/scans/{id} every 2 seconds.
  Gitleaks scans history; OSV.dev audits package manifests.

Step 3: Finding Analysis
  Scan finishes. Frontend displays findings list with severity badges and rule IDs.
  User opens Finding #1 (/findings/1).
  Frontend displays zero-raw-secret masked token (AKIA****WXYZ), OWASP/ASVS controls, and Git tree exposure status.

Step 4: AI Remediation
  User clicks "Review & Remediate (AI Fix)" -> navigates to /findings/1/fix.
  Frontend sends POST /api/findings/1/fix.
  AI synthesizes explanation, generates full-file edits (config.py, .env.example, .gitignore), and assigns review tier.
  Frontend renders Multi-File DiffViewer showing side-by-side or unified additions/deletions.

Step 5: Pull Request Opening
  User reviews diff and clicks "Open GitHub Pull Request".
  Frontend sends POST /api/fixes/{fix_id}/open-pr.
  Backend creates branch `repoguard/fix-1`, commits patches, opens PR on GitHub, and returns PR URL.
  Frontend displays direct clickable link: [PR #42 Opened on GitHub].

Step 6: Credential Invalidation
  Engineer follows the interactive Rotation Checklist to revoke compromised keys in AWS IAM.
```

---

## 7. How to Run & Test Locally

### Prerequisites
- Node.js 18+ and npm
- Python 3.12+ (Python 3.14 supported)
- PostgreSQL 16
- Gitleaks 8.30+ installed and on system `PATH`

### 1. Backend Setup
```powershell
cd backend
cp env.example.txt .env
# Edit .env with your DATABASE_URL, GITHUB_TOKEN, and GROQ_API_KEY / GEMINI_API_KEY
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8002
```
*API will run on:* `http://localhost:8002` (Health: `http://localhost:8002/health`)

### 2. Frontend Setup
```powershell
# In project root
npm.cmd install
npm.cmd run dev
```
*Frontend will run on:* `http://localhost:5173`

### 3. Running Automated Tests & Quality Checks
```powershell
# Run AI unit test suite (68 tests)
pytest backend/tests/ai

# Run live test repo scan and fix pipeline (requires GROQ_API_KEY in .env)
python -m scripts.try_repo https://github.com/gargrishika2005-cell/repoguard-test-python

# Run frontend linter (92 rules)
npx.cmd oxlint

# Run production frontend build
npm.cmd run build
```

---

## 8. Verification & Evaluation Checklist

- [x] **Linting:** `oxlint` passes with **0 warnings, 0 errors** across 23 files and 92 rules.
- [x] **Production Build:** `vite build` bundles cleanly into `dist/` in 284ms.
- [x] **AI Engine Tests:** `pytest backend/tests/ai` passes (61 passed, 7 skipped for missing external CLIs).
- [x] **Multi-Secret Preservation:** `hide_other_secrets` and `restore_other_secrets` verified across multi-finding source files.
- [x] **Contracts Compatibility:** Adheres to all Pydantic schemas in `CONTRACTS.md`.
- [x] **Branch Hygiene:** `design1` is the active, unified default branch tracking `origin/design1`. Redundant `main` branch deleted.
- [x] **Zero Mock Fallbacks:** Real API errors and genuine scan metrics are rendered without silent fake score injections.
- [x] **PR Safety:** `POST /api/fixes/{id}/open-pr` strictly validates Fix ID.
