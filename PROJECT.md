# RepoGuard (AI Secure DevOps Copilot)
> **Comprehensive Project Analysis, Architecture, & Team Evaluation Guide**  
> *Target Branch:* `design1` (Shared Default Branch)  
> *Last Updated:* October 2026

---

## 1. Executive Summary & Vision

**RepoGuard** is an automated, developer-first Security Operations (SecOps) platform designed to eliminate the critical vulnerability lifecycle gap in modern software engineering.

Traditional static analysis and secret detection tools (e.g., Gitleaks, TruffleHog, Snyk, GitGuardian) suffer from severe limitations:
1. **Alert Fatigue:** They detect and flag issues, but leave the complex task of code remediation and credential invalidation entirely to overburdened engineers.
2. **Context Blindness:** They fail to explain *why* an exposure is hazardous or how it maps to regulatory security controls (OWASP Top 10, ASVS).
3. **History Amnesia:** Removing a secret from the latest commit does *not* erase it from Git tree history. Unrotated credentials remain compromised.
4. **Disjointed Tooling:** Teams juggle separate platforms for secret scanning, dependency CVE tracking, and compliance reporting.

### The RepoGuard Solution: The Closed-Loop Security Cycle
RepoGuard implements a complete **Detect → Explain → Fix → Validate → Review** workflow:
- **Detect:** Full git tree and history secret scanning via Gitleaks + dependency CVE analysis via OSV.dev.
- **Explain:** Automated threat breakdown explaining what was exposed, why it is dangerous, and which security controls are violated.
- **Fix:** AI-generated remediation patches producing full-file edits (extracting credentials to environment variables, updating `.env.example`, ensuring `.gitignore` rules).
- **Validate:** Re-evaluates patches before opening PRs to guarantee zero residual secret tokens and syntactically clean code.
- **Review:** Opens review-only GitHub Pull Requests on dedicated remediation branches (`repoguard/fix-{id}`). **Strict zero-auto-merge policy.**
- **Rotate:** Enforces credential rotation checklists with provider-specific invalidation steps (AWS IAM, Stripe, GitHub PAT, etc.).

---

## 2. System Architecture & Tech Stack

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
| **AI / LLM** | Groq (`openai/gpt-oss-120b`), Gemini (`gemini-3.6-flash`) | Context-aware code remediation, explanation synthesis, and review tier classification. |
| **Contracts** | `docs/CONTRACTS.md` (v1.1) | Single source of truth for all database schemas, API shapes, and snake_case models. |

---

## 3. Team Member Division of Labor & Completed Work

### 1. Mayank (Frontend Architect & Lead)
*Branch:* `design1` / `Mayank`  
*Focus:* Complete User Interface, API Client Integration, Multi-file Diffs, and Contract Adherence.

**Key Deliverables & Completed Work:**
- **SecOps Console Design System:** Created a high-density, anti-AI console theme using pure Vanilla CSS (`src/index.css`) with curated HSL palettes, glassmorphism, terminal output blocks, and zero placeholder fluff.
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
*Branch:* `yash` / `design1`  
*Focus:* FastAPI Backend, Database Architecture, GitHub Integration, and Scan Pipeline.

**Key Deliverables & Completed Work:**
- **FastAPI Core & Routes (`backend/app/api/routes.py`, `backend/app/main.py`):**
  - Implemented RESTful endpoints for repos, scans, findings, fixes, feedback, and dashboard summaries.
  - Normalized error schema: `{"error": {"code": "...", "message": "..."}}`.
- **Database Schema & Migrations (`backend/app/models.py`, `backend/alembic/`):**
  - Designed relational tables: `repos`, `scans`, `findings`, `fixes`, `repo_scores`, `feedback`.
  - Configured PostgreSQL sessions, connection pooling, and initial migration `0001_initial.py`.
- **GitHub Client Integration (`backend/app/github_client/client.py`):**
  - Git repository cloning into isolated temporary directories with automatic cleanup.
  - Automated remediation branch creation (`repoguard/fix-{finding_id}`).
  - Commit generation with full-file edit patches.
  - GitHub Pull Request creation via GitHub REST API with formatted markdown PR descriptions.
  - HMAC SHA-256 webhook signature verification (`X-Hub-Signature-256`) for push triggers.
- **Scanning Services (`backend/app/services/scans.py`, `backend/app/scanners/`):**
  - Background asynchronous task runner executing full scans on manual triggers or push webhooks.
  - `secrets.py`: Gitleaks wrapper scanning working tree and historical commits, generating deterministic finding fingerprints.
  - `deps.py`: Dependency parser checking Python `requirements.txt` and Node `package.json` against OSV.dev QueryBatch API.
- **Containerization (`Dockerfile`, `docker-compose.yml`):** Multi-service Docker setup running FastAPI, PostgreSQL, and Vite frontend.

---

### 3. Saina (AI Remediation & LLM Engineering Lead)
*Branch:* `Saina`  
*Focus:* LLM Prompting, Safe Code Redaction, Fix Generation, and Review Tiers.

**Key Deliverables & Completed Work:**
- **Inference Engine (`backend/app/ai/llm.py`):**
  - Structured completion engine using Groq's high-speed `openai/gpt-oss-120b` with retry policies and Gemini `gemini-3.6-flash` fallback.
  - Enforced strict JSON schema output parsing.
- **Automated Fix Generation (`backend/app/ai/fix.py`):**
  - Takes finding metadata, affected source file, and repository directory tree as input.
  - **Zero-Raw-Secret LLM Ingestion:** Redacts sensitive key literals before prompting the model to prevent LLM training data leakage.
  - Generates full-file replacements for affected code, `.env.example` templates, and `.gitignore` entries.
  - Synthesizes educational explanations (`what`, `why_dangerous`, `how_fixed`, `rotation_note`).
- **Tier Classification (`backend/app/ai/tiers.py`):**
  - `auto_branch`: High-confidence deterministic patches suitable for automated branch creation.
  - `pr_review`: Changes modifying application logic or environment configs requiring peer review.
  - `flag_only`: Architectural exposures requiring manual intervention (generates rotation checklist only).
- **Post-Generation Validation:** Re-scans proposed patches with regex rules to guarantee secrets were eradicated and syntax compiles cleanly.
- **Suppression Engine (`backend/app/ai/feedback.py`):** Records false-positive feedback and suppresses recurring alerts across future rescans.
- **Validated Fixtures (`fixes.json`):** Created and verified AI patches for AWS access keys, Stripe secret tokens, and GitHub PATs.

---

### 4. Rishika (Security Standards, Compliance & Heuristic Risk Lead)
*Branch:* `rishika`  
*Focus:* OWASP & ASVS Control Mapping, Heuristic Risk Formula, and Evaluation Fixtures.

**Key Deliverables & Completed Work:**
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
    - Historical secret count in Git log (weight: 0.35)
    - Untracked or committed `.env` files (weight: 0.25)
    - Days since last active commit / commit velocity (weight: 0.15)
    - Missing `.gitignore` environment rules (weight: 0.15)
    - Contributor churn count (weight: 0.10)
- **Rotation Guides (`backend/app/compliance/rotation.py`):** Formulated provider-specific operational checklists to guide engineers through IAM invalidation, key rolling, and audit log inspection.
- **Evaluation Fixtures (`fixtures/`):** Created realistic repository samples, fake credential fixtures, and JSON schemas for integration testing.

---

## 4. Key Architectural Guarantees & Contracts

| Principle | Enforcement Mechanism |
|---|---|
| **Zero-Raw-Secret Policy** | Raw secrets are never stored in PostgreSQL, never returned in API responses, never shown in UI, and never sent to external LLM providers. Only `secret_masked` and SHA-256 hashes are persisted. |
| **Strict Zero-Auto-Merge** | Pull requests are created on dedicated branches (`repoguard/fix-{id}`) for human peer review. Nothing is ever auto-merged into default branches. |
| **Rotation-Aware Remediations** | Every secret fix enforces `rotation_required: true` and includes provider-specific rotation guidance because code patching does not purge exposed keys from past commits. |
| **Ephemeral Disk Isolation** | Scans execute in isolated temporary clones that are purged immediately after execution (`shutil.rmtree`). |
| **Contract Consistency** | All models and endpoints adhere strictly to `snake_case` naming defined in [`CONTRACTS.md`](file:///c:/proj/ideanova/docs/CONTRACTS.md). |

---

## 5. End-to-End Workflow Demonstration

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

## 6. How to Run Locally

### Prerequisites
- Node.js 18+ and npm
- Python 3.12+ (Python 3.14 supported)
- PostgreSQL 16
- Gitleaks 8.30+ installed and on system `PATH`

### 1. Backend Setup
```powershell
cd backend
cp .env.example .env
# Edit .env with your DATABASE_URL, GITHUB_TOKEN, and GROQ_API_KEY / GEMINI_API_KEY
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8002
```
*API will run on:* `http://localhost:8002` (Health: `http://localhost:8002/health`)

### 2. Frontend Setup
```powershell
# In project root
npm install
npm run dev
```
*Frontend will run on:* `http://localhost:5173`

### 3. Docker Compose (Alternative)
```powershell
docker compose up --build
```

---

## 7. Verification & Evaluation Checklist

- [x] **Linting:** `oxlint` passes with **0 warnings, 0 errors**.
- [x] **Production Build:** `vite build` bundles cleanly into `dist/`.
- [x] **Contracts Compatibility:** Adheres to all Pydantic schemas in `CONTRACTS.md`.
- [x] **Branch Hygiene:** `design1` is the active, unified default branch tracking `origin/design1`. Redundant `main` branch deleted.
- [x] **Zero Mock Fallbacks:** Real API errors and genuine scan metrics are rendered without silent fake score injections.
- [x] **PR Safety:** `POST /api/fixes/{id}/open-pr` strictly validates Fix ID.
