/**
 * RepoGuard Canonical Dataset
 * Ground truth for local state and calculation engines.
 */

export const INITIAL_REPOSITORIES = [
  {
    id: "repoguard-test-python",
    name: "repoguard-test-python",
    fullName: "repoguard-org/repoguard-test-python",
    description: "Flask microservice with internal payment dispatch and legacy database helpers.",
    defaultBranch: "main",
    language: "Python",
    createdAt: "2026-09-18T10:00:00Z",
    lastScannedAt: "2026-09-23T18:30:00Z",
    scanStatus: "completed", // queued | scanning | completed | failed
    signals: {
      envFileTracked: false,
      gitignoreHasEnv: false,
      hasPrecommitSecretHook: false,
      commitCount90d: 48,
      contributorCount: 6,
      daysSinceLastCommit: 2
    }
  },
  {
    id: "repoguard-test-node",
    name: "repoguard-test-node",
    fullName: "repoguard-org/repoguard-test-node",
    description: "Express authentication gateway service with third-party webhook dispatchers.",
    defaultBranch: "main",
    language: "JavaScript",
    createdAt: "2026-09-19T11:30:00Z",
    lastScannedAt: "2026-09-23T18:45:00Z",
    scanStatus: "completed",
    signals: {
      envFileTracked: true,
      gitignoreHasEnv: false,
      hasPrecommitSecretHook: false,
      commitCount90d: 72,
      contributorCount: 9,
      daysSinceLastCommit: 1
    }
  },
  {
    id: "repoguard-test-clean",
    name: "repoguard-test-clean",
    fullName: "repoguard-org/repoguard-test-clean",
    description: "Reference hardened repository with strict environment boundaries and zero known exposures.",
    defaultBranch: "main",
    language: "Python",
    createdAt: "2026-09-20T09:00:00Z",
    lastScannedAt: "2026-09-23T19:00:00Z",
    scanStatus: "completed",
    signals: {
      envFileTracked: false,
      gitignoreHasEnv: true,
      hasPrecommitSecretHook: true,
      commitCount90d: 14,
      contributorCount: 2,
      daysSinceLastCommit: 5
    }
  }
];

export const INITIAL_FINDINGS = [
  {
    id: "sec-101",
    repoId: "repoguard-test-python",
    type: "secret",
    ruleId: "aws-access-token",
    title: "AWS Access Key committed in configuration",
    severity: "critical",
    filePath: "app/config.py",
    line: 14,
    commitSha: "a1b2c3d4e5f67890123456789abcdef012345678",
    secretMasked: "AKIA••••MPLE",
    secretHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    package: null,
    ecosystem: null,
    installedVersion: null,
    fixedVersion: null,
    inHistoryOnly: false,
    confidence: 0.95,
    status: "open", // open | fix_proposed | pr_opened | fixed | false_positive | needs_rotation
    owaspIds: ["A07:2021"],
    asvsIds: ["V6.4.1"],
    detectedAt: "2026-09-23T18:29:45Z"
  },
  {
    id: "sec-102",
    repoId: "repoguard-test-python",
    type: "secret",
    ruleId: "postgres-connection-string",
    title: "PostgreSQL connection string with hardcoded password",
    severity: "critical",
    filePath: "app/db.py",
    line: 8,
    commitSha: "a1b2c3d4e5f67890123456789abcdef012345678",
    secretMasked: "post••••9999",
    secretHash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    package: null,
    ecosystem: null,
    installedVersion: null,
    fixedVersion: null,
    inHistoryOnly: false,
    confidence: 0.92,
    status: "open",
    owaspIds: ["A02:2021", "A07:2021"],
    asvsIds: ["V6.4.2"],
    detectedAt: "2026-09-23T18:29:48Z"
  },
  {
    id: "sec-103",
    repoId: "repoguard-test-python",
    type: "secret",
    ruleId: "stripe-api-key",
    title: "Stripe Secret Key leaked in historical commit",
    severity: "high",
    filePath: "legacy/billing.py",
    line: 22,
    commitSha: "8f7e6d5c4b3a210987654321fedcba0987654321",
    secretMasked: "sk_t••••5678",
    secretHash: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    package: null,
    ecosystem: null,
    installedVersion: null,
    fixedVersion: null,
    inHistoryOnly: true,
    confidence: 0.88,
    status: "needs_rotation",
    owaspIds: ["A07:2021"],
    asvsIds: ["V6.4.1"],
    detectedAt: "2026-09-23T18:29:50Z"
  },
  {
    id: "dep-104",
    repoId: "repoguard-test-python",
    type: "dependency",
    ruleId: "GHSA-4w7x-h847-qrq6",
    title: "Jinja2 vulnerable to Sandbox Bypass via arbitrary attribute access",
    severity: "high",
    filePath: "requirements.txt",
    line: 4,
    commitSha: "a1b2c3d4e5f67890123456789abcdef012345678",
    secretMasked: null,
    secretHash: null,
    package: "jinja2",
    ecosystem: "PyPI",
    installedVersion: "3.1.2",
    fixedVersion: "3.1.5",
    inHistoryOnly: false,
    confidence: 1.0,
    status: "open",
    owaspIds: ["A06:2021"],
    asvsIds: ["V14.2.1"],
    detectedAt: "2026-09-23T18:29:55Z"
  },
  {
    id: "dep-105",
    repoId: "repoguard-test-python",
    type: "dependency",
    ruleId: "GHSA-j8r2-6x86-q33q",
    title: "Requests vulnerable to unintended leak of Proxy-Authorization header",
    severity: "medium",
    filePath: "requirements.txt",
    line: 7,
    commitSha: "a1b2c3d4e5f67890123456789abcdef012345678",
    secretMasked: null,
    secretHash: null,
    package: "requests",
    ecosystem: "PyPI",
    installedVersion: "2.30.0",
    fixedVersion: "2.32.0",
    inHistoryOnly: false,
    confidence: 1.0,
    status: "open",
    owaspIds: ["A06:2021"],
    asvsIds: ["V14.2.1"],
    detectedAt: "2026-09-23T18:29:58Z"
  },
  {
    id: "sec-106",
    repoId: "repoguard-test-node",
    type: "secret",
    ruleId: "github-pat",
    title: "GitHub Personal Access Token hardcoded in sync handler",
    severity: "critical",
    filePath: "src/sync.js",
    line: 42,
    commitSha: "f1e2d3c4b5a67890123456789abcdef012345678",
    secretMasked: "ghp_••••klmn",
    secretHash: "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
    package: null,
    ecosystem: null,
    installedVersion: null,
    fixedVersion: null,
    inHistoryOnly: false,
    confidence: 0.96,
    status: "open",
    owaspIds: ["A07:2021"],
    asvsIds: ["V6.4.1"],
    detectedAt: "2026-09-23T18:44:50Z"
  },
  {
    id: "sec-107",
    repoId: "repoguard-test-node",
    type: "secret",
    ruleId: "generic-api-key",
    title: "Third-party Service API Key committed in tracked .env file",
    severity: "medium",
    filePath: ".env",
    line: 3,
    commitSha: "f1e2d3c4b5a67890123456789abcdef012345678",
    secretMasked: "api_••••wxyz",
    secretHash: "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
    package: null,
    ecosystem: null,
    installedVersion: null,
    fixedVersion: null,
    inHistoryOnly: false,
    confidence: 0.78,
    status: "open",
    owaspIds: ["A05:2021"],
    asvsIds: ["V14.2.1"],
    detectedAt: "2026-09-23T18:44:52Z"
  },
  {
    id: "dep-108",
    repoId: "repoguard-test-node",
    type: "dependency",
    ruleId: "GHSA-76p3-8jx3-jpfq",
    title: "Express vulnerable to Open Redirect via malformed URLs",
    severity: "high",
    filePath: "package.json",
    line: 15,
    commitSha: "f1e2d3c4b5a67890123456789abcdef012345678",
    secretMasked: null,
    secretHash: null,
    package: "express",
    ecosystem: "npm",
    installedVersion: "4.18.2",
    fixedVersion: "4.19.2",
    inHistoryOnly: false,
    confidence: 1.0,
    status: "open",
    owaspIds: ["A01:2021", "A06:2021"],
    asvsIds: ["V14.2.1"],
    detectedAt: "2026-09-23T18:44:58Z"
  }
];

export const INITIAL_FIXES = {
  "sec-101": {
    findingId: "sec-101",
    explanation: {
      what: "An AWS access key is hardcoded directly in app/config.py.",
      whyDangerous: "Anyone who clones this repository or gains read access can invoke AWS APIs under your IAM identity, potentially creating resources or exfiltrating data.",
      howFixed: "Extracted credential lookup to os.environ.get('AWS_ACCESS_KEY_ID'), added .env.example template, and updated configuration loader.",
      rotationRequired: true,
      rotationNote: "The AWS credential remains in Git commit history. Revoke and rotate this key in the AWS IAM Console immediately."
    },
    tier: "auto_branch", // auto_branch | pr_review | flag_only
    validation: {
      secretRemoved: true,
      syntaxOk: true,
      notes: [
        "Re-scanned modified file with Gitleaks: 0 secrets detected.",
        "Python syntax check (py_compile): Passed without syntax errors."
      ]
    },
    diff: {
      filePath: "app/config.py",
      beforeContent: `import os

class Config:
    DEBUG = False
    TESTING = False
    DATABASE_URI = os.getenv("DATABASE_URL")
    
    # AWS S3 Storage Credentials
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    S3_BUCKET = "repoguard-uploads-prod"`,
      afterContent: `import os

class Config:
    DEBUG = False
    TESTING = False
    DATABASE_URI = os.getenv("DATABASE_URL")
    
    # AWS S3 Storage Credentials (Loaded securely from environment)
    AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
    S3_BUCKET = os.environ.get("S3_BUCKET", "repoguard-uploads-prod")`
    },
    prNumber: 42,
    prUrl: "https://github.com/repoguard-org/repoguard-test-python/pull/42",
    status: "pr_opened"
  },
  "dep-104": {
    findingId: "dep-104",
    explanation: {
      what: "Pinned Jinja2 dependency version 3.1.2 contains a known sandbox escape vulnerability.",
      whyDangerous: "Attackers can bypass template sandboxes and access arbitrary attributes on the execution environment.",
      howFixed: "Bumped jinja2 pin in requirements.txt from 3.1.2 to 3.1.5.",
      rotationRequired: false,
      rotationNote: null
    },
    tier: "pr_review",
    validation: {
      secretRemoved: true,
      syntaxOk: true,
      notes: ["Dependency version bump verified against PyPI metadata."]
    },
    diff: {
      filePath: "requirements.txt",
      beforeContent: `flask==3.0.2
gunicorn==21.2.0
jinja2==3.1.2
requests==2.30.0
psycopg2-binary==2.9.9`,
      afterContent: `flask==3.0.2
gunicorn==21.2.0
jinja2==3.1.5
requests==2.30.0
psycopg2-binary==2.9.9`
    },
    prNumber: null,
    prUrl: null,
    status: "fix_proposed"
  }
};

export const ROTATION_CHECKLISTS = {
  "aws-access-token": {
    provider: "AWS IAM",
    steps: [
      { id: "step-1", label: "Open AWS IAM Console -> Users -> Security Credentials.", completed: true },
      { id: "step-2", label: "Locate compromised Access Key ID and switch status to 'Inactive'.", completed: true },
      { id: "step-3", label: "Create new Access Key pair and securely store in Secrets Manager.", completed: false },
      { id: "step-4", label: "Deploy new environment variables across active workloads.", completed: false },
      { id: "step-5", label: "Permanently delete the inactive credential from AWS IAM.", completed: false },
      { id: "step-6", label: "Trigger RepoGuard repository rescan to verify code clean.", completed: false }
    ]
  },
  "postgres-connection-string": {
    provider: "PostgreSQL Database",
    steps: [
      { id: "step-1", label: "Connect to the database instance via psql with administrative privileges.", completed: true },
      { id: "step-2", label: "Rotate user password: ALTER USER <username> WITH PASSWORD '<new_secret>';", completed: false },
      { id: "step-3", label: "Update connection string in secret vault / deployment environment.", completed: false },
      { id: "step-4", label: "Restart application connection pool instances gracefully.", completed: false },
      { id: "step-5", label: "Inspect database connection logs for unauthenticated access attempts.", completed: false }
    ]
  },
  "stripe-api-key": {
    provider: "Stripe Developer Dashboard",
    steps: [
      { id: "step-1", label: "Navigate to Stripe Dashboard -> Developers -> API Keys.", completed: true },
      { id: "step-2", label: "Click 'Roll key...' next to the compromised Secret Key.", completed: true },
      { id: "step-3", label: "Select a 24-hour expiration window for the old key to prevent service interruption.", completed: false },
      { id: "step-4", label: "Update STRIPE_SECRET_KEY on production servers.", completed: false },
      { id: "step-5", label: "Confirm payment and webhook operations execute without authentication failures.", completed: false }
    ]
  },
  "github-pat": {
    provider: "GitHub Developer Settings",
    steps: [
      { id: "step-1", label: "Open GitHub Settings -> Developer settings -> Personal access tokens.", completed: true },
      { id: "step-2", label: "Immediately revoke the compromised token.", completed: false },
      { id: "step-3", label: "Generate a new fine-grained token with minimum necessary repository permissions.", completed: false },
      { id: "step-4", label: "Update CI/CD runner secrets and local environment configs.", completed: false },
      { id: "step-5", label: "Inspect GitHub Security Audit Log for unauthorized API requests.", completed: false }
    ]
  },
  "generic-api-key": {
    provider: "Third-Party API Provider",
    steps: [
      { id: "step-1", label: "Access provider administration portal and revoke exposed token.", completed: true },
      { id: "step-2", label: "Generate a replacement key with restricted IP / role permissions.", completed: false },
      { id: "step-3", label: "Store key only in local .env and confirm .env is present in .gitignore.", completed: false },
      { id: "step-4", label: "Ensure credentials are never committed to source branches.", completed: false }
    ]
  }
};

export const INITIAL_SCANS = [
  {
    id: "scan-901",
    repoId: "repoguard-test-python",
    trigger: "manual",
    commitSha: "a1b2c3d4e5f67890123456789abcdef012345678",
    status: "completed",
    startedAt: "2026-09-23T18:29:40Z",
    finishedAt: "2026-09-23T18:30:00Z",
    durationSeconds: 20,
    findingsCount: 5,
    summary: "Found 3 secret exposures (1 historical) and 2 vulnerable dependency packages."
  },
  {
    id: "scan-902",
    repoId: "repoguard-test-node",
    trigger: "push",
    commitSha: "f1e2d3c4b5a67890123456789abcdef012345678",
    status: "completed",
    startedAt: "2026-09-23T18:44:40Z",
    finishedAt: "2026-09-23T18:45:00Z",
    durationSeconds: 20,
    findingsCount: 3,
    summary: "Found 2 secret exposures and 1 vulnerable dependency package."
  },
  {
    id: "scan-903",
    repoId: "repoguard-test-clean",
    trigger: "manual",
    commitSha: "99887766554433221100aabbccddeeff00112233",
    status: "completed",
    startedAt: "2026-09-23T18:59:50Z",
    finishedAt: "2026-09-23T19:00:00Z",
    durationSeconds: 10,
    findingsCount: 0,
    summary: "Clean repository scan. Zero secrets and zero vulnerable packages identified."
  }
];

export const INITIAL_ACTIVITIES = [
  {
    id: "act-1",
    timestamp: "2026-09-23T19:00:00Z",
    type: "scan_completed",
    repoId: "repoguard-test-clean",
    repoName: "repoguard-test-clean",
    title: "Scheduled scan completed",
    description: "Audit completed with 0 findings discovered. Compliance at 100%."
  },
  {
    id: "act-2",
    timestamp: "2026-09-23T18:50:12Z",
    type: "pr_opened",
    repoId: "repoguard-test-python",
    repoName: "repoguard-test-python",
    title: "Remediation Pull Request opened",
    description: "Opened PR #42 to replace hardcoded AWS access token with environment lookup."
  },
  {
    id: "act-3",
    timestamp: "2026-09-23T18:45:00Z",
    type: "secret_detected",
    repoId: "repoguard-test-node",
    repoName: "repoguard-test-node",
    title: "Critical GitHub token detected",
    description: "Gitleaks flagged active token in src/sync.js on branch main."
  },
  {
    id: "act-4",
    timestamp: "2026-09-23T18:30:00Z",
    type: "rotation_required",
    repoId: "repoguard-test-python",
    repoName: "repoguard-test-python",
    title: "Credential rotation checklist issued",
    description: "Stripe key discovered in historical commit 8f7e6d5. Issued provider rotation checklist."
  }
];
