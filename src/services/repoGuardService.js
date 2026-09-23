/**
 * RepoGuard Client Data Service & Calculation Engine
 * Operates on a single coherent dataset with persistent localStorage synchronization.
 */

import {
  INITIAL_REPOSITORIES,
  INITIAL_FINDINGS,
  INITIAL_FIXES,
  INITIAL_SCANS,
  INITIAL_ACTIVITIES,
  ROTATION_CHECKLISTS
} from '../data/initialData';

const STORAGE_KEYS = {
  REPOS: 'repoguard_repos_v2',
  FINDINGS: 'repoguard_findings_v2',
  FIXES: 'repoguard_fixes_v2',
  SCANS: 'repoguard_scans_v2',
  ACTIVITIES: 'repoguard_activities_v2',
  ROTATION: 'repoguard_rotation_v2'
};

// Safe JSON loader
function loadFromStorage(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

// Safe JSON saver
function saveToStorage(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (err) {
    console.error(`[RepoGuard Storage] Failed to save key "${key}":`, err);
  }
}

// Initialize persistent state
export function getStoredState() {
  const repos = loadFromStorage(STORAGE_KEYS.REPOS, INITIAL_REPOSITORIES);
  const findings = loadFromStorage(STORAGE_KEYS.FINDINGS, INITIAL_FINDINGS);
  const fixes = loadFromStorage(STORAGE_KEYS.FIXES, INITIAL_FIXES);
  const scans = loadFromStorage(STORAGE_KEYS.SCANS, INITIAL_SCANS);
  const activities = loadFromStorage(STORAGE_KEYS.ACTIVITIES, INITIAL_ACTIVITIES);
  const rotation = loadFromStorage(STORAGE_KEYS.ROTATION, ROTATION_CHECKLISTS);

  return { repos, findings, fixes, scans, activities, rotation };
}

// ----------------------------------------------------------------------------
// Core Calculation Engines (Honest, Reconciled, Non-Random)
// ----------------------------------------------------------------------------

export function calculateComplianceScore(findings = []) {
  // Score = 100 - sum(penalty(open findings)), floored at 0
  // Critical = 25, High = 15, Medium = 7, Low = 3
  // status 'fixed' or 'false_positive' = 0 penalty
  // status 'needs_rotation' = half penalty (code fixed, credential still exposed)
  let penaltySum = 0;

  for (const f of findings) {
    if (f.status === 'fixed' || f.status === 'false_positive') {
      continue;
    }

    let penalty = 0;
    switch (f.severity) {
      case 'critical': penalty = 25; break;
      case 'high': penalty = 15; break;
      case 'medium': penalty = 7; break;
      case 'low': penalty = 3; break;
      default: penalty = 5;
    }

    if (f.status === 'needs_rotation') {
      penalty = Math.round(penalty / 2);
    }

    penaltySum += penalty;
  }

  return Math.max(0, 100 - penaltySum);
}

export function calculateHeuristicRisk(repo, repoFindings = []) {
  // Visible factor breakdown:
  // 1. Open secrets in HEAD: count * 10 (max 30)
  // 2. Historical secrets: count * 5 (max 15)
  // 3. .env tracked in repo: 15
  // 4. .gitignore missing .env: 10
  // 5. Missing pre-commit secret hook: 5
  // 6. Vulnerable dependencies (crit/high): count * 4 (max 15)
  // 7. Contributor velocity & commit rate: scaled (max 10)

  const activeSecretsInHead = repoFindings.filter(
    f => f.type === 'secret' && !f.inHistoryOnly && !['fixed', 'false_positive'].includes(f.status)
  ).length;

  const historicalSecrets = repoFindings.filter(
    f => f.type === 'secret' && f.inHistoryOnly && !['fixed', 'false_positive'].includes(f.status)
  ).length;

  const vulnerableDeps = repoFindings.filter(
    f => f.type === 'dependency' && ['critical', 'high'].includes(f.severity) && !['fixed', 'false_positive'].includes(f.status)
  ).length;

  const signals = repo?.signals || {};

  const f1_contrib = Math.min(30, activeSecretsInHead * 10);
  const f2_contrib = Math.min(15, historicalSecrets * 5);
  const f3_contrib = signals.envFileTracked ? 15 : 0;
  const f4_contrib = !signals.gitignoreHasEnv ? 10 : 0;
  const f5_contrib = !signals.hasPrecommitSecretHook ? 5 : 0;
  const f6_contrib = Math.min(15, vulnerableDeps * 4);
  const f7_contrib = (signals.contributorCount || 1) >= 5 ? 5 : 0;

  const factors = [
    {
      name: "Open secrets in HEAD",
      signal: `${activeSecretsInHead} active secret${activeSecretsInHead === 1 ? '' : 's'}`,
      weight: 10,
      contribution: f1_contrib
    },
    {
      name: "Historical secrets in git tree",
      signal: `${historicalSecrets} historical secret${historicalSecrets === 1 ? '' : 's'}`,
      weight: 5,
      contribution: f2_contrib
    },
    {
      name: ".env committed to git repository",
      signal: signals.envFileTracked ? "Tracked in branch" : "Clean (Untracked)",
      weight: 15,
      contribution: f3_contrib
    },
    {
      name: ".gitignore missing .env protection",
      signal: signals.gitignoreHasEnv ? "Protected (.env ignored)" : "Missing from .gitignore",
      weight: 10,
      contribution: f4_contrib
    },
    {
      name: "Missing pre-commit secret hook",
      signal: signals.hasPrecommitSecretHook ? "Installed & enforced" : "No pre-commit hook",
      weight: 5,
      contribution: f5_contrib
    },
    {
      name: "High/Critical dependency CVEs",
      signal: `${vulnerableDeps} package vulnerability`,
      weight: 4,
      contribution: f6_contrib
    },
    {
      name: "Contributor velocity & commit rate",
      signal: `${signals.contributorCount || 1} contributors, ${signals.commitCount90d || 0} commits / 90d`,
      weight: 10,
      contribution: f7_contrib
    }
  ];

  const totalRaw = factors.reduce((sum, f) => sum + f.contribution, 0);
  const score = Math.min(100, totalRaw);

  return { score, factors };
}

export function getSeverityCounts(findings = []) {
  const active = findings.filter(f => !['fixed', 'false_positive'].includes(f.status));
  return {
    critical: active.filter(f => f.severity === 'critical').length,
    high: active.filter(f => f.severity === 'high').length,
    medium: active.filter(f => f.severity === 'medium').length,
    low: active.filter(f => f.severity === 'low').length,
    totalActive: active.length,
    totalAll: findings.length
  };
}

export function getOverallMetrics(repos = [], findings = []) {
  const activeFindings = findings.filter(f => !['fixed', 'false_positive'].includes(f.status));
  const openFindings = findings.filter(f => f.status === 'open');
  const criticalFindings = activeFindings.filter(f => f.severity === 'critical');
  const needsRotationFindings = findings.filter(f => f.status === 'needs_rotation');
  const fixedFindings = findings.filter(f => f.status === 'fixed');

  // Compute average compliance across repos
  const repoComplianceScores = repos.map(r => {
    const rFindings = findings.filter(f => f.repoId === r.id);
    return calculateComplianceScore(rFindings);
  });
  const avgCompliance = repoComplianceScores.length > 0
    ? Math.round(repoComplianceScores.reduce((a, b) => a + b, 0) / repoComplianceScores.length)
    : 100;

  // Compute average heuristic risk across repos
  const repoRiskScores = repos.map(r => {
    const rFindings = findings.filter(f => f.repoId === r.id);
    return calculateHeuristicRisk(r, rFindings).score;
  });
  const avgRisk = repoRiskScores.length > 0
    ? Math.round(repoRiskScores.reduce((a, b) => a + b, 0) / repoRiskScores.length)
    : 0;

  return {
    totalRepos: repos.length,
    activeFindingsCount: activeFindings.length,
    openFindingsCount: openFindings.length,
    criticalFindingsCount: criticalFindings.length,
    needsRotationCount: needsRotationFindings.length,
    fixedCount: fixedFindings.length,
    avgCompliance,
    avgRisk
  };
}

export function getOWASPComplianceBreakdown(findings = []) {
  const active = findings.filter(f => !['fixed', 'false_positive'].includes(f.status));

  const controls = [
    {
      id: "A01:2021",
      name: "Broken Access Control",
      description: "Enforce least privilege access, prevent open redirects and SSRF exposures."
    },
    {
      id: "A02:2021",
      name: "Cryptographic Failures",
      description: "Protect sensitive data in transit and rest; prevent plaintext credentials in source."
    },
    {
      id: "A05:2021",
      name: "Security Misconfiguration",
      description: "Ensure proper configuration hardening, environment separation, and .env isolation."
    },
    {
      id: "A06:2021",
      name: "Vulnerable and Outdated Components",
      description: "Audit third-party dependencies for known CVEs and maintain patched package pins."
    },
    {
      id: "A07:2021",
      name: "Identification and Authentication Failures",
      description: "Prevent credential stuffing, API key leakage, and insecure authentication token handling."
    }
  ];

  return controls.map(ctrl => {
    const matching = active.filter(f => f.owaspIds && f.owaspIds.includes(ctrl.id));
    return {
      ...ctrl,
      status: matching.length === 0 ? "passing" : "failing",
      findingsCount: matching.length,
      findings: matching
    };
  });
}

// ----------------------------------------------------------------------------
// Local State Mutation & Persistence Helpers
// ----------------------------------------------------------------------------

export const repoGuardService = {
  getState: getStoredState,

  saveRepos: (repos) => saveToStorage(STORAGE_KEYS.REPOS, repos),
  saveFindings: (findings) => saveToStorage(STORAGE_KEYS.FINDINGS, findings),
  saveFixes: (fixes) => saveToStorage(STORAGE_KEYS.FIXES, fixes),
  saveScans: (scans) => saveToStorage(STORAGE_KEYS.SCANS, scans),
  saveActivities: (activities) => saveToStorage(STORAGE_KEYS.ACTIVITIES, activities),
  saveRotation: (rotation) => saveToStorage(STORAGE_KEYS.ROTATION, rotation),

  resetToDefault: () => {
    Object.values(STORAGE_KEYS).forEach(key => localStorage.removeItem(key));
    return getStoredState();
  }
};
