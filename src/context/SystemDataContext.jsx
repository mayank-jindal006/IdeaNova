import React, { createContext, useState, useContext } from 'react';

const SystemDataContext = createContext(null);

// Helper to simulate sleep
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

export const SystemDataProvider = ({ children }) => {
  // 1. Initial Repositories Mock Data
  const [repositories, setRepositories] = useState([
    {
      id: 'repo-1',
      name: 'payment-api',
      language: 'JavaScript',
      branch: 'main',
      complianceScore: 42,
      leakProbability: 94,
      riskLevel: 'critical',
      lastCommit: 'Merge pull request #342 from dev-bob/feature-stripe',
      commitDate: '2 hours ago',
      scanningStatus: 'idle',
      scanProgress: 0,
      factors: [
        'Hardcoded stripe token detected in recent push',
        'High commit frequency by junior contributors',
        'Historical secrets leaked in older branches'
      ]
    },
    {
      id: 'repo-2',
      name: 'auth-service',
      language: 'Go',
      branch: 'master',
      complianceScore: 68,
      leakProbability: 65,
      riskLevel: 'high',
      lastCommit: 'refactor: simplify token validation endpoint',
      commitDate: '1 day ago',
      scanningStatus: 'idle',
      scanProgress: 0,
      factors: [
        'JWT signing secret stored in static JSON config',
        'Dependency "golang.org/x/crypto" is outdated'
      ]
    },
    {
      id: 'repo-3',
      name: 'web-gateway',
      language: 'Java',
      branch: 'main',
      complianceScore: 78,
      leakProbability: 38,
      riskLevel: 'medium',
      lastCommit: 'fix: resolve connection pool leak in db driver',
      commitDate: '3 days ago',
      scanningStatus: 'idle',
      scanProgress: 0,
      factors: [
        'Vulnerable Log4j library version found in pom.xml',
        'Low code review coverage on infrastructure commits'
      ]
    },
    {
      id: 'repo-4',
      name: 'data-pipeline',
      language: 'Python',
      branch: 'develop',
      complianceScore: 55,
      leakProbability: 82,
      riskLevel: 'critical',
      lastCommit: 'feat: add redshift bulk copy operation',
      commitDate: '4 hours ago',
      scanningStatus: 'idle',
      scanProgress: 0,
      factors: [
        'AWS credentials hardcoded in credentials script',
        'Unencrypted connection string used for database backend'
      ]
    },
    {
      id: 'repo-5',
      name: 'frontend-app',
      language: 'TypeScript',
      branch: 'main',
      complianceScore: 92,
      leakProbability: 12,
      riskLevel: 'low',
      lastCommit: 'docs: update deployment instructions in README',
      commitDate: '5 days ago',
      scanningStatus: 'idle',
      scanProgress: 0,
      factors: [
        'No active secrets found',
        'All dependencies up to date'
      ]
    }
  ]);

  // 2. Initial Security Findings (Secrets)
  const [secrets, setSecrets] = useState([
    {
      id: 'sec-1',
      repoId: 'repo-1',
      type: 'Stripe Secret API Key',
      severity: 'critical',
      status: 'exposed',
      filePath: 'src/config/stripe.js',
      commitHash: '7f9a2e1',
      dateFound: '2 hours ago',
      codeSnippet: `const stripe = require('stripe');\n\n// TODO: move to env vars before release\nconst stripeKey = "sk_test_" + "51Ny9A2H4nZ2LmP8sJq91W4R8vE9c3kP0x8y1Z0q8w7t9rX5vB4m1N2p3o4i5u6y7t8r9e0";\nconst stripeClient = stripe(stripeKey);`,
      explanation: 'A live Stripe Secret Key has been committed to source code. Anyone with access to this repository can read this key and process transactions on your Stripe account. Stripe keys must be revoked immediately and rotated.',
      proposedFix: `const stripe = require('stripe');\n\n// Proposed Fix: Retrieve the API Key from environment variables\nconst stripeKey = process.env.STRIPE_SECRET_KEY;\nconst stripeClient = stripe(stripeKey);`,
      diff: [
        { type: 'context', line: 1, content: "const stripe = require('stripe');" },
        { type: 'context', line: 2, content: "" },
        { type: 'deletion', line: 3, content: '- // TODO: move to env vars before release' },
        { type: 'deletion', line: 4, content: '- const stripeKey = "sk_test_" + "51Ny9A2H4nZ2LmP8sJq91W4R8vE9c3kP0x8y1Z0q8w7t9rX5vB4m1N2p3o4i5u6y7t8r9e0";' },
        { type: 'addition', line: 3, content: '+ // Proposed Fix: Retrieve the API Key from environment variables' },
        { type: 'addition', line: 4, content: '+ const stripeKey = process.env.STRIPE_SECRET_KEY;' },
        { type: 'context', line: 5, content: 'const stripeClient = stripe(stripeKey);' }
      ]
    },
    {
      id: 'sec-2',
      repoId: 'repo-2',
      type: 'JWT Signature Secret Key',
      severity: 'critical',
      status: 'exposed',
      filePath: 'config/jwt.json',
      commitHash: '3c8d1f4',
      dateFound: '1 day ago',
      codeSnippet: `{\n  "jwt": {\n    "expiration_hours": 24,\n    "secret": "my-ultra-secure-auth-jwt-token-key-1234567"\n  }\n}`,
      explanation: 'Hardcoded symmetric key used for JWT signing and validation. If compromised, an attacker can forge authorization tokens and bypass all security boundaries to gain administrative access.',
      proposedFix: `{\n  "jwt": {\n    "expiration_hours": 24,\n    "secret_env_var": "JWT_SIGNING_SECRET"\n  }\n}`,
      diff: [
        { type: 'context', line: 1, content: "{" },
        { type: 'context', line: 2, content: "  \"jwt\": {" },
        { type: 'context', line: 3, content: "    \"expiration_hours\": 24," },
        { type: 'deletion', line: 4, content: "-    \"secret\": \"my-ultra-secure-auth-jwt-token-key-1234567\"" },
        { type: 'addition', line: 4, content: "+    \"secret_env_var\": \"JWT_SIGNING_SECRET\"" },
        { type: 'context', line: 5, content: "  }" },
        { type: 'context', line: 6, content: "}" }
      ]
    },
    {
      id: 'sec-3',
      repoId: 'repo-4',
      type: 'AWS Access Credentials',
      severity: 'critical',
      status: 'exposed',
      filePath: 'scripts/upload.py',
      commitHash: 'e5f2a1b',
      dateFound: '4 hours ago',
      codeSnippet: `import boto3\n\n# Initialize S3 Client\ns3 = boto3.client(\n    's3',\n    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',\n    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n)`,
      explanation: 'AWS Access Key ID and Secret Access Key are hardcoded. Attacking bots constantly scrape GitHub for AWS keys; within minutes, compromised keys are used to spawn cryptomining instances, resulting in massive bills.',
      proposedFix: `import boto3\nimport os\n\n# Initialize S3 Client using environment variables or IAM instance profiles\ns3 = boto3.client('s3')`,
      diff: [
        { type: 'context', line: 1, content: "import boto3" },
        { type: 'addition', line: 2, content: "+ import os" },
        { type: 'context', line: 3, content: "" },
        { type: 'context', line: 4, content: "# Initialize S3 Client" },
        { type: 'deletion', line: 5, content: "- s3 = boto3.client(" },
        { type: 'deletion', line: 6, content: "-     's3'," },
        { type: 'deletion', line: 7, content: "-     aws_access_key_id='AKIAIOSFODNN7EXAMPLE'," },
        { type: 'deletion', line: 8, content: "-     aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'" },
        { type: 'deletion', line: 9, content: "- )" },
        { type: 'addition', line: 5, content: "+ # AWS SDK automatically picks up standard env variables or IAM role metadata" },
        { type: 'addition', line: 6, content: "+ s3 = boto3.client('s3')" }
      ]
    }
  ]);

  // 3. Initial SCA Vulnerabilities (Software Composition Analysis)
  const [vulnerabilities, setVulnerabilities] = useState([
    {
      id: 'vuln-1',
      repoId: 'repo-3',
      packageName: 'org.apache.logging.log4j:log4j-core',
      currentVersion: '2.14.1',
      safeVersion: '2.17.1',
      cveId: 'CVE-2021-44228',
      severity: 'critical',
      description: 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI endpoints. An attacker who can control log messages can execute arbitrary code loaded from LDAP servers.',
      remediation: 'Upgrade to log4j-core version 2.17.1 or higher in pom.xml.'
    },
    {
      id: 'vuln-2',
      repoId: 'repo-2',
      packageName: 'golang.org/x/crypto',
      currentVersion: 'v0.0.0-20200622214139-f8659685290b',
      safeVersion: 'v0.1.0',
      cveId: 'CVE-2022-27191',
      severity: 'high',
      description: 'An attacker can trigger a panic in the SSH server implementation by sending a crafted client identifier, leading to Denial of Service (DoS).',
      remediation: 'Upgrade golang.org/x/crypto dependency to v0.1.0 or newer in go.mod.'
    },
    {
      id: 'vuln-3',
      repoId: 'repo-1',
      packageName: 'axios',
      currentVersion: '0.21.1',
      safeVersion: '0.28.0',
      cveId: 'CVE-2023-45857',
      severity: 'medium',
      description: 'Axios is vulnerable to Server-Side Request Forgery (SSRF) when handling follow redirects parameters, which could leak sensitive API tokens to 3rd party servers.',
      remediation: 'Run npm install axios@latest to upgrade to a secure version.'
    }
  ]);

  // 4. Initial AI PRs state
  const [prs, setPrs] = useState([
    {
      id: 'pr-1',
      repoId: 'repo-1',
      issueId: 'sec-1',
      title: 'chore: [RepoGuard] Rotate Stripe Secret API Key and use env vars',
      status: 'open',
      createdAt: '1 hour ago',
      author: 'RepoGuard-AI-Agent',
      diffOverview: 'Modified src/config/stripe.js (added process.env support)'
    }
  ]);

  // 5. Initial Key Rotation Integrations
  const [integrations, setIntegrations] = useState([
    {
      id: 'int-1',
      name: 'Stripe API Provider',
      type: 'stripe',
      status: 'configured',
      description: 'Allows RepoGuard to auto-revoke exposed Stripe API keys and request new tokens.',
      activeKeysCount: 1,
      lastRotation: '2 weeks ago'
    },
    {
      id: 'int-2',
      name: 'AWS Identity Management',
      type: 'aws',
      status: 'configured',
      description: 'Automates disabling and rotating exposed AWS IAM access keys.',
      activeKeysCount: 3,
      lastRotation: '1 month ago'
    },
    {
      id: 'int-3',
      name: 'HashiCorp Vault Secret Manager',
      type: 'vault',
      status: 'pending',
      description: 'Pushes rotated keys directly to Vault transit engine keyrings.',
      activeKeysCount: 0,
      lastRotation: 'Never'
    }
  ]);

  // 6. Scan Simulation Logs Storage
  const [scanLogs, setScanLogs] = useState({});

  // ------------------------------------------
  // CORE FUNCTIONS
  // ------------------------------------------

  // Run a simulated repo security scan
  const runSecurityScan = async (repoId) => {
    // 1. Update repo status to scanning
    setRepositories(prev => prev.map(r => r.id === repoId ? { ...r, scanningStatus: 'scanning', scanProgress: 5 } : r));
    
    // Set initial logs
    let currentLogs = [
      `[INFO] Starting RepoGuard Scanner v1.4.2 on repo: ${repositories.find(r => r.id === repoId).name}...`,
      `[INFO] Ingesting commit history on branch: master...`,
      `[INFO] Checking 143 file objects in working directory...`
    ];
    setScanLogs(prev => ({ ...prev, [repoId]: currentLogs }));

    await delay(1200);
    setRepositories(prev => prev.map(r => r.id === repoId ? { ...r, scanProgress: 35 } : r));
    currentLogs = [
      ...currentLogs,
      `[INFO] Scanning for Secrets (Regex engine + Entropy analyser)...`,
      `[INFO] Loaded 45 secret signatures rules.`
    ];
    setScanLogs(prev => ({ ...prev, [repoId]: currentLogs }));

    await delay(1200);
    setRepositories(prev => prev.map(r => r.id === repoId ? { ...r, scanProgress: 65 } : r));
    
    const activeSecrets = secrets.filter(s => s.repoId === repoId && s.status === 'exposed');
    if (activeSecrets.length > 0) {
      activeSecrets.forEach(sec => {
        currentLogs.push(`[WARN] SEC-LEAK DETECTED: Found matching signature [${sec.type}] in file [${sec.filePath}].`);
        currentLogs.push(`[WARN] Confidence score: 98% (High Entropy).`);
      });
    } else {
      currentLogs.push(`[INFO] Secret scanning completed. 0 exposed credentials found in files.`);
    }
    
    currentLogs.push(`[INFO] Scanning dependencies for vulnerabilities (OSV database mapping)...`);
    const activeVulns = vulnerabilities.filter(v => v.repoId === repoId);
    if (activeVulns.length > 0) {
      activeVulns.forEach(v => {
        currentLogs.push(`[WARN] VULNERABILITY FOUND: Package [${v.packageName}] is vulnerable to [${v.cveId}] (${v.severity} severity).`);
      });
    } else {
      currentLogs.push(`[INFO] Dependency check completed. 0 CVEs found.`);
    }

    setScanLogs(prev => ({ ...prev, [repoId]: [...currentLogs] }));

    await delay(1000);
    setRepositories(prev => prev.map(r => r.id === repoId ? { ...r, scanProgress: 90 } : r));
    currentLogs = [
      ...currentLogs,
      `[INFO] Executing predictive risk modeling scorecard...`,
      `[INFO] Score calculated successfully.`
    ];
    setScanLogs(prev => ({ ...prev, [repoId]: currentLogs }));

    await delay(800);
    // Complete scanning
    setRepositories(prev => prev.map(r => r.id === repoId ? { ...r, scanningStatus: 'idle', scanProgress: 100 } : r));
    currentLogs = [
      ...currentLogs,
      `[SUCCESS] Security audit completed successfully. View findings dashboard.`
    ];
    setScanLogs(prev => ({ ...prev, [repoId]: currentLogs }));
  };

  // Trigger an AI auto-fix and create a simulated PR
  const triggerAiFix = (secretId) => {
    const secret = secrets.find(s => s.id === secretId);
    if (!secret) return;

    // 1. Change secret status to fixing
    setSecrets(prev => prev.map(s => s.id === secretId ? { ...s, status: 'fixing' } : s));

    // 2. Create PR
    const newPr = {
      id: `pr-${Date.now()}`,
      repoId: secret.repoId,
      issueId: secretId,
      title: `fix: [RepoGuard] Replace exposed ${secret.type} with env vars`,
      status: 'open',
      createdAt: 'Just now',
      author: 'RepoGuard-AI-Agent',
      diffOverview: `Modified ${secret.filePath} to load config from process environment.`
    };

    setPrs(prev => [newPr, ...prev]);
  };

  // Merge PR and resolve secret leak
  const mergePr = (prId) => {
    const pr = prs.find(p => p.id === prId);
    if (!pr) return;

    // 1. Update PR status to merged
    setPrs(prev => prev.map(p => p.id === prId ? { ...p, status: 'merged' } : p));

    // 2. Update secret status to resolved
    setSecrets(prev => prev.map(s => s.id === pr.issueId ? { ...s, status: 'resolved' } : s));

    // 3. Update repo compliance score (+15 points, max 100)
    setRepositories(prev => prev.map(r => {
      if (r.id === pr.repoId) {
        const newScore = Math.min(r.complianceScore + 15, 100);
        // Decrease risk probability too
        const newProb = Math.max(r.leakProbability - 30, 5);
        return {
          ...r,
          complianceScore: newScore,
          leakProbability: newProb,
          riskLevel: newProb > 80 ? 'critical' : newProb > 50 ? 'high' : newProb > 25 ? 'medium' : 'low'
        };
      }
      return r;
    }));
  };

  // Ignore / False Positive finding toggle
  const markAsFalsePositive = (secretId) => {
    setSecrets(prev => prev.map(s => s.id === secretId ? { ...s, status: 'false_positive' } : s));
  };

  // Resolve a dependency vulnerability (Upgrade library version)
  const upgradeDependency = (vulnId) => {
    const vuln = vulnerabilities.find(v => v.id === vulnId);
    if (!vuln) return;

    // Remove the vulnerability (simulate update)
    setVulnerabilities(prev => prev.filter(v => v.id !== vulnId));

    // Improve repo score
    setRepositories(prev => prev.map(r => {
      if (r.id === vuln.repoId) {
        const newScore = Math.min(r.complianceScore + 10, 100);
        const newProb = Math.max(r.leakProbability - 10, 5);
        return {
          ...r,
          complianceScore: newScore,
          leakProbability: newProb,
          riskLevel: newProb > 80 ? 'critical' : newProb > 50 ? 'high' : newProb > 25 ? 'medium' : 'low'
        };
      }
      return r;
    }));
  };

  // Rotate Key integration trigger
  const rotateIntegrationKey = async (integrationId) => {
    setIntegrations(prev => prev.map(i => i.id === integrationId ? { ...i, status: 'pending' } : i));
    await delay(2000);
    setIntegrations(prev => prev.map(i => i.id === integrationId ? {
      ...i,
      status: 'configured',
      lastRotation: 'Just now'
    } : i));
  };

  return (
    <SystemDataContext.Provider value={{
      repositories,
      secrets,
      vulnerabilities,
      prs,
      integrations,
      scanLogs,
      runSecurityScan,
      triggerAiFix,
      mergePr,
      markAsFalsePositive,
      upgradeDependency,
      rotateIntegrationKey
    }}>
      {children}
    </SystemDataContext.Provider>
  );
};

export const useSystemData = () => {
  const context = useContext(SystemDataContext);
  if (!context) {
    throw new Error('useSystemData must be used within a SystemDataProvider');
  }
  return context;
};
