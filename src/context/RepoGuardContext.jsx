import React, { createContext, useContext, useState, useMemo, useCallback } from 'react';
import {
  getStoredState,
  repoGuardService,
  getOverallMetrics
} from '../services/repoGuardService';

const RepoGuardContext = createContext(null);

export const RepoGuardProvider = ({ children }) => {
  const [state, setState] = useState(() => getStoredState());

  const { repos, findings, fixes, scans, activities, rotation } = state;

  // Reconciled metrics derived strictly from the dataset
  const metrics = useMemo(() => {
    return getOverallMetrics(repos, findings);
  }, [repos, findings]);

  // Add Repository
  const addRepository = useCallback((fullName, defaultBranch = "main") => {
    const cleanName = fullName.trim();
    if (!cleanName) {
      throw new Error("Repository full name cannot be empty.");
    }
    if (!cleanName.includes("/")) {
      throw new Error("Repository must follow 'owner/repo' format (e.g. repoguard-org/app).");
    }

    const id = cleanName.replace(/[^a-zA-Z0-9_-]/g, "-").toLowerCase();
    const existing = repos.find(r => r.fullName.toLowerCase() === cleanName.toLowerCase() || r.id === id);
    if (existing) {
      throw new Error(`Repository '${cleanName}' is already being monitored.`);
    }

    const shortName = cleanName.split("/")[1] || cleanName;
    const newRepo = {
      id,
      name: shortName,
      fullName: cleanName,
      description: "Imported GitHub repository monitored for secrets and dependency risks.",
      defaultBranch: defaultBranch.trim() || "main",
      language: "JavaScript",
      createdAt: new Date().toISOString(),
      lastScannedAt: null,
      scanStatus: "queued",
      signals: {
        envFileTracked: false,
        gitignoreHasEnv: true,
        hasPrecommitSecretHook: false,
        commitCount90d: 5,
        contributorCount: 1,
        daysSinceLastCommit: 0
      }
    };

    const newActivity = {
      id: `act-${Date.now()}`,
      timestamp: new Date().toISOString(),
      type: "repo_added",
      repoId: id,
      repoName: shortName,
      title: "Repository registered",
      description: `Added repository ${cleanName} on branch ${newRepo.defaultBranch}.`
    };

    const updatedRepos = [newRepo, ...repos];
    const updatedActivities = [newActivity, ...activities];

    setState(prev => ({
      ...prev,
      repos: updatedRepos,
      activities: updatedActivities
    }));

    repoGuardService.saveRepos(updatedRepos);
    repoGuardService.saveActivities(updatedActivities);

    return newRepo;
  }, [repos, activities]);

  // Run Scan state machine with stage updates
  const runScan = useCallback(async (repoId, onStageUpdate) => {
    const repo = repos.find(r => r.id === repoId);
    if (!repo) throw new Error("Repository not found");

    // Stage 1: Queued
    onStageUpdate?.({ stage: 'queued', label: 'Queuing security scan request...', progress: 10 });
    await new Promise(r => setTimeout(r, 600));

    // Stage 2: Ingesting & scanning secrets
    onStageUpdate?.({ stage: 'scanning_secrets', label: 'Running Gitleaks: Scanning commit tree for hardcoded credentials...', progress: 35 });
    await new Promise(r => setTimeout(r, 800));

    // Stage 3: Dependency SCA query
    onStageUpdate?.({ stage: 'scanning_deps', label: 'Querying OSV.dev database for dependency CVEs...', progress: 65 });
    await new Promise(r => setTimeout(r, 800));

    // Stage 4: Normalization & Compliance scoring
    onStageUpdate?.({ stage: 'analysing', label: 'Mapping controls to OWASP Top 10 & ASVS controls; calculating Heuristic Risk...', progress: 90 });
    await new Promise(r => setTimeout(r, 600));

    // Stage 5: Completed
    const repoFindings = findings.filter(f => f.repoId === repoId);
    const scanId = `scan-${Date.now()}`;
    const nowIso = new Date().toISOString();

    const newScanRecord = {
      id: scanId,
      repoId,
      trigger: "manual",
      commitSha: "head-" + Math.random().toString(16).slice(2, 10),
      status: "completed",
      startedAt: new Date(Date.now() - 3000).toISOString(),
      finishedAt: nowIso,
      durationSeconds: 3,
      findingsCount: repoFindings.filter(f => !['fixed', 'false_positive'].includes(f.status)).length,
      summary: `Discovered ${repoFindings.filter(f => f.type === 'secret').length} secrets and ${repoFindings.filter(f => f.type === 'dependency').length} dependency findings.`
    };

    const newActivity = {
      id: `act-${Date.now()}`,
      timestamp: nowIso,
      type: "scan_completed",
      repoId: repo.id,
      repoName: repo.name,
      title: "Repository scan completed",
      description: `Manual scan of ${repo.name} concluded: ${newScanRecord.findingsCount} active finding(s) detected.`
    };

    const updatedRepos = repos.map(r => r.id === repoId ? {
      ...r,
      lastScannedAt: nowIso,
      scanStatus: "completed"
    } : r);

    const updatedScans = [newScanRecord, ...scans];
    const updatedActivities = [newActivity, ...activities];

    setState(prev => ({
      ...prev,
      repos: updatedRepos,
      scans: updatedScans,
      activities: updatedActivities
    }));

    repoGuardService.saveRepos(updatedRepos);
    repoGuardService.saveScans(updatedScans);
    repoGuardService.saveActivities(updatedActivities);

    onStageUpdate?.({ stage: 'completed', label: 'Scan completed successfully.', progress: 100 });
    return newScanRecord;
  }, [repos, findings, scans, activities]);

  // Generate AI Fix for a finding
  const generateFix = useCallback(async (findingId) => {
    const finding = findings.find(f => f.id === findingId);
    if (!finding) throw new Error("Finding not found");

    // Simulate model inference time
    await new Promise(r => setTimeout(r, 1200));

    let newFix = fixes[findingId];
    if (!newFix) {
      if (finding.type === 'secret') {
        newFix = {
          findingId,
          explanation: {
            what: `Hardcoded credential detected in ${finding.filePath}.`,
            whyDangerous: "Exposed keys can be scraped from source code and exploited for unauthorized data access or billing fraud.",
            howFixed: "Replaced hardcoded token string with environment variable lookup and ensured template configuration is gitignored.",
            rotationRequired: true,
            rotationNote: "Source code removal does not revoke credentials from Git tree history. Please complete rotation steps."
          },
          tier: "pr_review",
          validation: {
            secretRemoved: true,
            syntaxOk: true,
            notes: [
              "Gitleaks re-scan verified zero matching credentials in proposed patch.",
              "Syntax compilation verified successfully."
            ]
          },
          diff: {
            filePath: finding.filePath,
            beforeContent: `// Original content with credential\nconst API_SECRET = "${finding.secretMasked || 'AKIA••••EXAMPLE'}";`,
            afterContent: `// Remediated content\nconst API_SECRET = process.env.API_SECRET;`
          },
          prNumber: null,
          prUrl: null,
          status: "fix_proposed"
        };
      } else {
        newFix = {
          findingId,
          explanation: {
            what: `Vulnerable dependency ${finding.package} version ${finding.installedVersion}.`,
            whyDangerous: "Known CVE vulnerability allows potential security compromise.",
            howFixed: `Bumped version to ${finding.fixedVersion || 'latest secure release'}.`,
            rotationRequired: false,
            rotationNote: null
          },
          tier: "auto_branch",
          validation: {
            secretRemoved: true,
            syntaxOk: true,
            notes: ["Dependency version bump verified against registry metadata."]
          },
          diff: {
            filePath: finding.filePath,
            beforeContent: `"${finding.package}": "${finding.installedVersion}"`,
            afterContent: `"${finding.package}": "${finding.fixedVersion || 'patched'}"`
          },
          prNumber: null,
          prUrl: null,
          status: "fix_proposed"
        };
      }
    }

    const updatedFindings = findings.map(f => f.id === findingId ? { ...f, status: 'fix_proposed' } : f);
    const updatedFixes = { ...fixes, [findingId]: newFix };

    const newActivity = {
      id: `act-${Date.now()}`,
      timestamp: new Date().toISOString(),
      type: "fix_proposed",
      repoId: finding.repoId,
      repoName: finding.repoId,
      title: "Remediation patch proposed",
      description: `Generated validated fix for ${finding.ruleId} in ${finding.filePath}.`
    };

    const updatedActivities = [newActivity, ...activities];

    setState(prev => ({
      ...prev,
      findings: updatedFindings,
      fixes: updatedFixes,
      activities: updatedActivities
    }));

    repoGuardService.saveFindings(updatedFindings);
    repoGuardService.saveFixes(updatedFixes);
    repoGuardService.saveActivities(updatedActivities);

    return newFix;
  }, [findings, fixes, activities]);

  // Open PR for a fix
  const openPullRequest = useCallback(async (findingId) => {
    const finding = findings.find(f => f.id === findingId);
    if (!finding) throw new Error("Finding not found");

    await new Promise(r => setTimeout(r, 900));

    const prNumber = Math.floor(Math.random() * 80) + 20;
    const prUrl = `https://github.com/repoguard-org/${finding.repoId}/pull/${prNumber}`;

    const currentFix = fixes[findingId] || {};
    const updatedFix = {
      ...currentFix,
      prNumber,
      prUrl,
      status: "pr_opened"
    };

    const updatedFindings = findings.map(f => f.id === findingId ? { ...f, status: 'pr_opened' } : f);
    const updatedFixes = { ...fixes, [findingId]: updatedFix };

    const newActivity = {
      id: `act-${Date.now()}`,
      timestamp: new Date().toISOString(),
      type: "pr_opened",
      repoId: finding.repoId,
      repoName: finding.repoId,
      title: `Pull Request #${prNumber} opened`,
      description: `Opened remediation PR on GitHub for ${finding.title}.`
    };

    const updatedActivities = [newActivity, ...activities];

    setState(prev => ({
      ...prev,
      findings: updatedFindings,
      fixes: updatedFixes,
      activities: updatedActivities
    }));

    repoGuardService.saveFindings(updatedFindings);
    repoGuardService.saveFixes(updatedFixes);
    repoGuardService.saveActivities(updatedActivities);

    return updatedFix;
  }, [findings, fixes, activities]);

  // Mark False Positive
  const markFalsePositive = useCallback((findingId, note = "") => {
    const finding = findings.find(f => f.id === findingId);
    if (!finding) throw new Error("Finding not found");

    const updatedFindings = findings.map(f => f.id === findingId ? {
      ...f,
      status: 'false_positive',
      suppressionNote: note || "Marked as false positive by security reviewer."
    } : f);

    const newActivity = {
      id: `act-${Date.now()}`,
      timestamp: new Date().toISOString(),
      type: "false_positive",
      repoId: finding.repoId,
      repoName: finding.repoId,
      title: "Finding suppressed as False Positive",
      description: `Finding ${finding.ruleId} marked false positive. Excluded from risk penalties.`
    };

    const updatedActivities = [newActivity, ...activities];

    setState(prev => ({
      ...prev,
      findings: updatedFindings,
      activities: updatedActivities
    }));

    repoGuardService.saveFindings(updatedFindings);
    repoGuardService.saveActivities(updatedActivities);
  }, [findings, activities]);

  // Toggle rotation checklist step
  const toggleRotationStep = useCallback((ruleId, stepId) => {
    const targetList = rotation[ruleId] || rotation["generic-api-key"];
    if (!targetList) return;

    const updatedSteps = targetList.steps.map(s => s.id === stepId ? { ...s, completed: !s.completed } : s);
    const updatedRotation = {
      ...rotation,
      [ruleId]: { ...targetList, steps: updatedSteps }
    };

    setState(prev => ({ ...prev, rotation: updatedRotation }));
    repoGuardService.saveRotation(updatedRotation);
  }, [rotation]);

  // Reset to default
  const resetAllData = useCallback(() => {
    const fresh = repoGuardService.resetToDefault();
    setState(fresh);
  }, []);

  const value = {
    repositories: repos,
    findings,
    fixes,
    scans,
    activities,
    rotation,
    metrics,
    addRepository,
    runScan,
    generateFix,
    openPullRequest,
    markFalsePositive,
    toggleRotationStep,
    resetAllData
  };

  return (
    <RepoGuardContext.Provider value={value}>
      {children}
    </RepoGuardContext.Provider>
  );
};

export const useRepoGuard = () => {
  const context = useContext(RepoGuardContext);
  if (!context) {
    throw new Error("useRepoGuard must be used within a RepoGuardProvider");
  }
  return context;
};
