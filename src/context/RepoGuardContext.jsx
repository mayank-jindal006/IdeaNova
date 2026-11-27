import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { RepoGuardContext } from './repoGuardContextValue';
import { getOverallMetrics } from '../services/repoGuardService';
import { securityApi } from '../services/securityApi';
import { scanDuration, scanOutcome } from '../services/scanPresentation';

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const repoView = (repo) => ({
  id: String(repo.id),
  name: repo.full_name.split('/').at(-1),
  fullName: repo.full_name,
  sourceType: repo.source_type || 'github',
  defaultBranch: repo.default_branch,
  createdAt: repo.created_at,
  lastScannedAt: repo.last_scanned_at,
  latestScore: repo.latest_score || null,
  signals: {}
});

const findingView = (finding) => ({
  id: String(finding.id),
  repoId: String(finding.repo_id),
  type: finding.type,
  ruleId: finding.rule_id,
  title: finding.title,
  description: finding.description || finding.title,
  severity: finding.severity || 'unknown',
  filePath: finding.file_path || 'unknown',
  line: finding.line,
  secretMasked: finding.secret_masked || null,
  inHistoryOnly: finding.in_history_only,
  confidence: finding.confidence,
  status: finding.status,
  owaspIds: finding.owasp_ids || [],
  asvsIds: finding.asvs_ids || [],
  detectedAt: finding.created_at,
  scanner: finding.scanner,
  package: finding.package,
  ecosystem: finding.ecosystem,
  installedVersion: finding.installed_version,
  affectedVersions: finding.affected_versions,
  fixedVersion: finding.fixed_version,
  advisoryId: finding.advisory_id,
  aliases: finding.aliases || [],
  references: finding.references || [],
  cvssScore: finding.cvss_score,
  apiFinding: {
    type: finding.type,
    scanner: finding.scanner,
    file: finding.file_path,
    line: finding.line,
    description: finding.title,
    rule_id: finding.rule_id,
    severity: finding.severity,
    package: finding.package,
    ecosystem: finding.ecosystem,
    installed_version: finding.installed_version,
    affected_versions: finding.affected_versions,
    fixed_version: finding.fixed_version,
    advisory_id: finding.advisory_id,
    aliases: finding.aliases || [],
    references: finding.references || [],
    cvss_score: finding.cvss_score
  }
});

const scanView = (scan) => ({
  id: String(scan.id),
  repoId: String(scan.repo_id),
  trigger: scan.trigger,
  commitSha: scan.commit_sha || '',
  status: scan.status,
  startedAt: scan.started_at,
  finishedAt: scan.finished_at,
  findingsCount: scan.findings_count || 0,
  scannerStatus: scan.scanner_status || null,
  error: scan.error || null,
  durationSeconds: scanDuration(scan.started_at, scan.finished_at)
});

const fixView = (fix, reviews = []) => ({
  ...fix,
  id: String(fix.id),
  findingId: String(fix.finding_id),
  source: 'api',
  targetFile: fix.target_file,
  riskLevel: fix.risk_level,
  generatedAt: fix.created_at,
  prUrl: fix.pr_url || null,
  prNumber: fix.pr_number || null,
  diff: fix.patch ? { patch: fix.patch, filePath: fix.target_file } : null,
  explanation: {
    what: fix.explanation?.what || '',
    whyDangerous: fix.explanation?.why_dangerous || '',
    howFixed: fix.explanation?.how_fixed || '',
    rotationRequired: Boolean(fix.explanation?.rotation_required),
    rotationNote: fix.explanation?.rotation_note || null
  },
  validation: fix.validation ? {
    ...fix.validation,
    secretRemoved: fix.validation.secret_removed,
    syntaxOk: fix.validation.syntax_ok
  } : null,
  reviews
});

const auditView = (event) => ({
  id: String(event.id),
  timestamp: event.created_at,
  title: event.action.replaceAll('.', ' ').replaceAll('_', ' '),
  description: [
    event.actor_email,
    event.repo_id ? `Repository ${event.repo_id}` : null,
    event.details?.status ? `Status: ${event.details.status}` : null,
    event.details?.decision ? `Decision: ${event.details.decision}` : null,
    event.details?.pr_number ? `Pull request #${event.details.pr_number}` : null
  ].filter(Boolean).join(' · ')
});

const emptyState = () => ({ repos: [], findings: [], scans: [], fixes: {}, activities: [], rotation: {} });

export const RepoGuardProvider = ({ children }) => {
  const [state, setState] = useState(emptyState);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState(null);
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const inFlight = useRef(new Set());
  const sessionVersion = useRef(0);

  const refreshActivity = useCallback(async () => {
    const activities = (await securityApi.listAuditLogs()).map(auditView);
    setState((old) => ({ ...old, activities }));
  }, []);

  const refresh = useCallback(async () => {
    const version = sessionVersion.current;
    setLoading(true);
    setApiError(null);
    try {
      const repos = (await securityApi.listRepositories()).map(repoView);
      const [related, activities] = await Promise.all([
        Promise.all(repos.map(async (repo) => ({
          findings: (await securityApi.listFindings(repo.id)).map(findingView),
          scans: (await securityApi.listRepositoryScans(repo.id)).map(scanView)
        }))),
        securityApi.listAuditLogs()
      ]);
      if (version !== sessionVersion.current) return;
      setState((old) => ({
        ...old,
        repos,
        findings: related.flatMap((item) => item.findings),
        scans: related.flatMap((item) => item.scans),
        activities: activities.map(auditView)
      }));
    } catch (error) {
      setApiError(error.message || 'Unable to load persistent security data.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!sessionStorage.getItem('repoguard_access_token')) {
      setAuthLoading(false);
      return;
    }
    (async () => {
      try {
        setUser(await securityApi.me());
        await refresh();
      } catch {
        sessionStorage.removeItem('repoguard_access_token');
      } finally {
        setAuthLoading(false);
      }
    })();
  }, [refresh]);

  const authenticate = useCallback(async (mode, credentials) => {
    const session = mode === 'register'
      ? await securityApi.register(credentials)
      : await securityApi.login(credentials);
    sessionStorage.setItem('repoguard_access_token', session.access_token);
    const account = await securityApi.me();
    setUser(account);
    await refresh();
    // Authentication flow completed; clear loading flag
    setAuthLoading(false);
    return account;
  }, [refresh]);

  const logout = useCallback(() => {
    sessionVersion.current += 1;
    sessionStorage.removeItem('repoguard_access_token');
    setUser(null);
    setState(emptyState());
  }, []);

  useEffect(() => {
    window.addEventListener('repoguard:session-expired', logout);
    return () => window.removeEventListener('repoguard:session-expired', logout);
  }, [logout]);

  const refreshRepo = useCallback(async (id) => {
    const version = sessionVersion.current;
    const [findings, scans] = await Promise.all([
      securityApi.listFindings(id),
      securityApi.listRepositoryScans(id)
    ]);
    if (version !== sessionVersion.current) return;
    setState((old) => ({
      ...old,
      findings: [
        ...old.findings.filter((finding) => finding.repoId !== String(id)),
        ...findings.map(findingView)
      ],
      scans: [
        ...old.scans.filter((scan) => scan.repoId !== String(id)),
        ...scans.map(scanView)
      ]
    }));
  }, []);

  const addRepository = useCallback(async (fullName, defaultBranch = 'main', local = false) => {
    const created = repoView(await securityApi.createRepository(local
      ? { local_path: fullName.trim() }
      : { full_name: fullName.trim(), default_branch: defaultBranch.trim() || 'main' }));
    setState((old) => ({ ...old, repos: [created, ...old.repos] }));
    return created;
  }, []);

  const runScan = useCallback(async (repoId, onStageUpdate) => {
    const key = String(repoId);
    if (inFlight.current.has(key)) throw new Error('A scan is already running for this repository.');
    inFlight.current.add(key);
    try {
      onStageUpdate?.({ stage: 'queued', label: 'Persistent scan queued.', progress: 10 });
      const queued = await securityApi.startScan(repoId);
      let scan;
      for (let attempt = 0; attempt < 80; attempt += 1) {
        await wait(1000);
        scan = await securityApi.getScan(queued.scan_id);
        if (scan.status === 'running') {
          onStageUpdate?.({ stage: 'scanning_secrets', label: 'Canonical Gitleaks and OSV scans are running.', progress: 55 });
        }
        if (['done', 'failed'].includes(scan.status)) break;
      }
      if (!scan || !['done', 'failed'].includes(scan.status)) {
        throw new Error('Scan status refresh timed out. Check scan history for the final result.');
      }
      const result = scanView(scan);
      await refreshRepo(repoId);
      await refresh();
      if (result.status === 'failed') throw new Error(result.error || 'Repository scan failed.');
      const outcome = scanOutcome(result.status, result.scannerStatus);
      onStageUpdate?.({ stage: 'completed', label: outcome === 'success' ? 'Both scanners completed.' : 'Scan completed with partial or unavailable scanner results.', progress: 100 });
      return result;
    } finally {
      inFlight.current.delete(key);
    }
  }, [refresh, refreshRepo]);

  const loadFix = useCallback(async (findingId) => {
    const detail = await securityApi.getFinding(findingId);
    if (!detail.fix) {
      setState((old) => {
        const fixes = { ...old.fixes };
        delete fixes[findingId];
        return { ...old, fixes };
      });
      return null;
    }
    const detailWithReviews = await securityApi.getFix(detail.fix.id);
    const fix = fixView(detailWithReviews.fix, detailWithReviews.reviews);
    setState((old) => ({ ...old, fixes: { ...old.fixes, [findingId]: fix } }));
    return fix;
  }, []);

  const generateFix = useCallback(async (findingId) => {
    const finding = state.findings.find((item) => item.id === String(findingId));
    if (!finding) throw new Error('Finding not found.');
    const fix = fixView(await securityApi.createFix(findingId));
    setState((old) => ({ ...old, fixes: { ...old.fixes, [findingId]: fix } }));
    await refreshActivity();
    return fix;
  }, [refreshActivity, state.findings]);

  const reviewFix = useCallback(async (findingId, decision, note = '') => {
    const current = state.fixes[findingId];
    if (!current) throw new Error('Load or generate a persisted fix before reviewing it.');
    const response = await securityApi.reviewFix(current.id, decision, note);
    const reviews = [...(current.reviews || []), response.review];
    const fix = fixView(response.fix, reviews);
    setState((old) => ({ ...old, fixes: { ...old.fixes, [findingId]: fix } }));
    await refreshActivity();
    return fix;
  }, [refreshActivity, state.fixes]);

  const validateFix = useCallback(async (findingId) => {
    const current = state.fixes[findingId];
    if (!current) throw new Error('Load or generate a persisted fix before validating it.');
    const response = await securityApi.validateFix(current.id);
    const fix = fixView(response.fix, current.reviews);
    setState((old) => ({ ...old, fixes: { ...old.fixes, [findingId]: fix } }));
    await refreshActivity();
    return fix;
  }, [refreshActivity, state.fixes]);

  const openPullRequest = useCallback(async (findingId) => {
    const current = state.fixes[findingId];
    if (!current) throw new Error('Load or generate a persisted fix before opening a pull request.');
    const response = await securityApi.openFixPullRequest(current.id);
    const detail = await securityApi.getFix(current.id);
    const fix = fixView(detail.fix, detail.reviews);
    setState((old) => ({ ...old, fixes: { ...old.fixes, [findingId]: fix } }));
    await refreshActivity();
    return response;
  }, [refreshActivity, state.fixes]);

  const markFalsePositive = useCallback(async (id, note = '') => {
    const updated = await securityApi.markFalsePositive(id, note);
    setState((old) => ({
      ...old,
      findings: old.findings.map((item) => item.id === String(id) ? findingView(updated) : item)
    }));
    await refreshActivity();
  }, [refreshActivity]);

  const metrics = useMemo(
    () => getOverallMetrics(state.repos, state.findings),
    [state.repos, state.findings]
  );

  return (
    <RepoGuardContext.Provider value={{
      repositories: state.repos,
      findings: state.findings,
      scans: state.scans,
      fixes: state.fixes,
      activities: state.activities,
      rotation: state.rotation,
      metrics,
      loading,
      apiError,
      user,
      authLoading,
      authenticate,
      logout,
      refresh,
      addRepository,
      runScan,
      loadFix,
      generateFix,
      reviewFix,
      validateFix,
      markFalsePositive,
      openPullRequest,
      resetAllData: refresh
    }}>
      {children}
    </RepoGuardContext.Provider>
  );
};
