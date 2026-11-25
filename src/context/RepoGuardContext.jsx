import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { RepoGuardContext } from './repoGuardContextValue';
import { getOverallMetrics } from '../services/repoGuardService';
import { securityApi } from '../services/securityApi';

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const repoView = (repo) => ({ id: String(repo.id), name: repo.full_name.split('/').at(-1), fullName: repo.full_name, defaultBranch: repo.default_branch, createdAt: repo.created_at, lastScannedAt: repo.last_scanned_at, latestScore: repo.latest_score || null, signals: {} });
const findingView = (f) => ({ id: String(f.id), repoId: String(f.repo_id), type: f.type, ruleId: f.rule_id, title: f.title, description: f.title, severity: f.severity || 'unknown', filePath: f.file_path || 'unknown', line: f.line, secretMasked: f.secret_masked || null, inHistoryOnly: f.in_history_only, confidence: f.confidence, status: f.status, owaspIds: f.owasp_ids || [], asvsIds: f.asvs_ids || [], detectedAt: f.created_at, scanner: f.scanner, package: f.package, ecosystem: f.ecosystem, installedVersion: f.installed_version, affectedVersions: f.affected_versions, fixedVersion: f.fixed_version, advisoryId: f.advisory_id, aliases: f.aliases || [], references: f.references || [], cvssScore: f.cvss_score, apiFinding: { type: f.type, scanner: f.scanner, file: f.file_path, line: f.line, description: f.title, rule_id: f.rule_id, severity: f.severity, package: f.package, ecosystem: f.ecosystem, installed_version: f.installed_version, affected_versions: f.affected_versions, fixed_version: f.fixed_version, advisory_id: f.advisory_id, aliases: f.aliases || [], references: f.references || [], cvss_score: f.cvss_score } });
const scanView = (s) => ({ id: String(s.id), repoId: String(s.repo_id), trigger: s.trigger, commitSha: s.commit_sha || '', status: s.status, startedAt: s.started_at, finishedAt: s.finished_at, findingsCount: s.findings_count || 0, scannerStatus: s.scanner_status || null, error: s.error || null, durationSeconds: s.started_at && s.finished_at ? Math.max(0, Math.round((new Date(s.finished_at) - new Date(s.started_at)) / 1000)) : null });

export const RepoGuardProvider = ({ children }) => {
  const [state, setState] = useState({ repos: [], findings: [], scans: [], fixes: {}, activities: [], rotation: {} });
  const [loading, setLoading] = useState(true); const [apiError, setApiError] = useState(null);
  const [user, setUser] = useState(null); const [authLoading, setAuthLoading] = useState(true);
  const inFlight = useRef(new Set());
  const refresh = useCallback(async () => {
    setLoading(true); setApiError(null);
    try {
      const repos = (await securityApi.listRepositories()).map(repoView);
      const related = await Promise.all(repos.map(async (repo) => ({ findings: (await securityApi.listFindings(repo.id)).map(findingView), scans: (await securityApi.listRepositoryScans(repo.id)).map(scanView) })));
      setState((old) => ({ ...old, repos, findings: related.flatMap((x) => x.findings), scans: related.flatMap((x) => x.scans) }));
    } catch (error) { setApiError(error.message || 'Unable to load persistent security data.'); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { (async () => { try { setUser(await securityApi.me()); await refresh(); } catch { sessionStorage.removeItem('repoguard_access_token'); } finally { setAuthLoading(false); } })(); }, [refresh]);
  const authenticate = useCallback(async (mode, credentials) => { const session = mode === 'register' ? await securityApi.register(credentials) : await securityApi.login(credentials); sessionStorage.setItem('repoguard_access_token', session.access_token); const account = await securityApi.me(); setUser(account); await refresh(); return account; }, [refresh]);
  const logout = useCallback(() => { sessionStorage.removeItem('repoguard_access_token'); setUser(null); setState({ repos: [], findings: [], scans: [], fixes: {}, activities: [], rotation: {} }); }, []);
  const refreshRepo = useCallback(async (id) => {
    const [findings, scans] = await Promise.all([securityApi.listFindings(id), securityApi.listRepositoryScans(id)]);
    setState((old) => ({ ...old, findings: [...old.findings.filter((x) => x.repoId !== String(id)), ...findings.map(findingView)], scans: [...old.scans.filter((x) => x.repoId !== String(id)), ...scans.map(scanView)] }));
  }, []);
  const addRepository = useCallback(async (fullName, defaultBranch = 'main') => {
    const created = repoView(await securityApi.createRepository({ full_name: fullName.trim(), default_branch: defaultBranch.trim() || 'main' }));
    setState((old) => ({ ...old, repos: [created, ...old.repos] })); return created;
  }, []);
  const runScan = useCallback(async (repoId, onStageUpdate) => {
    const key = String(repoId); if (inFlight.current.has(key)) throw new Error('A scan is already running for this repository.'); inFlight.current.add(key);
    try {
      onStageUpdate?.({ stage: 'queued', label: 'Persistent scan queued.', progress: 10 }); const queued = await securityApi.startScan(repoId); let scan;
      for (let i = 0; i < 80; i += 1) { await wait(1000); scan = await securityApi.getScan(queued.scan_id); if (scan.status === 'running') onStageUpdate?.({ stage: 'scanning_secrets', label: 'Canonical Gitleaks and OSV scans are running.', progress: 55 }); if (['done', 'failed'].includes(scan.status)) break; }
      if (!scan || !['done', 'failed'].includes(scan.status)) throw new Error('Scan status refresh timed out. Check scan history for the final result.');
      const result = scanView(scan); await refreshRepo(repoId); await refresh(); if (result.status === 'failed') throw new Error(result.error || 'Repository scan failed.'); onStageUpdate?.({ stage: 'completed', label: 'Persistent scan completed.', progress: 100 }); return result;
    } finally { inFlight.current.delete(key); }
  }, [refresh, refreshRepo]);
  const generateFix = useCallback(async (findingId) => {
    const finding = state.findings.find((x) => x.id === String(findingId)); if (!finding) throw new Error('Finding not found.'); const response = await securityApi.explainFinding(finding.apiFinding); const e = response?.explanation; if (!e || typeof e !== 'object') throw new Error('The guidance service returned an unexpected response.');
    const fix = { findingId: String(findingId), source: 'api', guidanceSource: e.guidance_source, guidanceFailureReason: e.guidance_failure_reason || null, explanation: { what: e.summary, whyDangerous: e.risk_assessment, howFixed: e.remediation, rotationRequired: Boolean(e.requires_rotation), rotationNote: e.developer_summary || null }, validation: null, diff: null, status: 'explanation_generated', generatedAt: new Date().toISOString() };
    setState((old) => ({ ...old, fixes: { ...old.fixes, [findingId]: fix } })); return fix;
  }, [state.findings]);
  const markFalsePositive = useCallback(async (id, note = '') => { const updated = await securityApi.markFalsePositive(id, note); setState((old) => ({ ...old, findings: old.findings.map((x) => x.id === String(id) ? findingView(updated) : x) })); }, []);
  const metrics = useMemo(() => getOverallMetrics(state.repos, state.findings), [state.repos, state.findings]);
  return <RepoGuardContext.Provider value={{ repositories: state.repos, findings: state.findings, scans: state.scans, fixes: state.fixes, activities: state.activities, rotation: state.rotation, metrics, loading, apiError, user, authLoading, authenticate, logout, refresh, addRepository, runScan, generateFix, markFalsePositive, openPullRequest: async () => { throw new Error('A pull request requires a persisted generated patch, which is not available from the guidance endpoint.'); }, resetAllData: refresh }}>{children}</RepoGuardContext.Provider>;
};
