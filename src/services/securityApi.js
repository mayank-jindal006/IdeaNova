const API_BASE_URL = import.meta.env?.VITE_API_BASE_URL || '';

async function request(path, options = {}, binary = false) {
  const token = sessionStorage.getItem('repoguard_access_token');
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(options.headers || {})
      }
    });
  } catch {
    throw new Error('Unable to reach the RepoGuard security service.');
  }
  if (response.ok && binary) {
    if (response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/zip') {
      throw new Error('The export service returned an invalid archive.');
    }
    const archive = await response.blob();
    if (!archive.size || archive.size > 512 * 1024) throw new Error('The export archive is empty or too large.');
    return archive;
  }
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && token && path !== '/api/auth/login' && path !== '/api/auth/register' && sessionStorage.getItem('repoguard_access_token') === token) {
      sessionStorage.removeItem('repoguard_access_token');
      window.dispatchEvent(new Event('repoguard:session-expired'));
    }
    throw new Error(body?.error?.message || `Security service request failed (${response.status}).`);
  }
  return body;
}

export const securityApi = {
  register: (payload) => request('/api/auth/register', { method: 'POST', body: JSON.stringify(payload) }),
  login: (payload) => request('/api/auth/login', { method: 'POST', body: JSON.stringify(payload) }),
  me: () => request('/api/auth/me'),
  listRepositories: () => request('/api/repos'),
  getRepository: (id) => request(`/api/repos/${id}`),
  createRepository: (payload) => request('/api/repos', { method: 'POST', body: JSON.stringify(payload) }),
  listRepositoryScans: (id) => request(`/api/repos/${id}/scans`),
  startScan: (id) => request(`/api/repos/${id}/scan`, { method: 'POST' }),
  getScan: (id) => request(`/api/scans/${id}`),
  getScanFindings: (id) => request(`/api/scans/${id}/findings`),
  listFindings: (id) => request(`/api/repos/${id}/findings`),
  getFinding: (id) => request(`/api/findings/${id}`),
  explainPersistedFinding: (id) => request(`/api/findings/${id}/explain`, { method: 'POST' }),
  createFix: (id) => request(`/api/findings/${id}/fix`, { method: 'POST' }),
  getFix: (id) => request(`/api/fixes/${id}`),
  reviewFix: (id, decision, note = '') => request(`/api/fixes/${id}/review`, {
    method: 'POST',
    body: JSON.stringify({ decision, note })
  }),
  validateFix: (id) => request(`/api/fixes/${id}/validate`, { method: 'POST' }),
  patchExportStatus: (id) => request(`/api/fixes/${id}/export-status`),
  exportPatch: (id) => request(`/api/fixes/${id}/export`, { method: 'POST' }, true),
  openFixPullRequest: (id) => request(`/api/fixes/${id}/open-pr`, { method: 'POST' }),
  pullRequestEligibility: (id) => request(`/api/fixes/${id}/pr-eligibility`),
  listAuditLogs: () => request('/api/audit-logs'),
  markFalsePositive: (id, note) => request(`/api/findings/${id}/feedback`, {
    method: 'POST',
    body: JSON.stringify({ verdict: 'false_positive', note })
  }),
  dashboard: () => request('/api/dashboard/summary'),
  explainFinding: (finding) => request('/api/findings/explain', {
    method: 'POST',
    body: JSON.stringify({ finding, source_context: '' })
  }),
  scanCompatibility: (repoId) => request('/api/repositories/scan', {
    method: 'POST',
    body: JSON.stringify({ repo_id: Number(repoId) })
  })
};
