const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      headers: { 'Content-Type': 'application/json', ...(sessionStorage.getItem('repoguard_access_token') ? { Authorization: `Bearer ${sessionStorage.getItem('repoguard_access_token')}` } : {}), ...(options.headers || {}) },
      ...options
    });
  } catch {
    throw new Error('Unable to reach the RepoGuard security service.');
  }
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.error?.message || `Security service request failed (${response.status}).`);
  return body;
}

export const securityApi = {
  register: (payload) => request('/api/auth/register', { method: 'POST', body: JSON.stringify(payload) }),
  login: (payload) => request('/api/auth/login', { method: 'POST', body: JSON.stringify(payload) }),
  me: () => request('/api/auth/me'),
  logout: () => request('/api/auth/logout', { method: 'POST' }),
  listRepositories: () => request('/api/repos'),
  getRepository: (id) => request(`/api/repos/${id}`),
  createRepository: (payload) => request('/api/repos', { method: 'POST', body: JSON.stringify(payload) }),
  listRepositoryScans: (id) => request(`/api/repos/${id}/scans`),
  startScan: (id) => request(`/api/repos/${id}/scan`, { method: 'POST' }),
  getScan: (id) => request(`/api/scans/${id}`),
  getScanFindings: (id) => request(`/api/scans/${id}/findings`),
  listFindings: (id) => request(`/api/repos/${id}/findings`),
  getFinding: (id) => request(`/api/findings/${id}`),
  markFalsePositive: (id, note) => request(`/api/findings/${id}/feedback`, { method: 'POST', body: JSON.stringify({ verdict: 'false_positive', note }) }),
  dashboard: () => request('/api/dashboard/summary'),
  explainFinding: (finding) => request('/api/findings/explain', { method: 'POST', body: JSON.stringify({ finding, source_context: '' }) })
  ,scanCompatibility: (repoId) => request('/api/repositories/scan', { method: 'POST', body: JSON.stringify({ repo_id: Number(repoId) }) })
};
