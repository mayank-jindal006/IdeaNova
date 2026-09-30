const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8002';

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}/api${path}`, {
    ...options,
    headers: {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...options.headers
    }
  });

  const data = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    throw new Error(data?.error?.message || `Request failed (${response.status})`);
  }
  return data;
}

export const api = {
  listRepositories: () => request('/repos'),
  getRepositoryFindings: (repoId) => request(`/repos/${repoId}/findings`),
  getDashboardSummary: () => request('/dashboard/summary'),
  createScan: (repoId) => request(`/repos/${repoId}/scan`, { method: 'POST' }),
  getScan: (scanId) => request(`/scans/${scanId}`)
};