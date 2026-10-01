const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8002';

async function request(path, options = {}) {
  const url = `${API_BASE_URL}/api${path}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...options.headers
    }
  });

  const data = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    const errorMsg = data?.error?.message || `Request failed (${response.status})`;
    const error = new Error(errorMsg);
    error.status = response.status;
    error.code = data?.error?.code;
    error.data = data;
    throw error;
  }
  return data;
}

export const api = {
  // Repositories
  listRepositories: () => request('/repos'),
  getRepository: (repoId) => request(`/repos/${repoId}`),
  createRepository: (fullName) =>
    request('/repos', {
      method: 'POST',
      body: JSON.stringify({ full_name: fullName })
    }),

  // Scans
  createScan: (repoId) =>
    request(`/repos/${repoId}/scan`, {
      method: 'POST'
    }),
  getScan: (scanId) => request(`/scans/${scanId}`),

  // Findings
  getRepositoryFindings: (repoId, filters = {}) => {
    const params = new URLSearchParams();
    if (filters.type) params.set('type', filters.type);
    if (filters.status) params.set('status', filters.status);
    if (filters.severity) params.set('severity', filters.severity);
    const queryString = params.toString();
    return request(`/repos/${repoId}/findings${queryString ? `?${queryString}` : ''}`);
  },
  getFinding: (findingId) => request(`/findings/${findingId}`),

  // Fixes & PR
  generateFix: (findingId) =>
    request(`/findings/${findingId}/fix`, {
      method: 'POST'
    }),
  openPr: (fixId) =>
    request(`/fixes/${fixId}/open-pr`, {
      method: 'POST'
    }),

  // Feedback (False Positive / True Positive)
  submitFeedback: (findingId, { verdict = 'false_positive', note = null } = {}) =>
    request(`/findings/${findingId}/feedback`, {
      method: 'POST',
      body: JSON.stringify({ verdict, note })
    }),

  // Dashboard
  getDashboardSummary: () => request('/dashboard/summary')
};

export default api;