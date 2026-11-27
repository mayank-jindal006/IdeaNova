// Uses the Vite proxy in development. Set VITE_COMMERCE_API_BASE_URL to the deployed API URL in production.
const API_BASE_URL = import.meta.env.VITE_COMMERCE_API_BASE_URL || '';
const TOKEN_KEY = 'repoguard_commerce_token';
const USER_KEY = 'repoguard_commerce_user';

async function request(path, { token, ...options } = {}) {
  const response = await fetch(`${API_BASE_URL}/api/v1${path}`, {
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers },
    ...options,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error?.message || 'Request failed. Please try again.');
  return body;
}

export const commerceService = {
  getSession() {
    try { return { token: localStorage.getItem(TOKEN_KEY), user: JSON.parse(localStorage.getItem(USER_KEY) || 'null') }; }
    catch { return { token: null, user: null }; }
  },
  clearSession() { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY); },
  async authenticate(mode, values) {
    const result = await request(`/auth/${mode}`, { method: 'POST', body: JSON.stringify(values) });
    localStorage.setItem(TOKEN_KEY, result.token);
    localStorage.setItem(USER_KEY, JSON.stringify(result.user));
    return result.user;
  },
  listProducts: () => request('/products'),
  createOrder: (items, token) => request('/orders', { method: 'POST', token, body: JSON.stringify({ items }) }),
};
