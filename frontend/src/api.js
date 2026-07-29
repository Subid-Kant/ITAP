// ITAP v2.0 — API Client
// Includes JWT authorization, token refresh interceptor, retry logic, and all endpoints.

const API_BASE = 'http://localhost:8000/api/v1';
const TOKEN_KEY = 'itap_access_token';
const REFRESH_KEY = 'itap_refresh_token';

let isRefreshing = false;
let refreshQueue = [];

async function processRefreshQueue(token) {
  refreshQueue.forEach(cb => cb(token));
  refreshQueue = [];
}

async function refreshAccessToken() {
  const refresh = localStorage.getItem(REFRESH_KEY);
  if (!refresh) throw new Error('No refresh token');
  const res = await fetch(`${API_BASE}/auth/refresh?token=${encodeURIComponent(refresh)}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Refresh failed');
  const data = await res.json();
  localStorage.setItem(TOKEN_KEY, data.access_token);
  return data.access_token;
}

async function request(path, options = {}, retries = 1) {
  const token = localStorage.getItem(TOKEN_KEY);
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  // Handle 401 — try refresh
  if (res.status === 401 && retries > 0) {
    if (!isRefreshing) {
      isRefreshing = true;
      try {
        const newToken = await refreshAccessToken();
        processRefreshQueue(newToken);
      } catch {
        processRefreshQueue(null);
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(REFRESH_KEY);
        window.location.reload();
      } finally {
        isRefreshing = false;
      }
    } else {
      // Wait for ongoing refresh
      await new Promise(resolve => refreshQueue.push(resolve));
    }
    return request(path, options, 0);
  }

  if (!res.ok) {
    const errData = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
    throw Object.assign(new Error(errData.detail || `API Error: ${res.status}`), {
      status: res.status,
      data: errData,
    });
  }

  // Handle empty responses (204 No Content)
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  // ── Authentication ──────────────────────────────────────
  login: (username, password) =>
    request(`/auth/login?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`, { method: 'POST' }),

  refreshToken: (token) =>
    request(`/auth/refresh?token=${encodeURIComponent(token)}`, { method: 'POST' }),

  getMe: () => request('/auth/me'),

  // ── Targets ─────────────────────────────────────────────
  getTargets: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/targets${q ? '?' + q : ''}`);
  },
  createTarget: (data) => request('/targets', { method: 'POST', body: JSON.stringify(data) }),
  getTarget: (id) => request(`/targets/${id}`),
  deleteTarget: (id) => request(`/targets/${id}`, { method: 'DELETE' }),

  // ── OSINT Scanning ──────────────────────────────────────
  runScan: (data) => request('/scan', { method: 'POST', body: JSON.stringify(data) }),
  getScan: (id) => request(`/scan/${id}`),

  // ── AI/ML Engine ────────────────────────────────────────
  predict: (domain) =>
    request(`/ml/predict?domain=${encodeURIComponent(domain)}`, { method: 'POST' }),
  detectAnomalies: (threshold = 0.82) =>
    request(`/ml/anomaly-detect?threshold=${threshold}`, { method: 'POST' }),
  severityScore: (params) => {
    const q = new URLSearchParams(params).toString();
    return request(`/ml/severity-score?${q}`, { method: 'POST' });
  },

  // ── Threats ─────────────────────────────────────────────
  getThreats: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/threats${q ? '?' + q : ''}`);
  },
  getThreat: (id) => request(`/threats/${id}`),
  resolveThreat: (id) => request(`/threats/${id}/resolve`, { method: 'PUT' }),

  // ── MITRE ATT&CK ────────────────────────────────────────
  getMitreMatrix: () => request('/mitre/matrix'),
  getThreatActors: () => request('/mitre/threat-actors'),
  mapToMitre: (description, attackType = '') =>
    request(`/mitre/map?description=${encodeURIComponent(description)}&attack_type=${encodeURIComponent(attackType)}`, { method: 'POST' }),
  getKillChain: (phase) =>
    request(`/threat-intel/kill-chain?current_phase=${encodeURIComponent(phase)}`, { method: 'POST' }),

  // ── IOC ─────────────────────────────────────────────────
  enrichIOC: (indicator, type = 'domain') =>
    request(`/threat-intel/ioc-enrich?indicator=${encodeURIComponent(indicator)}&indicator_type=${type}`, { method: 'POST' }),
  bulkIOC: (indicators) =>
    request('/threat-intel/ioc-bulk', { method: 'POST', body: JSON.stringify(indicators) }),

  // ── Incidents ────────────────────────────────────────────
  getIncidents: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/incidents${q ? '?' + q : ''}`);
  },
  createIncident: (data) =>
    request('/incidents', { method: 'POST', body: JSON.stringify(data) }),
  getIncident: (id) => request(`/incidents/${id}`),
  updateIncidentStatus: (id, status) =>
    request(`/incidents/${id}/status?new_status=${status}`, { method: 'PUT' }),

  // ── Playbook ─────────────────────────────────────────────
  generatePlaybook: (data) =>
    request('/playbook/generate', { method: 'POST', body: JSON.stringify(data) }),

  // ── Dashboard ────────────────────────────────────────────
  getDashboardStats: () => request('/dashboard/stats'),
  getThreatTimeline: (days = 30) => request(`/dashboard/threat-timeline?days=${days}`),
  getAdvancedMetrics: () => request('/dashboard/metrics'),

  // ── Monitoring ───────────────────────────────────────────
  getServerStatus: () => request('/monitoring/server-status'),
  getGlobalThreats: () => request('/monitoring/global-threats'),

  // ── Reports ──────────────────────────────────────────────
  generateReport: (format = 'json', days = 7) =>
    request(`/reports/generate?format=${format}&days=${days}`),
  downloadReport: async (days = 7) => {
    const token = localStorage.getItem(TOKEN_KEY);
    const res = await fetch(`${API_BASE}/reports/generate?format=text&days=${days}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new Error('Report generation failed');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `itap_report_${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  },
};
