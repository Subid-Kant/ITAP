const API_BASE = 'http://localhost:8000/api/v1';

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) throw new Error(`API Error: ${res.status}`);
  return res.json();
}

export const api = {
  // Targets
  getTargets: () => request('/targets'),
  createTarget: (data) => request('/targets', { method: 'POST', body: JSON.stringify(data) }),
  deleteTarget: (id) => request(`/targets/${id}`, { method: 'DELETE' }),

  // Scanning
  runScan: (data) => request('/scan', { method: 'POST', body: JSON.stringify(data) }),

  // ML
  predict: (domain) => request(`/ml/predict?domain=${encodeURIComponent(domain)}`, { method: 'POST' }),
  detectAnomalies: (threshold = 0.85) => request(`/ml/anomaly-detect?threshold=${threshold}`, { method: 'POST' }),
  severityScore: (params) => {
    const q = new URLSearchParams(params).toString();
    return request(`/ml/severity-score?${q}`, { method: 'POST' });
  },

  // Threats
  getThreats: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/threats?${q}`);
  },
  getThreat: (id) => request(`/threats/${id}`),

  // MITRE
  getMitreMatrix: () => request('/mitre/matrix'),
  getKillChain: (phase) => request(`/threat-intel/kill-chain?current_phase=${encodeURIComponent(phase)}`, { method: 'POST' }),

  // Incidents
  getIncidents: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/incidents?${q}`);
  },
  createIncident: (data) => request('/incidents', { method: 'POST', body: JSON.stringify(data) }),
  updateIncidentStatus: (id, status) => request(`/incidents/${id}/status?new_status=${status}`, { method: 'PUT' }),

  // Playbook
  generatePlaybook: (data) => request('/playbook/generate', { method: 'POST', body: JSON.stringify(data) }),

  // Dashboard
  getDashboardStats: () => request('/dashboard/stats'),
  getThreatTimeline: (days = 30) => request(`/dashboard/threat-timeline?days=${days}`),

  // IOC
  enrichIOC: (indicator, type = 'domain') => request(`/threat-intel/ioc-enrich?indicator=${encodeURIComponent(indicator)}&indicator_type=${type}`, { method: 'POST' }),
};
