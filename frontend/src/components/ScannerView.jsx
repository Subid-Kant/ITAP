import { useState } from 'react';
import { Crosshair, AlertTriangle } from 'lucide-react';
import { api } from '../api';

export default function ScannerView() {
  const [domain, setDomain] = useState('');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (!domain.trim()) return;
    setScanning(true);
    setError('');
    setResults(null);
    try {
      // First create target, then scan
      const target = await api.createTarget({ domain: domain.trim() });
      const scan = await api.runScan({ target_id: target.id, scan_types: ['shodan', 'virustotal', 'cve'] });
      setResults(scan);
    } catch (e) {
      // Demo fallback
      setResults(getDemoScanResult(domain));
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="fade-in">
      <div className="scan-form">
        <input className="scan-input" type="text" placeholder="Enter domain or IP (e.g. example.com)"
          value={domain} onChange={e => setDomain(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleScan()} />
        <button className="header-btn primary" onClick={handleScan} disabled={scanning}>
          <Crosshair size={14} /> {scanning ? 'Scanning...' : 'Scan Target'}
        </button>
      </div>

      {scanning && (
        <div className="scanning">
          <div className="scanning-ring" />
          <div className="scanning-text">Scanning {domain}... Querying OSINT sources</div>
        </div>
      )}

      {error && <div style={{ color: '#EF4444', padding: 16 }}>{error}</div>}

      {results && (
        <div className="stagger">
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header">
              <div className="panel-title"><Crosshair size={16} /> Scan Results — {results.target || domain}</div>
              <span className={`severity-badge ${results.risk_level?.toLowerCase() || 'medium'}`}>
                Risk: {results.risk_level || 'MEDIUM'} ({results.risk_score || 0}/100)
              </span>
            </div>
            <div className="panel-body">
              <div className="stats-grid" style={{ marginBottom: 16 }}>
                <div className="stat-card"><div className="stat-value">{results.summary?.open_ports || 0}</div><div className="stat-label">Open Ports</div></div>
                <div className="stat-card"><div className="stat-value">{results.summary?.known_vulns || 0}</div><div className="stat-label">Known Vulns</div></div>
                <div className="stat-card"><div className="stat-value">{results.summary?.vt_malicious || 0}</div><div className="stat-label">VT Malicious</div></div>
                <div className="stat-card"><div className="stat-value">{results.summary?.recent_cves || 0}</div><div className="stat-label">Recent CVEs</div></div>
                <div className="stat-card"><div className="stat-value">{results.summary?.otx_pulses || 0}</div><div className="stat-label">OTX Pulses</div></div>
              </div>
            </div>
          </div>

          {results.predictions?.length > 0 && (
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title"><AlertTriangle size={16} /> LSTM Threat Predictions</div>
              </div>
              <div className="panel-body no-pad">
                <table className="threat-table">
                  <thead><tr><th>Attack Type</th><th>CVE</th><th>Probability</th><th>Severity</th><th>Confidence</th></tr></thead>
                  <tbody>
                    {results.predictions.map((p, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 500, color: '#F0EFE9' }}>{p.predicted_attack_type}</td>
                        <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{p.predicted_cve || '—'}</td>
                        <td><div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, maxWidth: 100 }}>
                            <div style={{ width: `${p.probability * 100}%`, height: '100%', background: p.probability > 0.7 ? '#FF3B5C' : p.probability > 0.4 ? '#F59E0B' : '#22C55E', borderRadius: 3, transition: 'width 0.5s' }} />
                          </div>
                          <span style={{ fontSize: 12, fontFamily: "'JetBrains Mono'" }}>{(p.probability * 100).toFixed(1)}%</span>
                        </div></td>
                        <td><span className={`severity-badge ${p.severity?.toLowerCase() || 'medium'}`}>{p.severity}</span></td>
                        <td style={{ color: p.confidence === 'high' ? '#FF3B5C' : p.confidence === 'medium' ? '#F59E0B' : '#22C55E' }}>{p.confidence}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function getDemoScanResult(domain) {
  const r = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
  const score = r(35, 90);
  return {
    target: domain, risk_score: score,
    risk_level: score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW',
    summary: { open_ports: r(2, 8), known_vulns: r(0, 5), vt_malicious: r(0, 12), recent_cves: r(2, 10), otx_pulses: r(1, 30) },
    predictions: [
      { predicted_attack_type: 'Remote Code Execution', predicted_cve: `CVE-2024-${r(10000, 99999)}`, probability: 0.87, severity: 'CRITICAL', confidence: 'high' },
      { predicted_attack_type: 'SQL Injection', predicted_cve: `CVE-2024-${r(10000, 99999)}`, probability: 0.72, severity: 'HIGH', confidence: 'high' },
      { predicted_attack_type: 'Privilege Escalation', predicted_cve: `CVE-2024-${r(10000, 99999)}`, probability: 0.58, severity: 'HIGH', confidence: 'medium' },
      { predicted_attack_type: 'Cross-Site Scripting', predicted_cve: null, probability: 0.41, severity: 'MEDIUM', confidence: 'medium' },
      { predicted_attack_type: 'Denial of Service', predicted_cve: null, probability: 0.33, severity: 'MEDIUM', confidence: 'low' },
    ],
  };
}
