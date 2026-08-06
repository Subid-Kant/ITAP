import { useState } from 'react';
import { Crosshair, AlertTriangle, RotateCcw } from 'lucide-react';
import { api } from '../api';
import { useAuth } from '../hooks/useAuth';

export default function ScannerView({ onScanComplete, scannerState, setScannerState }) {
  const { user } = useAuth();
  const isViewer = user?.role === 'viewer';
  const [scanning, setScanning] = useState(false);

  // Use lifted state (props) so results survive view-switching.
  // Fall back to local state if the component is used standalone.
  const domain = scannerState?.domain ?? '';
  const results = scannerState?.results ?? null;
  const error = scannerState?.error ?? '';

  const setDomain = (val) => setScannerState(s => ({ ...s, domain: val }));
  const setResults = (val) => setScannerState(s => ({ ...s, results: val }));
  const setError = (val) => setScannerState(s => ({ ...s, error: val }));

  const handleScan = async () => {
    if (!domain.trim() || isViewer) return;
    setScanning(true);
    setError('');
    setResults(null);
    try {
      // Create target, then run full OSINT scan
      const target = await api.createTarget({ domain: domain.trim() });
      const scan = await api.runScan({ target_id: target.id, scan_types: ['shodan', 'virustotal', 'cve'] });
      setResults(scan);
      // Notify App.jsx to refresh the dashboard so new threats appear immediately
      if (onScanComplete) onScanComplete();
    } catch (e) {
      setError(e.message || 'Scan failed to complete. Please ensure backend services are running and the target is reachable.');
    } finally {
      setScanning(false);
    }
  };

  const handleClear = () => {
    setScannerState({ domain: '', results: null, error: '' });
  };

  return (
    <div className="fade-in">
      <div className="scan-form">
        <input className="scan-input" type="text" placeholder="Enter domain or IP (e.g. example.com)"
          value={domain} onChange={e => setDomain(e.target.value)}
          disabled={scanning || isViewer}
          onKeyDown={e => e.key === 'Enter' && handleScan()} />
        <button className="header-btn primary" onClick={handleScan} disabled={scanning || isViewer} title={isViewer ? "Viewer mode restricted" : ""}>
          <Crosshair size={14} /> {scanning ? 'Scanning...' : 'Scan Target'}
        </button>
        {results && (
          <button
            className="header-btn"
            onClick={handleClear}
            title="Clear results and scan a new domain"
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <RotateCcw size={14} /> Clear
          </button>
        )}
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
              {results.threats_created?.length > 0 && (
                <div style={{ color: '#22C55E', fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
                  ✓ {results.threats_created.length} threat{results.threats_created.length !== 1 ? 's' : ''} added to SOC Dashboard
                </div>
              )}
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
