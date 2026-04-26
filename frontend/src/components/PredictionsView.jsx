import { useState } from 'react';
import { Brain, Eye } from 'lucide-react';
import { api } from '../api';

export default function PredictionsView() {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const predict = async () => {
    if (!domain) return;
    setLoading(true);
    try {
      const data = await api.predict(domain);
      setResults(data);
    } catch (e) {
      console.error("Prediction failed", e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fade-in">
      <div className="scan-form">
        <input className="scan-input" placeholder="Enter domain for LSTM prediction..." value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === 'Enter' && predict()} />
        <button className="header-btn primary" onClick={predict} disabled={loading}><Brain size={14} /> {loading ? 'Predicting...' : 'Predict Threats'}</button>
      </div>
      {loading && <div className="scanning"><div className="scanning-ring" /><div className="scanning-text">LSTM model processing...</div></div>}
      {results && (
        <div className="panel fade-in">
          <div className="panel-header">
            <div className="panel-title"><Brain size={16} /> Predictions for {results.domain} (Risk: {results.risk_score})</div>
          </div>
          <div className="panel-body no-pad">
            <table className="threat-table">
              <thead><tr><th>Attack Type</th><th>CVE</th><th>Probability</th><th>Window</th><th>Confidence</th></tr></thead>
              <tbody>{(results.predictions || []).map((p, i) => (
                <tr key={i}>
                  <td style={{ fontWeight: 500, color: '#F0EFE9' }}>{p.predicted_attack_type}</td>
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 12 }}>{p.predicted_cve || '—'}</td>
                  <td><div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, maxWidth: 100 }}>
                      <div style={{ width: `${p.probability * 100}%`, height: '100%', borderRadius: 3, background: p.probability > 0.7 ? '#FF3B5C' : p.probability > 0.4 ? '#F59E0B' : '#22C55E' }} />
                    </div>
                    <span style={{ fontSize: 12, fontFamily: "'JetBrains Mono'" }}>{(p.probability * 100).toFixed(1)}%</span>
                  </div></td>
                  <td>{p.time_window_hours}h</td>
                  <td style={{ color: p.confidence === 'high' ? '#FF3B5C' : '#F59E0B', fontWeight: 600 }}>{p.confidence}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export function AnomaliesView() {
  const [loading, setLoading] = useState(false);
  const [anomalies, setAnomalies] = useState(null);

  const detect = async () => {
    setLoading(true);
    try {
      const data = await api.detectAnomalies();
      setAnomalies(data);
    } catch (e) {
      console.error("Anomaly detection failed", e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fade-in">
      <button className="header-btn primary" onClick={detect} disabled={loading} style={{ marginBottom: 20 }}>
        <Eye size={14} /> {loading ? 'Detecting...' : 'Run Anomaly Detection'}
      </button>
      {loading && <div className="scanning"><div className="scanning-ring" /><div className="scanning-text">Autoencoder analysing traffic patterns...</div></div>}
      {anomalies && (
        <div className="panel fade-in">
          <div className="panel-header">
            <div className="panel-title"><Eye size={16} /> {anomalies.anomalies_detected} Anomalies Detected</div>
          </div>
          <div className="panel-body no-pad">
            <table className="threat-table">
              <thead><tr><th>Source IP</th><th>Score</th><th>Classification</th><th>Threat DNA</th></tr></thead>
              <tbody>{(anomalies.anomalies || []).slice(0, 10).map((a, i) => (
                <tr key={i}>
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 12 }}>{a.source_ip}</td>
                  <td><span className={`severity-badge ${a.anomaly_score > 0.9 ? 'critical' : 'high'}`}>{(a.anomaly_score * 100).toFixed(1)}%</span></td>
                  <td style={{ fontWeight: 500, color: '#F0EFE9' }}>{a.classification}</td>
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: '#8B5CF6' }}>{a.pattern_fingerprint?.slice(0, 16) || '—'}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export function AnomaliesView() {
  // ... (rest of the component stays the same)
}
