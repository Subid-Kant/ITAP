import { useState, useEffect } from 'react';
import { Brain, Eye, Cpu, Database } from 'lucide-react';
import { api } from '../api';
import { useAuth } from '../hooks/useAuth';

export default function PredictionsView() {
  const { user } = useAuth();
  const isViewer = user?.role === 'viewer';
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [mlStatus, setMlStatus] = useState(null);

  useEffect(() => {
    // We haven't added this to api.js yet, so use fetch directly for now or add it to api.js
    fetch('http://localhost:8000/api/v1/ml/status')
      .then(res => res.json())
      .then(setMlStatus)
      .catch(console.error);
  }, []);

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
      
      {/* AI Model Status Banner */}
      <div style={{ marginBottom: 20, padding: '12px 20px', background: mlStatus?.status === 'online' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(245, 158, 11, 0.1)', border: `1px solid ${mlStatus?.status === 'online' ? '#22C55E' : '#F59E0B'}`, borderRadius: 8, display: 'flex', alignItems: 'center', gap: 12 }}>
        {mlStatus?.status === 'online' ? <Cpu size={20} color="#22C55E" /> : <Database size={20} color="#F59E0B" />}
        <div>
          <div style={{ color: '#F0EFE9', fontWeight: 600, fontSize: 14 }}>Active Engine: {mlStatus?.engine || 'Checking...'}</div>
          <div style={{ color: '#8892B0', fontSize: 12 }}>{mlStatus?.message || 'Connecting to ML engine...'}</div>
        </div>
      </div>

      <div className="scan-form">
        <input className="scan-input" placeholder="Enter domain or attack signature for analysis..." value={domain} onChange={e => setDomain(e.target.value)} disabled={loading || isViewer} onKeyDown={e => e.key === 'Enter' && predict()} />
        <button className="header-btn primary" onClick={predict} disabled={loading || isViewer} title={isViewer ? "Viewer mode restricted" : ""}><Brain size={14} /> {loading ? 'Analyzing...' : 'Predict Threats'}</button>
      </div>
      {loading && <div className="scanning"><div className="scanning-ring" /><div className="scanning-text">{mlStatus?.engine || 'ML Engine'} processing...</div></div>}
      {results && (
        <div className="panel fade-in">
          <div className="panel-header">
            <div className="panel-title"><Brain size={16} /> LLM Predictions for {results.domain} (Risk: {results.risk_score})</div>
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
  const { user } = useAuth();
  const isViewer = user?.role === 'viewer';
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
      <button className="header-btn primary" onClick={detect} disabled={loading || isViewer} title={isViewer ? "Viewer mode restricted" : ""} style={{ marginBottom: 20 }}>
        <Eye size={14} /> {loading ? 'Detecting...' : 'Run Anomaly Detection'}
      </button>
      {loading && <div className="scanning"><div className="scanning-ring" /><div className="scanning-text">Llama 3 8B analyzing traffic patterns...</div></div>}
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

