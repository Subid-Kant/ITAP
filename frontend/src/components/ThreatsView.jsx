import { AlertTriangle } from 'lucide-react';

export default function ThreatsView({ stats }) {
  const threats = stats?.recent_threats || [];
  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title"><AlertTriangle size={16} /> Active Threats ({threats.length})</div>
        </div>
        <div className="panel-body no-pad">
          <table className="threat-table">
            <thead><tr><th>Threat</th><th>Severity</th><th>Score</th><th>MITRE Tactic</th><th>Origin</th><th>Detected</th></tr></thead>
            <tbody>
              {threats.map((t, i) => (
                <tr key={i}>
                  <td style={{ color: '#F0EFE9', fontWeight: 500, maxWidth: 250 }}>{t.title}</td>
                  <td><span className={`severity-badge ${t.severity}`}>{t.severity}</span></td>
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 13, fontWeight: 600 }}>{t.severity_score}</td>
                  <td>{t.mitre_tactic || '—'}</td>
                  <td>{t.source_country ? `📍 ${t.source_country}` : '—'}</td>
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, whiteSpace: 'nowrap' }}>
                    {t.detected_at ? new Date(t.detected_at).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {threats.length === 0 && (
            <div className="empty-state"><AlertTriangle size={40} /><h3>No threats detected</h3><p>Run an OSINT scan to discover threats</p></div>
          )}
        </div>
      </div>
    </div>
  );
}
