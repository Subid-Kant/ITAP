import { Bell } from 'lucide-react';

export default function IncidentsView({ stats }) {
  const incidents = stats?.recent_incidents || [];
  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title"><Bell size={16} /> Incidents ({incidents.length})</div>
        </div>
        <div className="panel-body no-pad">
          <table className="threat-table">
            <thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Detected</th></tr></thead>
            <tbody>
              {incidents.map((inc, i) => (
                <tr key={i}>
                  <td style={{ color: '#F0EFE9', fontWeight: 500 }}>{inc.title}</td>
                  <td><span className={`severity-badge ${inc.severity}`}>{inc.severity}</span></td>
                  <td><span className={`status-badge ${inc.status}`}>● {inc.status}</span></td>
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 11 }}>
                    {inc.detected_at ? new Date(inc.detected_at).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {incidents.length === 0 && (
            <div className="empty-state"><Bell size={40} /><h3>No incidents</h3><p>Incidents are auto-created from critical threats</p></div>
          )}
        </div>
      </div>
    </div>
  );
}
