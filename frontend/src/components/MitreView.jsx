import { Grid3X3 } from 'lucide-react';

const MITRE_TACTICS = [
  { name: 'Reconnaissance', id: 'TA0043', color: '#378ADD' },
  { name: 'Resource Dev', id: 'TA0042', color: '#6366F1' },
  { name: 'Initial Access', id: 'TA0001', color: '#8B5CF6' },
  { name: 'Execution', id: 'TA0002', color: '#A855F7' },
  { name: 'Persistence', id: 'TA0003', color: '#EC4899' },
  { name: 'Priv Escalation', id: 'TA0004', color: '#F43F5E' },
  { name: 'Defense Evasion', id: 'TA0005', color: '#EF4444' },
  { name: 'Credential Access', id: 'TA0006', color: '#F97316' },
  { name: 'Discovery', id: 'TA0007', color: '#F59E0B' },
  { name: 'Lateral Movement', id: 'TA0008', color: '#EAB308' },
  { name: 'Collection', id: 'TA0009', color: '#84CC16' },
  { name: 'C2', id: 'TA0011', color: '#22C55E' },
  { name: 'Exfiltration', id: 'TA0010', color: '#06D6A0' },
  { name: 'Impact', id: 'TA0040', color: '#FF3B5C' },
];

export default function MitreView({ stats }) {
  const coverage = stats?.mitre_attack_coverage || [];
  const tacticCounts = {};
  coverage.forEach(c => { tacticCounts[c.tactic] = (tacticCounts[c.tactic] || 0) + 1; });

  return (
    <div className="fade-in">
      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <div className="panel-title"><Grid3X3 size={16} /> MITRE ATT&CK Matrix — Detection Coverage</div>
        </div>
        <div className="mitre-matrix">
          {MITRE_TACTICS.map(t => (
            <div key={t.id} className={`mitre-tactic ${tacticCounts[t.name] ? 'active' : ''}`}
              style={tacticCounts[t.name] ? { borderColor: t.color, boxShadow: `0 0 12px ${t.color}33` } : {}}>
              <div className="mitre-tactic-count" style={tacticCounts[t.name] ? { color: t.color } : {}}>
                {tacticCounts[t.name] || 0}
              </div>
              <div className="mitre-tactic-name">{t.name}</div>
              <div style={{ fontSize: 9, color: '#6B7280', marginTop: 2 }}>{t.id}</div>
            </div>
          ))}
        </div>
      </div>

      {coverage.length > 0 && (
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">Detected Techniques</div>
          </div>
          <div className="panel-body no-pad">
            <table className="threat-table">
              <thead><tr><th>Tactic</th><th>Technique ID</th><th>Technique Name</th><th>Severity</th></tr></thead>
              <tbody>
                {coverage.map((c, i) => (
                  <tr key={i}>
                    <td style={{ fontWeight: 500, color: '#F0EFE9' }}>{c.tactic}</td>
                    <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 12 }}>{c.technique_id}</td>
                    <td>{c.technique_name}</td>
                    <td><span className={`severity-badge ${c.severity}`}>{c.severity}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
