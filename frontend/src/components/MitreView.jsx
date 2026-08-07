import { useState, useMemo } from 'react';
import { Grid3X3, ExternalLink, ShieldAlert, ShieldOff, Target } from 'lucide-react';

const MITRE_TACTICS = [
  { name: 'Reconnaissance', id: 'TA0043', color: '#378ADD', icon: '🔍' },
  { name: 'Resource Dev', id: 'TA0042', color: '#6366F1', icon: '🛠️' },
  { name: 'Initial Access', id: 'TA0001', color: '#8B5CF6', icon: '🚪' },
  { name: 'Execution', id: 'TA0002', color: '#A855F7', icon: '⚡' },
  { name: 'Persistence', id: 'TA0003', color: '#EC4899', icon: '🔗' },
  { name: 'Priv Escalation', id: 'TA0004', color: '#F43F5E', icon: '⬆️' },
  { name: 'Defense Evasion', id: 'TA0005', color: '#EF4444', icon: '🛡️' },
  { name: 'Credential Access', id: 'TA0006', color: '#F97316', icon: '🔑' },
  { name: 'Discovery', id: 'TA0007', color: '#F59E0B', icon: '🗺️' },
  { name: 'Lateral Movement', id: 'TA0008', color: '#EAB308', icon: '↔️' },
  { name: 'Collection', id: 'TA0009', color: '#84CC16', icon: '📦' },
  { name: 'C2', id: 'TA0011', color: '#22C55E', icon: '📡' },
  { name: 'Exfiltration', id: 'TA0010', color: '#06D6A0', icon: '📤' },
  { name: 'Impact', id: 'TA0040', color: '#FF3B5C', icon: '💥' },
];

// Coverage gap descriptions for blind-spot analysis
const TACTIC_BLIND_SPOTS = {
  'Reconnaissance': 'No passive scanning or footprinting activity detected. Consider deploying honeypots or monitoring DNS query logs for scanning probes.',
  'Resource Dev': 'No threat actor infrastructure staging detected. Monitor for newly registered domains mimicking your brand (typosquatting).',
  'Initial Access': 'No initial access attempts detected. Ensure logging covers all external entry points: VPN, web app, email gateway.',
  'Execution': 'No malicious code execution attempts logged. Verify endpoint telemetry and script execution logging (PowerShell, bash) is active.',
  'Persistence': 'No persistence mechanisms detected. Audit scheduled tasks, cron jobs, startup entries, and registry run keys periodically.',
  'Priv Escalation': 'No privilege escalation activity. Monitor for SUID abuse, sudo misuse, token manipulation, and kernel exploit attempts.',
  'Defense Evasion': 'No evasion techniques detected. Consider monitoring for log clearing, process hollowing, and AMSI bypass attempts.',
  'Credential Access': 'No credential theft activity. Deploy honeycredentials, monitor for LSASS access, and alert on Kerberoasting patterns.',
  'Discovery': 'No internal reconnaissance detected. Implement network detection for port scans from internal hosts.',
  'Lateral Movement': 'No lateral movement detected. Monitor for unusual SMB, RDP, or SSH connections between internal systems.',
  'Collection': 'No data staging detected. Monitor large file reads, clipboard access, and unusual archive creation.',
  'C2': 'No C2 beaconing detected. Ensure DNS sinkholing and SSL inspection are active on egress traffic.',
  'Exfiltration': 'No data exfiltration detected. Monitor for large outbound transfers, especially to cloud storage or unusual geo-locations.',
  'Impact': 'No destructive or disruptive activity detected. Ensure backup integrity monitoring and ransomware detection rules are active.',
};

export default function MitreView({ stats }) {
  const [selectedTactic, setSelectedTactic] = useState(null);
  const coverage = stats?.mitre_attack_coverage || [];

  // Group techniques by tactic
  const tacticMap = useMemo(() => {
    const map = {};
    coverage.forEach(c => {
      const tactic = c.tactic;
      if (!map[tactic]) map[tactic] = [];
      map[tactic].push(c);
    });
    return map;
  }, [coverage]);

  const tacticCounts = useMemo(() => {
    const counts = {};
    Object.keys(tacticMap).forEach(t => { counts[t] = tacticMap[t].length; });
    return counts;
  }, [tacticMap]);

  const activeTactics = Object.keys(tacticMap);
  const inactiveTactics = MITRE_TACTICS.filter(t => !tacticCounts[t.name]);

  const selectedTacticData = selectedTactic ? tacticMap[selectedTactic] : null;

  const severityColors = { critical: '#FF2E63', high: '#F59E0B', medium: '#378ADD', low: '#22C55E' };

  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* ── ATT&CK Matrix Heatmap ── */}
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title"><Grid3X3 size={16} /> MITRE ATT&CK Matrix — Live Detection Coverage</div>
          <div style={{ fontSize: 12, color: '#6B7280' }}>
            {activeTactics.length}/{MITRE_TACTICS.length} tactics active
          </div>
        </div>
        <div style={{ padding: '16px' }}>
          <div className="mitre-matrix">
            {MITRE_TACTICS.map(t => {
              const count = tacticCounts[t.name] || 0;
              const isActive = count > 0;
              const isSelected = selectedTactic === t.name;
              return (
                <div
                  key={t.id}
                  onClick={() => setSelectedTactic(isSelected ? null : t.name)}
                  className={`mitre-tactic ${isActive ? 'active' : ''}`}
                  style={{
                    cursor: isActive ? 'pointer' : 'default',
                    borderColor: isActive ? t.color : undefined,
                    boxShadow: isActive ? `0 0 14px ${t.color}40` : undefined,
                    outline: isSelected ? `2px solid ${t.color}` : undefined,
                    transform: isSelected ? 'scale(1.06)' : undefined,
                    transition: 'all 0.2s ease',
                  }}
                >
                  <div className="mitre-tactic-count" style={{ color: isActive ? t.color : undefined }}>
                    {count}
                  </div>
                  <div className="mitre-tactic-name">{t.name}</div>
                  <div style={{ fontSize: 9, color: '#4B5563', marginTop: 2 }}>{t.id}</div>
                </div>
              );
            })}
          </div>
          {activeTactics.length > 0 && (
            <div style={{ fontSize: 11, color: '#6B7280', marginTop: 12, textAlign: 'center' }}>
              Click an active tactic to see technique details
            </div>
          )}
        </div>
      </div>

      {/* ── Selected Tactic Detail ── */}
      {selectedTactic && selectedTacticData && (
        <div className="panel" style={{ borderColor: 'rgba(55,138,221,0.3)' }}>
          <div className="panel-header">
            <div className="panel-title">
              <ShieldAlert size={16} />
              {selectedTactic} — Active Techniques
            </div>
            <button onClick={() => setSelectedTactic(null)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6B7280', fontSize: 18 }}>×</button>
          </div>
          <div className="panel-body no-pad">
            <table className="threat-table">
              <thead>
                <tr>
                  <th>Technique ID</th>
                  <th>Technique Name</th>
                  <th>Target Domain</th>
                  <th>Severity</th>
                  <th>Reference</th>
                </tr>
              </thead>
              <tbody>
                {selectedTacticData.map((c, i) => {
                  const sc = severityColors[c.severity?.toLowerCase()] || '#6B7280';
                  return (
                    <tr key={i}>
                      <td>
                        <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#378ADD' }}>
                          {c.technique_id || '—'}
                        </code>
                      </td>
                      <td style={{ color: '#F0EFE9', fontWeight: 500 }}>{c.technique_name || '—'}</td>
                      <td>
                        {c.target_domain
                          ? <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                              <Target size={10} color="#6B7280" />
                              <span style={{ fontSize: 12, color: '#9CA3AF' }}>{c.target_domain}</span>
                            </span>
                          : <span style={{ color: '#4B5563' }}>—</span>
                        }
                      </td>
                      <td>
                        <span style={{ fontSize: 11, fontWeight: 700, color: sc, background: `${sc}18`, border: `1px solid ${sc}40`, padding: '2px 7px', borderRadius: 4 }}>
                          {c.severity?.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        {c.mitre_url && c.technique_id && (
                          <a href={c.mitre_url} target="_blank" rel="noopener noreferrer"
                            style={{ color: '#378ADD', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
                            <ExternalLink size={11} /> ATT&CK
                          </a>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── All Detected Techniques (when none selected) ── */}
      {!selectedTactic && coverage.length > 0 && (
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">Detected Techniques ({coverage.length} total)</div>
          </div>
          <div className="panel-body no-pad">
            <table className="threat-table">
              <thead>
                <tr><th>Tactic</th><th>Technique ID</th><th>Technique Name</th><th>Target</th><th>Severity</th><th>MITRE Link</th></tr>
              </thead>
              <tbody>
                {coverage.map((c, i) => {
                  const sc = severityColors[c.severity?.toLowerCase()] || '#6B7280';
                  return (
                    <tr key={i} onClick={() => setSelectedTactic(c.tactic)} style={{ cursor: 'pointer' }}>
                      <td style={{ fontWeight: 500, color: '#F0EFE9' }}>{c.tactic}</td>
                      <td><code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#378ADD' }}>{c.technique_id}</code></td>
                      <td>{c.technique_name}</td>
                      <td style={{ fontSize: 12, color: '#9CA3AF' }}>{c.target_domain || '—'}</td>
                      <td><span className={`severity-badge ${c.severity?.toLowerCase()}`}>{c.severity?.toUpperCase()}</span></td>
                      <td>
                        {c.mitre_url && c.technique_id && (
                          <a href={c.mitre_url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}
                            style={{ color: '#378ADD', display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}>
                            <ExternalLink size={10} /> View
                          </a>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Coverage Gap Analysis ── */}
      {inactiveTactics.length > 0 && (
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <ShieldOff size={16} style={{ color: '#F59E0B' }} />
              Coverage Gap Analysis — {inactiveTactics.length} Undetected Tactics
            </div>
          </div>
          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ fontSize: 12, color: '#6B7280', marginBottom: 4 }}>
              The following ATT&CK tactics have zero detections. This may indicate blind spots in your monitoring coverage.
            </div>
            {inactiveTactics.map(t => (
              <div key={t.id} style={{
                display: 'flex', alignItems: 'flex-start', gap: 12, padding: '10px 14px',
                background: 'rgba(245,158,11,0.04)', border: '1px solid rgba(245,158,11,0.12)', borderRadius: 8
              }}>
                <div style={{ fontSize: 16, flexShrink: 0 }}>{t.icon}</div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                    <span style={{ fontWeight: 600, fontSize: 12, color: '#F0EFE9' }}>{t.name}</span>
                    <code style={{ fontSize: 10, color: '#4B5563', fontFamily: "'JetBrains Mono', monospace" }}>{t.id}</code>
                  </div>
                  <div style={{ fontSize: 11, color: '#9CA3AF', lineHeight: 1.6 }}>
                    {TACTIC_BLIND_SPOTS[t.name] || 'No detection rules active for this tactic.'}
                  </div>
                </div>
                <a href={`https://attack.mitre.org/tactics/${t.id}/`} target="_blank" rel="noopener noreferrer"
                  style={{ color: '#4B5563', flexShrink: 0 }} title="View on MITRE">
                  <ExternalLink size={12} />
                </a>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Empty state */}
      {coverage.length === 0 && (
        <div className="panel">
          <div className="panel-body" style={{ textAlign: 'center', padding: 40, color: '#6B7280' }}>
            <Grid3X3 size={40} style={{ opacity: 0.2, marginBottom: 16 }} />
            <div style={{ fontSize: 14, marginBottom: 8 }}>No MITRE ATT&CK data yet</div>
            <div style={{ fontSize: 12 }}>Run an OSINT scan to populate the ATT&CK matrix with real threat intelligence</div>
          </div>
        </div>
      )}
    </div>
  );
}
