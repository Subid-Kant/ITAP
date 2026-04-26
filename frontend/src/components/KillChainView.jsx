import { Target, ChevronRight } from 'lucide-react';

const PHASES = [
  'Reconnaissance', 'Resource Dev', 'Initial Access', 'Execution',
  'Persistence', 'Priv Escalation', 'Defense Evasion', 'Credential Access',
  'Lateral Movement', 'Collection', 'C2', 'Exfiltration', 'Impact'
];

export default function KillChainView({ stats }) {
  const threats = stats?.recent_threats || [];
  // Find the most advanced phase from detected threats
  const detectedTactics = new Set((stats?.mitre_attack_coverage || []).map(c => c.tactic));
  const currentIdx = PHASES.reduce((max, phase, idx) => {
    const match = [...detectedTactics].some(t => t.toLowerCase().includes(phase.toLowerCase().split(' ')[0].toLowerCase()));
    return match ? Math.max(max, idx) : max;
  }, 1);

  return (
    <div className="fade-in">
      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <div className="panel-title"><Target size={16} /> Cyber Kill Chain — Attack Progression</div>
          <span style={{ fontSize: 12, color: '#6B7280' }}>
            {((currentIdx + 1) / PHASES.length * 100).toFixed(0)}% progression detected
          </span>
        </div>
        <div className="panel-body">
          <div className="kill-chain">
            {PHASES.map((phase, idx) => (
              <div key={phase} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div className={`kill-chain-phase ${idx < currentIdx ? 'completed' : idx === currentIdx ? 'current' : idx <= currentIdx + 2 ? 'predicted' : ''}`}>
                  <div style={{ fontSize: 14, fontWeight: 700, color: idx <= currentIdx ? '#FF3B5C' : idx <= currentIdx + 2 ? '#378ADD' : '#6B7280' }}>
                    {idx + 1}
                  </div>
                  <div className="kill-chain-phase-name">{phase}</div>
                </div>
                {idx < PHASES.length - 1 && <div className="kill-chain-arrow"><ChevronRight size={14} /></div>}
              </div>
            ))}
          </div>

          <div style={{ marginTop: 20, display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            <div style={{ padding: 12, background: 'rgba(255,59,92,0.08)', borderRadius: 8, border: '1px solid rgba(255,59,92,0.2)' }}>
              <div style={{ fontSize: 11, color: '#FF3B5C', fontWeight: 600, marginBottom: 4 }}>● COMPLETED</div>
              <div style={{ fontSize: 12, color: '#B4B2A9' }}>Phases already detected in threat data</div>
            </div>
            <div style={{ padding: 12, background: 'rgba(245,158,11,0.08)', borderRadius: 8, border: '1px solid rgba(245,158,11,0.2)' }}>
              <div style={{ fontSize: 11, color: '#F59E0B', fontWeight: 600, marginBottom: 4 }}>● CURRENT</div>
              <div style={{ fontSize: 12, color: '#B4B2A9' }}>Current attack phase detected</div>
            </div>
            <div style={{ padding: 12, background: 'rgba(55,138,221,0.08)', borderRadius: 8, border: '1px dashed rgba(55,138,221,0.3)' }}>
              <div style={{ fontSize: 11, color: '#378ADD', fontWeight: 600, marginBottom: 4 }}>◌ PREDICTED</div>
              <div style={{ fontSize: 12, color: '#B4B2A9' }}>AI-predicted next phases</div>
            </div>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">Recommended Defensive Actions</div>
        </div>
        <div className="panel-body">
          <div className="playbook">
            {[
              { n: 1, t: 'Patch Public-Facing Apps', d: 'Apply security patches to all web-facing services. Focus on CVEs identified in OSINT scan.' },
              { n: 2, t: 'Enable Enhanced Monitoring', d: 'Deploy additional EDR sensors. Increase SIEM log retention. Enable network packet capture.' },
              { n: 3, t: 'Segment Critical Networks', d: 'Implement micro-segmentation. Restrict lateral movement paths. Review firewall rules.' },
              { n: 4, t: 'Credential Hardening', d: 'Force MFA on all accounts. Rotate exposed credentials. Deploy credential guard.' },
            ].map(s => (
              <div key={s.n} className="playbook-step">
                <div className="playbook-step-number">{s.n}</div>
                <div className="playbook-step-content"><h4>{s.t}</h4><p>{s.d}</p></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
