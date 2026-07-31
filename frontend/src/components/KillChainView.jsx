import { useState, useEffect } from 'react';
import { Target, ChevronRight, Activity, ShieldAlert, CheckCircle } from 'lucide-react';
import { api } from '../api';

const PHASES = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact'
];

export default function KillChainView({ stats }) {
  const [killChainData, setKillChainData] = useState(null);
  const [loading, setLoading] = useState(false);

  // Derive current phase from threats
  const detectedTactics = new Set((stats?.mitre_attack_coverage || []).map(c => c.tactic));
  const currentIdx = PHASES.reduce((max, phase, idx) => {
    // Handle MITRE mapping which sometimes omits parts of the name
    const match = [...detectedTactics].some(t => t.toLowerCase().includes(phase.toLowerCase().split(' ')[0].toLowerCase()));
    return match ? Math.max(max, idx) : max;
  }, 2); // Default to Initial Access if nothing detected yet

  const currentPhase = PHASES[currentIdx];

  useEffect(() => {
    async function loadKillChain() {
      setLoading(true);
      try {
        const data = await api.getKillChain(currentPhase);
        setKillChainData(data);
      } catch(e) {
        console.error("Failed to fetch kill chain data", e);
      } finally {
        setLoading(false);
      }
    }
    loadKillChain();
  }, [currentPhase, stats?.timestamp]);

  return (
    <div className="fade-in">
      {(!stats || stats.active_threats === 0) ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60vh', textAlign: 'center' }}>
          <div style={{ background: 'rgba(55,138,221,0.1)', padding: 30, borderRadius: '50%', marginBottom: 20 }}>
            <Target size={48} color="#378ADD" />
          </div>
          <h2 style={{ color: '#F0EFE9', marginBottom: 10 }}>No Active Kill Chains</h2>
          <p style={{ color: '#8892B0', maxWidth: 400, lineHeight: 1.6 }}>
            Your environment has no ongoing local attacks. Once threats are detected, the AI will map them to the MITRE ATT&CK framework and predict subsequent phases here.
          </p>
        </div>
      ) : (
        <>
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-header">
              <div className="panel-title"><Target size={16} /> Data-Driven Cyber Kill Chain</div>
              <span style={{ fontSize: 12, color: '#378ADD' }}>
                 {killChainData ? killChainData.attack_progression_pct : ((currentIdx + 1) / PHASES.length * 100).toFixed(0)}% Progression
              </span>
            </div>
        <div className="panel-body">
          <div className="kill-chain" style={{ flexWrap: 'wrap', gap: '8px 4px' }}>
            {PHASES.map((phase, idx) => (
              <div key={phase} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div className={`kill-chain-phase ${idx < currentIdx ? 'completed' : idx === currentIdx ? 'current' : idx <= currentIdx + 3 ? 'predicted' : ''}`}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: idx <= currentIdx ? '#FF3B5C' : idx <= currentIdx + 3 ? '#378ADD' : '#6B7280' }}>
                    {idx + 1}
                  </div>
                  <div className="kill-chain-phase-name" style={{ fontSize: 10 }}>{phase.replace(' ', '\n')}</div>
                </div>
                {idx < PHASES.length - 1 && <div className="kill-chain-arrow"><ChevronRight size={12} /></div>}
              </div>
            ))}
          </div>

          <div style={{ marginTop: 20, display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            <div style={{ padding: 12, background: 'rgba(255,59,92,0.08)', borderRadius: 8, border: '1px solid rgba(255,59,92,0.2)' }}>
              <div style={{ fontSize: 11, color: '#FF3B5C', fontWeight: 600, marginBottom: 4 }}>● COMPLETED</div>
              <div style={{ fontSize: 12, color: '#B4B2A9' }}>Phases confirmed by DB threat telemetry</div>
            </div>
            <div style={{ padding: 12, background: 'rgba(245,158,11,0.08)', borderRadius: 8, border: '1px solid rgba(245,158,11,0.2)' }}>
              <div style={{ fontSize: 11, color: '#F59E0B', fontWeight: 600, marginBottom: 4 }}>● CURRENT</div>
              <div style={{ fontSize: 12, color: '#B4B2A9' }}>Most advanced attack phase detected</div>
            </div>
            <div style={{ padding: 12, background: 'rgba(55,138,221,0.08)', borderRadius: 8, border: '1px dashed rgba(55,138,221,0.3)' }}>
              <div style={{ fontSize: 11, color: '#378ADD', fontWeight: 600, marginBottom: 4 }}>◌ PREDICTED</div>
              <div style={{ fontSize: 12, color: '#B4B2A9' }}>AI-predicted upcoming phases</div>
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title"><Activity size={16} /> AI Prediction: Next Phases</div>
          </div>
          <div className="panel-body no-pad">
            {loading ? <div className="scanning"><div className="scanning-ring"/></div> : (
              <table className="threat-table">
                <thead><tr><th>Predicted Phase</th><th>Probability</th><th>Likely Technique</th></tr></thead>
                <tbody>
                  {(killChainData?.predicted_next_phases || []).slice(0, 4).map((p, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 500, color: '#F0EFE9' }}>{p.phase}</td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                           <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                             <div style={{ width: `${p.probability * 100}%`, height: '100%', borderRadius: 2, background: p.probability > 0.8 ? '#FF3B5C' : '#F59E0B' }} />
                           </div>
                           <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono'" }}>{(p.probability * 100).toFixed(0)}%</span>
                        </div>
                      </td>
                      <td style={{ fontSize: 11, color: '#8892B0' }}>{p.likely_techniques?.[0] || 'Unknown'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <div className="panel-title"><ShieldAlert size={16} /> Recommended Defensive Actions</div>
          </div>
          <div className="panel-body">
            <div className="playbook" style={{ gap: 10 }}>
              {killChainData?.recommended_action && (
                <div className="playbook-step" style={{ padding: 12, background: 'rgba(34, 197, 94, 0.1)', border: '1px solid rgba(34, 197, 94, 0.2)' }}>
                  <div className="playbook-step-number" style={{ background: '#22C55E', color: '#000' }}><CheckCircle size={14}/></div>
                  <div className="playbook-step-content">
                    <h4 style={{ color: '#22C55E' }}>Immediate Action for {currentPhase}</h4>
                    <p>{killChainData.recommended_action}</p>
                  </div>
                </div>
              )}
              {(killChainData?.predicted_next_phases || []).slice(0, 2).map((p, i) => (
                <div key={i} className="playbook-step" style={{ padding: 12 }}>
                  <div className="playbook-step-number" style={{ background: '#378ADD', color: '#fff' }}>{i + 1}</div>
                  <div className="playbook-step-content">
                    <h4>Preemptive: {p.phase}</h4>
                    <p>{p.defensive_action}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
      </>
      )}
    </div>
  );
}
