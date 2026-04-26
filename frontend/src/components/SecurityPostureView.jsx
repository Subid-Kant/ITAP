import { ShieldCheck, AlertCircle, Info, Activity, ShieldAlert } from 'lucide-react';

export default function SecurityPostureView({ stats }) {
  if (!stats) return null;

  const score = 100 - (stats.critical_threats * 15 + stats.active_threats * 5 + stats.open_incidents * 10);
  const normalizedScore = Math.max(0, Math.min(100, score));
  
  const getStatusColor = (s) => {
    if (s >= 80) return 'var(--accent-green)';
    if (s >= 50) return 'var(--accent-orange)';
    return 'var(--accent-red)';
  };

  const statusColor = getStatusColor(normalizedScore);

  return (
    <div className="fade-in">
      <div className="panel glass" style={{ marginBottom: 24, border: `1px solid ${statusColor}33` }}>
        <div className="panel-body" style={{ display: 'flex', alignItems: 'center', gap: 40, padding: '30px' }}>
          <div style={{ position: 'relative', width: 140, height: 140 }}>
            <svg viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)', width: '100%', height: '100%' }}>
              <circle cx="50" cy="50" r="45" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
              <circle cx="50" cy="50" r="45" fill="none" stroke={statusColor} strokeWidth="8"
                strokeDasharray="283" strokeDashoffset={283 * (1 - normalizedScore / 100)}
                strokeLinecap="round" style={{ transition: 'all 1.5s ease-out' }} />
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <div style={{ fontSize: 32, fontWeight: 900, color: statusColor }}>{normalizedScore}%</div>
              <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700 }}>Security Health</div>
            </div>
          </div>
          
          <div style={{ flex: 1 }}>
            <h2 style={{ fontSize: 24, marginBottom: 8, fontWeight: 800 }}>AI Security Executive Summary</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: 14, lineHeight: 1.6, maxWidth: 600 }}>
              {normalizedScore >= 80 
                ? "Your infrastructure is currently in a high security state. All predictive models indicate low immediate risk, though routine scanning is recommended for 0-day detection."
                : normalizedScore >= 50
                ? "Moderate risk detected. Multiple active threats are being correlated across OSINT sources. AI models predict potential escalation in the next 48 hours."
                : "CRITICAL ALERT: Your security posture is severely compromised. Immediate remediation of critical incidents is required to prevent further lateral movement and data exfiltration."}
            </p>
            <div style={{ display: 'flex', gap: 16, marginTop: 20 }}>
              <div className="glass" style={{ padding: '8px 16px', borderRadius: 12, display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                <Activity size={14} color="var(--accent-blue)" /> <span>Real-time Monitoring Active</span>
              </div>
              <div className="glass" style={{ padding: '8px 16px', borderRadius: 12, display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                <ShieldCheck size={14} color="var(--accent-green)" /> <span>Compliance: PCI-DSS, ISO27001</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="content-grid">
        <div className="panel glass">
          <div className="panel-header"><div className="panel-title"><ShieldAlert size={16} /> Intelligence Insights</div></div>
          <div className="panel-body">
            <ul style={{ listStyle: 'none', padding: 0 }}>
              {[
                { icon: Info, text: "Unusual traffic spikes detected from 3 Russian IP blocks.", color: 'var(--accent-orange)' },
                { icon: AlertCircle, text: "4 CVEs identified in public-facing web servers require urgent patching.", color: 'var(--accent-red)' },
                { icon: ShieldCheck, text: "DDoS mitigation successfully absorbed 45Gbps peak.", color: 'var(--accent-green)' }
              ].map((item, i) => (
                <li key={i} style={{ display: 'flex', gap: 12, marginBottom: 16, fontSize: 13, alignItems: 'start' }}>
                  <item.icon size={16} style={{ marginTop: 2, color: item.color }} />
                  <span style={{ color: 'var(--text-secondary)' }}>{item.text}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
        
        <div className="panel glass">
          <div className="panel-header"><div className="panel-title"><Activity size={16} /> AI Predictive Status</div></div>
          <div className="panel-body">
             <div style={{ marginBottom: 15 }}>
               <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
                 <span>LSTM Confidence</span>
                 <span>94.2%</span>
               </div>
               <div style={{ height: 6, background: 'rgba(255,255,255,0.05)', borderRadius: 3 }}>
                 <div style={{ width: '94.2%', height: '100%', background: 'var(--accent-blue)', borderRadius: 3 }} />
               </div>
             </div>
             <div style={{ marginBottom: 15 }}>
               <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
                 <span>Autoencoder Training Delta</span>
                 <span>-0.02% (Stable)</span>
               </div>
               <div style={{ height: 6, background: 'rgba(255,255,255,0.05)', borderRadius: 3 }}>
                 <div style={{ width: '85%', height: '100%', background: 'var(--accent-cyan)', borderRadius: 3 }} />
               </div>
             </div>
             <div style={{ padding: 12, background: 'rgba(0, 163, 255, 0.05)', borderRadius: 10, fontSize: 12, color: 'var(--text-secondary)' }}>
                Predictive window: Next 72 hours of operations are being analyzed. No major zero-day variants detected.
             </div>
          </div>
        </div>
      </div>
    </div>
  );
}
