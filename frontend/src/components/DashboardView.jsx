import { Shield, AlertTriangle, Activity, Target, Brain, Eye, Terminal } from 'lucide-react';
import LiveSystemLog from './LiveSystemLog';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, AreaChart, Area } from 'recharts';

const SEVERITY_COLORS = {
  critical: '#FF3B5C', high: '#F97316', medium: '#F59E0B', low: '#22C55E', info: '#60A5FA'
};

function StatCard({ icon: Icon, value, label, color, className }) {
  return (
    <div className={`stat-card ${className || ''}`}>
      <div className={`stat-icon ${color}`}><Icon size={20} /></div>
      <div className={`stat-value ${color === 'red' ? 'critical' : ''}`}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function SeverityChart({ data }) {
  const chartData = Object.entries(data || {}).map(([k, v]) => ({ name: k, value: v, fill: SEVERITY_COLORS[k] }));
  return (
    <div className="chart-container">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <XAxis dataKey="name" tick={{ fill: '#6B7280', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: '#6B7280', fontSize: 11 }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={{ background: '#151b2b', border: '1px solid rgba(55,138,221,0.2)', borderRadius: 8, color: '#F0EFE9' }} />
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>
            {chartData.map((e, i) => <Cell key={i} fill={e.fill} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function RiskGauge({ score }) {
  const r = 50, c = 2 * Math.PI * r;
  const pct = (score || 0) / 100;
  const color = score >= 75 ? '#FF3B5C' : score >= 50 ? '#F97316' : score >= 25 ? '#F59E0B' : '#22C55E';
  return (
    <div className="risk-gauge">
      <svg width="120" height="120" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
        <circle cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={c} strokeDashoffset={c * (1 - pct)} strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1s ease' }} />
      </svg>
      <div className="risk-gauge-value">
        <div className="risk-gauge-number" style={{ color }}>{score || 0}</div>
        <div className="risk-gauge-label">Risk Score</div>
      </div>
    </div>
  );
}

function ThreatTimeline({ threats }) {
  return (
    <div className="timeline">
      {(threats || []).slice(0, 8).map((t, i) => (
        <div key={i} className={`timeline-item ${t.severity}`}>
          <div className="timeline-time">{new Date(t.detected_at).toLocaleTimeString()}</div>
          <div className="timeline-title">{t.title}</div>
          <div className="timeline-meta">
            <span className={`severity-badge ${t.severity}`}>{t.severity}</span>
            {t.source_country && <span style={{ marginLeft: 8 }}>📍 {t.source_country}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

export default function DashboardView({ stats }) {
  if (!stats) return <div className="scanning"><div className="scanning-ring" /><div className="scanning-text">Loading dashboard...</div></div>;
  
  if (stats.total_targets === 0 && stats.active_threats === 0) {
    return (
      <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60vh', textAlign: 'center' }}>
        <div style={{ background: 'rgba(55,138,221,0.1)', padding: 30, borderRadius: '50%', marginBottom: 20 }}>
          <Target size={48} color="#378ADD" />
        </div>
        <h2 style={{ color: '#F0EFE9', marginBottom: 10 }}>No Targets Being Monitored</h2>
        <p style={{ color: '#8892B0', maxWidth: 400, lineHeight: 1.6 }}>
          Your environment is currently quiet. Add a target in the OSINT Scanner to begin collecting intelligence and generating threat predictions. Live global threats can be viewed in the Incidents tab.
        </p>
      </div>
    );
  }

  return (
    <div className="fade-in">
      <div className="stats-grid stagger">
        <StatCard icon={Target} value={stats.total_targets} label="Monitored Targets" color="blue" />
        <StatCard icon={AlertTriangle} value={stats.active_threats} label="Active Threats" color="orange" />
        <StatCard icon={Shield} value={stats.critical_threats} label="Critical Threats" color="red" className="critical" />
        <StatCard icon={Activity} value={stats.open_incidents} label="Open Incidents" color="purple" />
        <StatCard icon={Brain} value={stats.predictions_active} label="Active Predictions" color="cyan" />
        <StatCard icon={Eye} value={stats.anomalies_detected} label="Anomalies Detected" color="green" />
      </div>

      <div className="content-grid" style={{ gridTemplateColumns: '1fr 1fr 1fr' }}>
        <div className="panel">
          <div className="panel-header"><div className="panel-title"><AlertTriangle size={16} /> Threats by Severity</div></div>
          <div className="panel-body"><SeverityChart data={stats.threats_by_severity} /></div>
        </div>
        <div className="panel">
          <div className="panel-header"><div className="panel-title"><Activity size={16} /> Threat Timeline</div></div>
          <div className="panel-body"><ThreatTimeline threats={stats.recent_threats} /></div>
        </div>
        <div className="panel" style={{ gridRow: 'span 2' }}>
           <LiveSystemLog />
        </div>
      </div>

      <div className="content-grid">
        <div className="panel">
          <div className="panel-header"><div className="panel-title"><Shield size={16} /> Recent Threats</div></div>
          <div className="panel-body no-pad">
            <table className="threat-table">
              <thead><tr><th>Threat</th><th>Severity</th><th>MITRE Tactic</th><th>Time</th></tr></thead>
              <tbody>
                {(stats.recent_threats || []).slice(0, 6).map((t, i) => (
                  <tr key={i}>
                    <td style={{ color: '#F0EFE9', fontWeight: 500 }}>{t.title}</td>
                    <td><span className={`severity-badge ${t.severity}`}>{t.severity}</span></td>
                    <td>{t.mitre_tactic || '—'}</td>
                    <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>{t.detected_at ? new Date(t.detected_at).toLocaleTimeString() : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="panel">
          <div className="panel-header"><div className="panel-title"><Activity size={16} /> Incidents</div></div>
          <div className="panel-body no-pad">
            <table className="threat-table">
              <thead><tr><th>Incident</th><th>Severity</th><th>Status</th></tr></thead>
              <tbody>
                {(stats.recent_incidents || []).slice(0, 6).map((inc, i) => (
                  <tr key={i}>
                    <td style={{ color: '#F0EFE9', fontWeight: 500 }}>{inc.title}</td>
                    <td><span className={`severity-badge ${inc.severity}`}>{inc.severity}</span></td>
                    <td><span className={`status-badge ${inc.status}`}>● {inc.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
