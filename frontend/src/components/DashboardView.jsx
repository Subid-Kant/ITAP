import { useState, useEffect } from 'react';
import {
  Shield, AlertTriangle, Activity, Target, Brain, Eye,
  Layers, Link2, ShieldAlert
} from 'lucide-react';
import LiveSystemLog from './LiveSystemLog';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const SEVERITY_COLORS = {
  critical: '#FF2E63', high: '#F97316', medium: '#F59E0B', low: '#22C55E', info: '#60A5FA'
};



// Animated stat card with count-up effect
function StatCard({ icon: Icon, value, label, color }) {
  const [displayed, setDisplayed] = useState(0);
  useEffect(() => {
    if (!value) return;
    const target = parseInt(value, 10);
    if (isNaN(target)) return;
    let current = 0;
    const step = Math.ceil(target / 20);
    const timer = setInterval(() => {
      current = Math.min(current + step, target);
      setDisplayed(current);
      if (current >= target) clearInterval(timer);
    }, 40);
    return () => clearInterval(timer);
  }, [value]);

  const colorMap = {
    blue: 'var(--accent-blue)', orange: '#F97316', red: '#FF2E63',
    purple: '#9D50FF', cyan: '#00F5D4', green: '#22C55E',
  };
  const c = colorMap[color] || 'var(--accent-blue)';

  return (
    <div className="stat-card" style={{ position: 'relative', overflow: 'hidden' }}>
      <div className="stat-icon" style={{ color: c }}>
        <Icon size={20} />
      </div>
      <div className="stat-value" style={{ color: color === 'red' && value > 0 ? '#FF2E63' : undefined }}>
        {displayed}
      </div>
      <div className="stat-label">{label}</div>
      {color === 'red' && value > 0 && (
        <div style={{
          position: 'absolute', inset: 0, borderRadius: 'inherit', pointerEvents: 'none',
          animation: 'criticalPulse 2s ease-in-out infinite',
        }} />
      )}
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
          <Tooltip contentStyle={{ background: '#0d1323', border: '1px solid rgba(55,138,221,0.2)', borderRadius: 8, color: '#F0EFE9' }} />
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>
            {chartData.map((e, i) => <Cell key={i} fill={e.fill} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}



// Attack Surface Panel
function AttackSurfacePanel({ data }) {
  if (!data?.length) return (
    <div style={{ color: '#4B5563', fontSize: 12, textAlign: 'center', padding: 16 }}>
      No attack surface data yet — run an OSINT scan.
    </div>
  );
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {data.map((item, i) => {
        const c = item.severity === 'HIGH' ? '#F59E0B' : '#378ADD';
        return (
          <div key={i} style={{
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '7px 10px', background: `${c}08`,
            border: `1px solid ${c}25`, borderRadius: 7,
          }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: c, flexShrink: 0 }} />
            <div style={{ flex: 1, fontSize: 12, color: '#B4B2A9', fontWeight: 500 }}>{item.component}</div>
            <div style={{ fontSize: 11, color: c, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
              {item.threat_count} threat{item.threat_count !== 1 ? 's' : ''}
            </div>
          </div>
        );
      })}
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
  if (!stats) return (
    <div className="scanning">
      <div className="scanning-ring" />
      <div className="scanning-text">Loading dashboard...</div>
    </div>
  );

  if (stats.total_targets === 0 && stats.active_threats === 0) {
    return (
      <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60vh', textAlign: 'center' }}>
        <div style={{ background: 'rgba(55,138,221,0.1)', padding: 30, borderRadius: '50%', marginBottom: 20 }}>
          <Target size={48} color="#378ADD" />
        </div>
        <h2 style={{ color: '#F0EFE9', marginBottom: 10 }}>No Targets Being Monitored</h2>
        <p style={{ color: '#8892B0', maxWidth: 400, lineHeight: 1.6 }}>
          Your environment is currently quiet. Add a target in the OSINT Scanner to begin collecting intelligence and generating threat predictions.
        </p>
      </div>
    );
  }

  return (
    <div className="fade-in">
      {/* Stat Cards with count-up animation */}
      <div className="stats-grid stagger">
        <StatCard icon={Target} value={stats.total_targets} label="Monitored Targets" color="blue" />
        <StatCard icon={AlertTriangle} value={stats.active_threats} label="Active Threats" color="orange" />
        <StatCard icon={Shield} value={stats.critical_threats} label="Critical Threats" color="red" />
        <StatCard icon={Activity} value={stats.open_incidents} label="Open Incidents" color="purple" />
        <StatCard icon={Brain} value={stats.predictions_active} label="Active Predictions" color="cyan" />
        <StatCard icon={Eye} value={stats.anomalies_detected} label="Anomalies Detected" color="green" />
      </div>

      {/* Main content grid */}
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



      {/* Second row: Threats + Attack Surface */}
      <div className="content-grid">
        <div className="panel">
          <div className="panel-header"><div className="panel-title"><Shield size={16} /> Recent Threats</div></div>
          <div className="panel-body no-pad">
            <table className="threat-table">
              <thead>
                <tr><th>Threat</th><th>Severity</th><th>MITRE Tactic</th><th>Time</th></tr>
              </thead>
              <tbody>
                {(stats.recent_threats || []).slice(0, 6).map((t, i) => (
                  <tr key={i}>
                    <td style={{ color: '#F0EFE9', fontWeight: 500 }}>{t.title}</td>
                    <td><span className={`severity-badge ${t.severity}`}>{t.severity}</span></td>
                    <td>{t.mitre_tactic || '—'}</td>
                    <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>
                      {t.detected_at ? new Date(t.detected_at).toLocaleTimeString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* NEW: Attack Surface Panel */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <Layers size={16} style={{ color: '#F59E0B' }} />
              Attack Surface
            </div>
            <div style={{ fontSize: 11, color: '#6B7280' }}>Top affected components</div>
          </div>
          <div className="panel-body">
            <AttackSurfacePanel data={stats.attack_surface_summary} />
          </div>
        </div>
      </div>

      {/* Incidents row */}
      <div className="content-grid">
        <div className="panel">
          <div className="panel-header"><div className="panel-title"><ShieldAlert size={16} /> Open Incidents</div></div>
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

      <style>{`
        @keyframes criticalPulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(255,46,99,0); }
          50% { box-shadow: 0 0 20px 4px rgba(255,46,99,0.2); }
        }
      `}</style>
    </div>
  );
}
