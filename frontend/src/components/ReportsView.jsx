import { useState } from 'react';
import { FileText, Download, Calendar, BarChart2, Shield, AlertTriangle, TrendingUp } from 'lucide-react';
import { api } from '../api';
import { useToast } from './ToastNotification';

function MetricCard({ label, value, color, icon: Icon }) {
  return (
    <div className="stat-card" style={{ textAlign: 'center' }}>
      <div className="stat-icon" style={{ background: `${color}22`, color, margin: '0 auto 12px' }}>
        <Icon size={18} />
      </div>
      <div className="stat-value" style={{ color }}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export default function ReportsView() {
  const { addToast } = useToast();
  const [days, setDays] = useState(7);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);

  const handleGenerate = async () => {
    setLoading(true);
    try {
      const data = await api.generateReport('json', days);
      setReport(data);
      addToast('Report generated successfully', 'success');
    } catch {
      addToast('Report generation failed — ensure backend is running', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async () => {
    try {
      await api.downloadReport(days);
      addToast('Report downloaded', 'success');
    } catch {
      addToast('Download failed', 'error');
    }
  };

  const exec = report?.executive_summary;
  const sev = report?.threats_by_severity || {};

  return (
    <div className="fade-in">
      {/* Config Panel */}
      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <div className="panel-title"><FileText size={16} /> Executive Security Report Generator</div>
        </div>
        <div className="panel-body">
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Calendar size={14} color="var(--accent-blue)" />
              <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Report Period:</span>
              <select
                id="report-days"
                className="scan-input"
                style={{ width: 140, padding: '6px 12px', fontSize: 13 }}
                value={days}
                onChange={e => setDays(Number(e.target.value))}
              >
                <option value={7}>Last 7 Days</option>
                <option value={14}>Last 14 Days</option>
                <option value={30}>Last 30 Days</option>
                <option value={90}>Last 90 Days</option>
              </select>
            </div>
            <button id="report-generate" className="header-btn primary" onClick={handleGenerate} disabled={loading}>
              <BarChart2 size={14} />
              {loading ? 'Generating...' : 'Generate Report'}
            </button>
            {report && (
              <button className="header-btn" onClick={handleDownload}>
                <Download size={14} /> Download TXT
              </button>
            )}
          </div>
        </div>
      </div>

      {!report && !loading && (
        <div className="panel" style={{ padding: 60, textAlign: 'center' }}>
          <FileText size={52} color="var(--text-muted)" style={{ marginBottom: 20 }} />
          <div style={{ color: 'var(--text-muted)', fontSize: 15, marginBottom: 8 }}>
            Select a period and generate your executive security report
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>
            Reports include threat summary, severity breakdown, top IOCs, and recommendations
          </div>
        </div>
      )}

      {loading && (
        <div className="scanning">
          <div className="scanning-ring" />
          <div className="scanning-text">Compiling threat data and generating report...</div>
        </div>
      )}

      {report && (
        <div className="stagger">
          {/* Report Header */}
          <div className="panel glass" style={{ marginBottom: 20, borderColor: 'rgba(0,163,255,0.3)' }}>
            <div className="panel-body" style={{ padding: 28 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                    <Shield size={28} color="var(--accent-blue)" />
                    <h2 style={{ fontSize: 20, fontWeight: 800 }}>{report.report_title}</h2>
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                    Generated: {new Date(report.generated_at).toLocaleString()} · By: {report.generated_by}
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                    Period: {new Date(report.period_start).toLocaleDateString()} – {new Date(report.period_end).toLocaleDateString()}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="header-btn" onClick={handleDownload}>
                    <Download size={14} /> Export
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Metrics */}
          <div className="stats-grid stagger" style={{ marginBottom: 20 }}>
            <MetricCard label="Threats Detected" value={exec?.total_threats_detected || 0}
              color="var(--accent-blue)" icon={Shield} />
            <MetricCard label="Critical Threats" value={exec?.critical_threats || 0}
              color="var(--severity-critical)" icon={AlertTriangle} />
            <MetricCard label="High Threats" value={exec?.high_threats || 0}
              color="var(--severity-high)" icon={AlertTriangle} />
            <MetricCard label="Incidents Opened" value={exec?.incidents_opened || 0}
              color="var(--accent-orange)" icon={TrendingUp} />
            <MetricCard label="Incidents Resolved" value={exec?.incidents_resolved || 0}
              color="var(--accent-green)" icon={Shield} />
          </div>

          {/* Severity Breakdown */}
          <div className="content-grid">
            <div className="panel">
              <div className="panel-header"><div className="panel-title"><BarChart2 size={16} /> Threats by Severity</div></div>
              <div className="panel-body">
                {Object.entries(sev).map(([s, count]) => {
                  const colors = { critical: 'var(--severity-critical)', high: 'var(--severity-high)', medium: 'var(--severity-medium)', low: 'var(--severity-low)', info: 'var(--severity-info)' };
                  const c = colors[s] || 'var(--accent-blue)';
                  const max = Math.max(...Object.values(sev), 1);
                  return (
                    <div key={s} style={{ marginBottom: 14 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <span className={`severity-badge ${s}`}>{s}</span>
                        <span style={{ fontFamily: "'JetBrains Mono'", fontSize: 13 }}>{count}</span>
                      </div>
                      <div style={{ height: 8, background: 'rgba(255,255,255,0.05)', borderRadius: 4, overflow: 'hidden' }}>
                        <div style={{ width: `${(count / max) * 100}%`, height: '100%', background: c, borderRadius: 4, transition: 'width 0.8s ease' }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="panel">
              <div className="panel-header"><div className="panel-title"><Shield size={16} /> Recommendations</div></div>
              <div className="panel-body">
                <ol style={{ padding: '0 0 0 18px', margin: 0 }}>
                  {(report.recommendations || []).map((rec, i) => (
                    <li key={i} style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12, lineHeight: 1.6 }}>
                      {rec}
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          </div>

          {/* Top Threats */}
          {report.top_threats?.length > 0 && (
            <div className="panel" style={{ marginTop: 20 }}>
              <div className="panel-header"><div className="panel-title"><AlertTriangle size={16} /> Top Threats in Period</div></div>
              <div className="panel-body no-pad">
                <table className="threat-table">
                  <thead><tr><th>Threat</th><th>Severity</th><th>Score</th><th>MITRE Tactic</th><th>Detected</th></tr></thead>
                  <tbody>
                    {report.top_threats.map((t, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{t.title}</td>
                        <td><span className={`severity-badge ${t.severity}`}>{t.severity}</span></td>
                        <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 12 }}>{t.score?.toFixed(1) || '—'}</td>
                        <td style={{ color: 'var(--accent-purple)' }}>{t.mitre_tactic || '—'}</td>
                        <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 11 }}>
                          {t.detected_at ? new Date(t.detected_at).toLocaleDateString() : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
