import { useState } from 'react';
import { FileText, Download, Calendar, BarChart2, Shield, AlertTriangle, TrendingUp, Clock, Activity } from 'lucide-react';
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

// ─── SVG Line Graph ───────────────────────────────────────────
function SchedulerLineGraph({ scanHistory }) {
  if (!scanHistory || scanHistory.length < 2) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
        Need at least 2 scan data points to render the graph.
      </div>
    );
  }

  const W = 700, H = 260, PAD_L = 50, PAD_R = 30, PAD_T = 20, PAD_B = 50;
  const gw = W - PAD_L - PAD_R;
  const gh = H - PAD_T - PAD_B;

  // Reverse so oldest is first
  const data = [...scanHistory].reverse();
  const maxRisk = Math.max(...data.map(d => d.riskScore), 100);
  const minRisk = 0;

  const points = data.map((d, i) => ({
    x: PAD_L + (i / (data.length - 1)) * gw,
    y: PAD_T + gh - ((d.riskScore - minRisk) / (maxRisk - minRisk)) * gh,
    risk: d.riskScore,
    threats: d.threatsCreated,
    time: new Date(d.timestamp).toLocaleTimeString(),
    error: d.error,
  }));

  const pathD = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
  // Fill area
  const areaD = pathD + ` L ${points[points.length - 1].x} ${PAD_T + gh} L ${points[0].x} ${PAD_T + gh} Z`;

  // Y axis labels
  const yLabels = [0, 25, 50, 75, 100].map(v => ({
    value: v,
    y: PAD_T + gh - (v / maxRisk) * gh,
  }));

  // X axis labels (show up to 8)
  const step = Math.max(1, Math.floor(data.length / 8));
  const xLabels = data.filter((_, i) => i % step === 0 || i === data.length - 1).map((d, idx) => {
    const originalIdx = data.indexOf(d);
    return {
      label: new Date(d.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      x: PAD_L + (originalIdx / (data.length - 1)) * gw,
    };
  });

  const riskColor = (score) => {
    if (score >= 75) return '#FF2E63';
    if (score >= 50) return '#F59E0B';
    if (score >= 25) return '#378ADD';
    return '#22C55E';
  };

  return (
    <div style={{ overflowX: 'auto' }}>
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', maxWidth: W, height: 'auto' }}>
        {/* Grid lines */}
        {yLabels.map((yl, i) => (
          <g key={i}>
            <line x1={PAD_L} y1={yl.y} x2={W - PAD_R} y2={yl.y}
              stroke="rgba(255,255,255,0.04)" strokeWidth={1} />
            <text x={PAD_L - 8} y={yl.y + 4} textAnchor="end"
              fill="#4B5563" fontSize={10} fontFamily="'JetBrains Mono', monospace">
              {yl.value}
            </text>
          </g>
        ))}

        {/* X axis labels */}
        {xLabels.map((xl, i) => (
          <text key={i} x={xl.x} y={H - 10} textAnchor="middle"
            fill="#4B5563" fontSize={9} fontFamily="'JetBrains Mono', monospace">
            {xl.label}
          </text>
        ))}

        {/* Y axis title */}
        <text x={12} y={PAD_T + gh / 2} textAnchor="middle"
          fill="#6B7280" fontSize={10} fontWeight={600}
          transform={`rotate(-90, 12, ${PAD_T + gh / 2})`}>
          Risk Score
        </text>

        {/* Area fill with gradient */}
        <defs>
          <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#00A3FF" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#00A3FF" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        <path d={areaD} fill="url(#riskGradient)" />

        {/* Line */}
        <path d={pathD} fill="none" stroke="#00A3FF" strokeWidth={2.5}
          strokeLinecap="round" strokeLinejoin="round" />

        {/* Data points */}
        {points.map((p, i) => (
          <g key={i}>
            <circle cx={p.x} cy={p.y} r={4} fill={p.error ? '#FF2E63' : riskColor(p.risk)}
              stroke="rgba(15,23,42,0.8)" strokeWidth={2} />
            {/* Tooltip on hover — simple title attribute */}
            <circle cx={p.x} cy={p.y} r={10} fill="transparent" style={{ cursor: 'pointer' }}>
              <title>{`${p.time}\nRisk: ${p.risk}\nThreats: +${p.threats}${p.error ? '\n⚠ Error' : ''}`}</title>
            </circle>
          </g>
        ))}
      </svg>
    </div>
  );
}

// ─── Scheduler Report Panel ───────────────────────────────────
function SchedulerReport({ scheduler }) {
  const history = scheduler?.scanHistory || [];
  const successfulScans = history.filter(h => !h.error);
  const failedScans = history.filter(h => h.error);
  const avgRisk = successfulScans.length > 0
    ? Math.round(successfulScans.reduce((sum, s) => sum + s.riskScore, 0) / successfulScans.length)
    : 0;
  const totalThreats = successfulScans.reduce((sum, s) => sum + s.threatsCreated, 0);
  const maxRisk = successfulScans.length > 0 ? Math.max(...successfulScans.map(s => s.riskScore)) : 0;
  const minRisk = successfulScans.length > 0 ? Math.min(...successfulScans.map(s => s.riskScore)) : 0;

  // Calculate elapsed time
  const startedAt = scheduler?.startedAt;
  const stoppedAt = scheduler?.stoppedAt || (scheduler?.active ? Date.now() : null);
  let elapsedStr = '—';
  if (startedAt && stoppedAt) {
    const ms = stoppedAt - startedAt;
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (h > 0) elapsedStr = `${h}h ${m}m ${sec}s`;
    else if (m > 0) elapsedStr = `${m}m ${sec}s`;
    else elapsedStr = `${sec}s`;
  }

  const intervalLabel = (() => {
    const ms = scheduler?.intervalMs;
    if (!ms) return '—';
    if (ms < 60000) return `${ms / 1000}s`;
    if (ms < 3600000) return `${ms / 60000}m`;
    return `${ms / 3600000}h`;
  })();

  if (history.length === 0) {
    return (
      <div className="panel" style={{ padding: 60, textAlign: 'center' }}>
        <Clock size={52} color="var(--text-muted)" style={{ marginBottom: 20 }} />
        <div style={{ color: 'var(--text-muted)', fontSize: 15, marginBottom: 8 }}>
          No scheduler data available
        </div>
        <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>
          Start the Scan Scheduler from the header to begin automated scanning.
          Reports will be generated from the collected scan data.
        </div>
      </div>
    );
  }

  return (
    <div className="stagger">
      {/* Report Header */}
      <div className="panel glass" style={{ marginBottom: 20, borderColor: 'rgba(139,92,246,0.3)' }}>
        <div className="panel-body" style={{ padding: 28 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                <Clock size={28} color="#8B5CF6" />
                <h2 style={{ fontSize: 20, fontWeight: 800 }}>Automated Scan Scheduler Report</h2>
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                Target: <span style={{ color: '#00A3FF', fontFamily: "'JetBrains Mono', monospace" }}>{scheduler?.domain || '—'}</span>
                {' · '}Interval: {intervalLabel}
                {' · '}Status: {scheduler?.active ? (
                  <span style={{ color: '#22C55E' }}>● Active</span>
                ) : (
                  <span style={{ color: '#F59E0B' }}>● Stopped</span>
                )}
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
                {startedAt && `Started: ${new Date(startedAt).toLocaleString()}`}
                {stoppedAt && !scheduler?.active && ` · Stopped: ${new Date(stoppedAt).toLocaleString()}`}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Metrics */}
      <div className="stats-grid stagger" style={{ marginBottom: 20 }}>
        <MetricCard label="Total Scans" value={history.length} color="#8B5CF6" icon={Activity} />
        <MetricCard label="Successful" value={successfulScans.length} color="var(--accent-green)" icon={Shield} />
        <MetricCard label="Failed" value={failedScans.length} color="var(--severity-critical)" icon={AlertTriangle} />
        <MetricCard label="Total Elapsed" value={elapsedStr} color="var(--accent-blue)" icon={Clock} />
        <MetricCard label="Avg Risk Score" value={avgRisk} color="var(--accent-orange)" icon={TrendingUp} />
        <MetricCard label="Total Threats" value={totalThreats} color="var(--severity-high)" icon={AlertTriangle} />
      </div>

      {/* Risk Score Line Graph */}
      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <div className="panel-title"><TrendingUp size={16} /> Risk Score Over Time</div>
        </div>
        <div className="panel-body">
          <SchedulerLineGraph scanHistory={history} />
        </div>
      </div>

      {/* Risk Range */}
      <div className="content-grid" style={{ marginBottom: 20 }}>
        <div className="panel">
          <div className="panel-header"><div className="panel-title"><BarChart2 size={16} /> Risk Score Range</div></div>
          <div className="panel-body">
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 28, fontWeight: 900, color: '#22C55E' }}>{minRisk}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Minimum</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 28, fontWeight: 900, color: '#F59E0B' }}>{avgRisk}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Average</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 28, fontWeight: 900, color: '#FF2E63' }}>{maxRisk}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Maximum</div>
              </div>
            </div>
            <div style={{ height: 8, background: 'rgba(255,255,255,0.05)', borderRadius: 4, overflow: 'hidden', position: 'relative' }}>
              <div style={{
                position: 'absolute',
                left: `${minRisk}%`,
                width: `${Math.max(maxRisk - minRisk, 2)}%`,
                height: '100%',
                background: 'linear-gradient(90deg, #22C55E, #F59E0B, #FF2E63)',
                borderRadius: 4,
                transition: 'all 0.8s ease',
              }} />
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><div className="panel-title"><Shield size={16} /> Scheduler Summary</div></div>
          <div className="panel-body">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {[
                { label: 'Scans Performed', value: `${history.length} scans in ${elapsedStr}`, color: '#8B5CF6' },
                { label: 'Success Rate', value: `${history.length > 0 ? Math.round((successfulScans.length / history.length) * 100) : 0}%`, color: '#22C55E' },
                { label: 'Threats per Scan', value: successfulScans.length > 0 ? (totalThreats / successfulScans.length).toFixed(1) : '0', color: '#F59E0B' },
                { label: 'Scan Interval', value: intervalLabel, color: '#00A3FF' },
              ].map((item, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: i < 3 ? '1px solid rgba(255,255,255,0.04)' : 'none' }}>
                  <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{item.label}</span>
                  <span style={{ fontSize: 13, fontWeight: 700, color: item.color, fontFamily: "'JetBrains Mono', monospace" }}>{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Scan Log Table */}
      <div className="panel">
        <div className="panel-header"><div className="panel-title"><Activity size={16} /> Full Scan Log</div></div>
        <div className="panel-body no-pad">
          <table className="threat-table">
            <thead><tr><th>#</th><th>Timestamp</th><th>Status</th><th>Risk Score</th><th>Threats Created</th></tr></thead>
            <tbody>
              {history.map((entry, i) => (
                <tr key={i}>
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 12, color: '#4B5563' }}>{history.length - i}</td>
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 11 }}>
                    {new Date(entry.timestamp).toLocaleString()}
                  </td>
                  <td>
                    {entry.error ? (
                      <span className="severity-badge critical">FAILED</span>
                    ) : (
                      <span className="severity-badge" style={{ background: 'rgba(34,197,94,0.1)', color: '#22C55E', border: '1px solid rgba(34,197,94,0.3)' }}>SUCCESS</span>
                    )}
                  </td>
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 13, fontWeight: 700, color: entry.riskScore >= 75 ? '#FF2E63' : entry.riskScore >= 50 ? '#F59E0B' : '#22C55E' }}>
                    {entry.error ? '—' : entry.riskScore}
                  </td>
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 12 }}>
                    {entry.error ? '—' : `+${entry.threatsCreated}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ─── Main ReportsView ─────────────────────────────────────────
export default function ReportsView({ scheduler }) {
  const { addToast } = useToast();
  const [days, setDays] = useState(7);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [activeTab, setActiveTab] = useState('regular');

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

  const hasSchedulerData = scheduler?.scanHistory?.length > 0;

  return (
    <div className="fade-in">
      {/* Tab Switcher */}
      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-body" style={{ padding: '0' }}>
          <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <button
              onClick={() => setActiveTab('regular')}
              style={{
                background: 'none', border: 'none', cursor: 'pointer',
                padding: '14px 24px', fontSize: 13, fontWeight: 600,
                color: activeTab === 'regular' ? '#00A3FF' : '#6B7280',
                borderBottom: `2px solid ${activeTab === 'regular' ? '#00A3FF' : 'transparent'}`,
                transition: 'all 0.2s', display: 'flex', alignItems: 'center', gap: 8,
              }}
            >
              <FileText size={14} /> Executive Report
            </button>
            <button
              onClick={() => setActiveTab('scheduler')}
              style={{
                background: 'none', border: 'none', cursor: 'pointer',
                padding: '14px 24px', fontSize: 13, fontWeight: 600,
                color: activeTab === 'scheduler' ? '#8B5CF6' : '#6B7280',
                borderBottom: `2px solid ${activeTab === 'scheduler' ? '#8B5CF6' : 'transparent'}`,
                transition: 'all 0.2s', display: 'flex', alignItems: 'center', gap: 8,
                position: 'relative',
              }}
            >
              <Clock size={14} /> Scheduler Report
              {hasSchedulerData && (
                <span style={{
                  background: '#8B5CF6', color: '#000', borderRadius: 10,
                  padding: '1px 7px', fontSize: 10, fontWeight: 700,
                }}>
                  {scheduler.scanHistory.length}
                </span>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Regular Report Tab */}
      {activeTab === 'regular' && (
        <>
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
        </>
      )}

      {/* Scheduler Report Tab */}
      {activeTab === 'scheduler' && (
        <SchedulerReport scheduler={scheduler} />
      )}
    </div>
  );
}
