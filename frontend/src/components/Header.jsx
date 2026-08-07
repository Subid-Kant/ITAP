import { RefreshCw, Scan, Download, Command } from 'lucide-react';
import { api } from '../api';

const VIEW_TITLES = {
  posture:     ['Security Posture',        'AI-driven executive intelligence summary'],
  dashboard:   ['SOC Dashboard',           'Real-time threat overview'],
  threats:     ['Active Threats',          'Detected threats with MITRE mapping'],
  incidents:   ['Incident Response',       'Open incidents and playbooks'],
  scanner:     ['OSINT Deep Scanner',      'Multi-source vulnerability intelligence'],
  predictions: ['AI Predictions',          'LSTM threat forecasting engine'],
  anomalies:   ['Anomaly Detection',       'Zero-day pattern recognition'],
  mitre:       ['MITRE ATT&CK Matrix',     'Tactic and technique coverage'],
  killchain:   ['Kill Chain Analysis',     'Attack progression tracking'],
  geomap:      ['Threat Geolocation',      'Global attack source map'],
  playbooks:   ['Response Playbooks',      'AI-generated remediation guides'],
  history:     ['System History',          'Past scan sessions and threat archives'],
  ioc:         ['IOC Workbench',           'Indicator of compromise analysis'],
  reports:     ['Reports',                 'Generate and download SOC reports'],
};

export default function Header({ activeView, onRefresh, onScan, onNewSession, isLive, user, onOpenPalette }) {
  const [title, subtitle] = VIEW_TITLES[activeView] || ['ITAP', 'Integrated Threat Assessment Platform'];

  return (
    <header className="header">
      <div className="header-left">
        <div>
          <div className="header-title">{title}</div>
          <div className="header-subtitle">{subtitle}</div>
        </div>
        {isLive && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#22C55E', background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 20, padding: '3px 10px' }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22C55E', animation: 'pulse 2s ease-in-out infinite' }} />
            LIVE
          </div>
        )}
      </div>

      <div className="header-right">
        {/* Command Palette trigger */}
        {onOpenPalette && (
          <button
            className="header-btn"
            onClick={onOpenPalette}
            title="Open Command Palette (Ctrl+K)"
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Command size={13} />
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Ctrl+K</span>
          </button>
        )}
        <button className="header-btn" onClick={() => api.downloadReport(7)} title="Export Report">
          <Download size={14} /> Export
        </button>
        <button className="header-btn" onClick={onRefresh} title="Refresh data">
          <RefreshCw size={14} /> Refresh
        </button>
        <button className="header-btn" onClick={onNewSession} title="Archive current data and start fresh">
          New Session
        </button>
        <button className="header-btn primary" onClick={onScan}>
          <Scan size={14} /> New Scan
        </button>
      </div>
    </header>
  );
}
