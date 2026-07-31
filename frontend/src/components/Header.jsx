import { RefreshCw, Scan, Download } from 'lucide-react';
import { api } from '../api';

const VIEW_TITLES = {
  posture: ['Security Posture', 'AI-driven executive intelligence summary'],
  dashboard: ['SOC Dashboard', 'Real-time threat overview'],
  threats: ['Active Threats', 'Detected threats with MITRE mapping'],
  incidents: ['Incident Response', 'Open incidents and playbooks'],
  scanner: ['OSINT Scanner', 'Multi-source intelligence gathering'],
  predictions: ['AI Predictions', 'LSTM threat forecasting engine'],
  anomalies: ['Anomaly Detection', 'Zero-day pattern recognition'],
  mitre: ['MITRE ATT&CK Matrix', 'Tactic and technique coverage'],
  killchain: ['Kill Chain Analysis', 'Attack progression tracking'],
  geomap: ['Threat Geolocation', 'Global attack source map'],
  playbooks: ['Response Playbooks', 'AI-generated remediation guides'],
  history: ['System History', 'Past scan sessions and threat archives'],
};

export default function Header({ activeView, onRefresh, onScan, onNewSession }) {
  const [title, subtitle] = VIEW_TITLES[activeView] || ['ITAP', 'Integrated Threat Assessment Platform'];
  return (
    <header className="header">
      <div className="header-left">
        <div>
          <div className="header-title">{title}</div>
          <div className="header-subtitle">{subtitle}</div>
        </div>
      </div>
      <div className="header-right">
        <button className="header-btn" onClick={() => api.downloadReport(7)} title="Export Report">
          <Download size={14} /> Export PDF
        </button>
        <button className="header-btn" onClick={onRefresh} title="Refresh data">
          <RefreshCw size={14} /> Refresh
        </button>
        <button className="header-btn" onClick={onNewSession} title="Archive current data and start fresh">
          <RefreshCw size={14} /> New Session
        </button>
        <button className="header-btn primary" onClick={onScan}>
          <Scan size={14} /> New Scan
        </button>
      </div>
    </header>
  );
}
