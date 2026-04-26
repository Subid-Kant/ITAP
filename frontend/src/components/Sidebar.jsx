import { Shield, Activity, AlertTriangle, Target, Brain, Eye, LayoutDashboard, Crosshair, BookOpen, Bell, Settings, Map, Clock, Grid3X3 } from 'lucide-react';

const NAV_ITEMS = [
  { section: 'Intelligence' },
  { id: 'posture', label: 'Security Posture', icon: Shield },
  { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },
  { id: 'threats', label: 'Active Threats', icon: AlertTriangle, badge: true },
  { id: 'incidents', label: 'Incidents', icon: Bell },
  { section: 'Intelligence' },
  { id: 'scanner', label: 'OSINT Scanner', icon: Crosshair },
  { id: 'predictions', label: 'AI Predictions', icon: Brain },
  { id: 'anomalies', label: 'Anomaly Detection', icon: Activity },
  { section: 'Analysis' },
  { id: 'mitre', label: 'MITRE ATT&CK', icon: Grid3X3 },
  { id: 'killchain', label: 'Kill Chain', icon: Target },
  { id: 'geomap', label: 'Threat Map', icon: Map },
  { section: 'Response' },
  { id: 'playbooks', label: 'Playbooks', icon: BookOpen },
];

export default function Sidebar({ activeView, setActiveView, stats }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <h1>⚡ ITAP</h1>
        <p>Integrated Threat Assessment</p>
      </div>
      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item, i) =>
          item.section ? (
            <div key={i} className="nav-section-title">{item.section}</div>
          ) : (
            <div
              key={item.id}
              className={`nav-item ${activeView === item.id ? 'active' : ''}`}
              onClick={() => setActiveView(item.id)}
            >
              <item.icon size={18} />
              <span>{item.label}</span>
              {item.badge && stats?.critical_threats > 0 && (
                <span className="nav-badge">{stats.critical_threats}</span>
              )}
            </div>
          )
        )}
      </nav>
      <div className="sidebar-status">
        <div className="status-indicator">
          <span className="status-dot" />
          <span>System Operational</span>
        </div>
      </div>
    </aside>
  );
}
