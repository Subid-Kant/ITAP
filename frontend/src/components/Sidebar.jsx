import { useState } from 'react';
import { Shield, Activity, AlertTriangle, Target, Brain, Eye, LayoutDashboard, Crosshair, BookOpen, Bell, Map, Grid3X3, Search, FileText, LogOut, User, ChevronLeft, ChevronRight, Wifi } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';

const NAV_ITEMS = [
  { section: 'Overview' },
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
  { id: 'ioc', label: 'IOC Workbench', icon: Search },
  { section: 'Response' },
  { id: 'playbooks', label: 'Playbooks', icon: BookOpen },
  { id: 'reports', label: 'Reports', icon: FileText },
  { section: 'System' },
  { id: 'history', label: 'History', icon: FileText },
];

export default function Sidebar({ activeView, setActiveView, stats, user, onLogout }) {
  const [collapsed, setCollapsed] = useState(false);
  const { connected } = useWebSocket();

  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      {/* Brand */}
      <div className="sidebar-brand">
        {!collapsed && (
          <>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
              <Shield size={20} color="var(--accent-blue)" strokeWidth={1.5} />
              <h1>ITAP</h1>
            </div>
            <p>Integrated Threat Assessment</p>
          </>
        )}
        {collapsed && <Shield size={22} color="var(--accent-blue)" strokeWidth={1.5} />}
      </div>

      {/* Collapse toggle */}
      <button className="sidebar-collapse-btn" onClick={() => setCollapsed(c => !c)}>
        {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
      </button>

      {/* Nav */}
      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item, i) =>
          item.section ? (
            !collapsed && <div key={i} className="nav-section-title">{item.section}</div>
          ) : (
            <div
              key={item.id}
              id={`nav-${item.id}`}
              className={`nav-item ${activeView === item.id ? 'active' : ''}`}
              onClick={() => setActiveView(item.id)}
              title={collapsed ? item.label : ''}
            >
              <item.icon size={18} />
              {!collapsed && <span>{item.label}</span>}
              {item.badge && stats?.critical_threats > 0 && (
                <span className="nav-badge">{stats.critical_threats}</span>
              )}
            </div>
          )
        )}
      </nav>

      {/* Status & User */}
      <div className="sidebar-status">
        {!collapsed && (
          <>
            <div className="status-indicator">
              <span className={`status-dot ${connected ? '' : 'offline'}`} />
              <span style={{ fontSize: 11 }}>{connected ? 'WS Live' : 'WS Offline'}</span>
            </div>
            {user && (
              <div className="sidebar-user">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 0 }}>
                  <div className="user-avatar">
                    <User size={12} />
                  </div>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, truncate: true, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {user.username}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                      {user.role}
                    </div>
                  </div>
                </div>
                <button className="icon-btn" onClick={onLogout} title="Sign out">
                  <LogOut size={14} />
                </button>
              </div>
            )}
          </>
        )}
        {collapsed && onLogout && (
          <button className="icon-btn" onClick={onLogout} title="Sign out" style={{ margin: '0 auto' }}>
            <LogOut size={14} />
          </button>
        )}
      </div>
    </aside>
  );
}
