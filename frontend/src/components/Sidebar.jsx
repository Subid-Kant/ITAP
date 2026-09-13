import { useState } from 'react';
import { Shield, Activity, AlertTriangle, Target, Brain, Eye, LayoutDashboard, Crosshair, BookOpen, Bell, Map, Grid3X3, Search, FileText, LogOut, User, ChevronLeft, ChevronRight, Wifi } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import { motion } from 'framer-motion';
import AnimatedButton from './ui/AnimatedButton';

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
      <div className="sidebar-brand" style={{ position: 'relative', height: collapsed ? 'auto' : 76, minHeight: 76, display: 'flex', flexDirection: collapsed ? 'column' : 'row', alignItems: 'center', gap: collapsed ? 16 : 0 }}>
        {!collapsed && (
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
              <Shield size={20} color="var(--accent-blue)" strokeWidth={1.5} style={{ flexShrink: 0 }} />
              <h1>ITAP</h1>
            </div>
            <p>Integrated Threat Assessment</p>
          </div>
        )}
        {collapsed && <Shield size={22} color="var(--accent-blue)" strokeWidth={1.5} />}

        {/* Small theme-matched collapse button */}
        <AnimatedButton
          variant="none"
          onClick={() => setCollapsed(c => !c)}
          style={{
            position: collapsed ? 'relative' : 'absolute',
            right: collapsed ? 'auto' : 16,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
            background: 'var(--bg-card)', border: '1px solid var(--border-primary)',
            color: 'var(--accent-blue)', cursor: 'pointer',
            transition: 'transform var(--transition-fast)'
          }}
          title={collapsed ? "Expand Sidebar" : "Collapse Sidebar"}
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </AnimatedButton>
      </div>

      {/* Nav */}
      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item, i) =>
          item.section ? (
            !collapsed && <div key={i} className="nav-section-title">{item.section}</div>
          ) : (
            <AnimatedButton
              key={item.id}
              id={`nav-${item.id}`}
              variant="none"
              active={activeView === item.id}
              className={`nav-item ${activeView === item.id ? 'active' : ''}`}
              onClick={() => setActiveView(item.id)}
              title={collapsed ? item.label : ''}
              style={{ width: '100%', marginBottom: 2, background: 'transparent', border: 'none' }}
            >
              {activeView === item.id && (
                <motion.div
                  layoutId="sidebar-active"
                  style={{
                    position: 'absolute',
                    left: 0,
                    top: '50%',
                    y: '-50%',
                    height: '60%',
                    width: 3,
                    background: 'var(--accent-blue)',
                    borderRadius: '0 3px 3px 0',
                    zIndex: 0
                  }}
                  transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                />
              )}
              <item.icon size={18} style={{ zIndex: 1, position: 'relative', flexShrink: 0 }} />
              {!collapsed && <span style={{ zIndex: 1, position: 'relative', whiteSpace: 'nowrap' }}>{item.label}</span>}
              {!collapsed && item.badge && stats?.critical_threats > 0 && (
                <span className="nav-badge" style={{ zIndex: 1, position: 'relative' }}>{stats.critical_threats}</span>
              )}
            </AnimatedButton>
          )
        )}
      </nav>

      {/* Status & User */}
      <div className="sidebar-status">
        {!collapsed && (
          <>
            <div className="status-indicator" style={{ whiteSpace: 'nowrap' }}>
              <span className={`status-dot ${connected ? '' : 'offline'}`} />
              <span style={{ fontSize: 11 }}>{connected ? 'WS Live' : 'WS Offline'}</span>
            </div>
            {user && (
              <div className="sidebar-user" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', marginTop: 8, background: 'rgba(255,255,255,0.03)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 0, whiteSpace: 'nowrap' }}>
                  <div className="user-avatar" style={{ flexShrink: 0 }}>
                    <User size={12} />
                  </div>
                  <div style={{ minWidth: 0, overflow: 'hidden' }}>
                    <div style={{ fontSize: 12, fontWeight: 600, textOverflow: 'ellipsis', overflow: 'hidden' }}>
                      {user.username}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                      {user.role}
                    </div>
                  </div>
                </div>
                {onLogout && (
                  <AnimatedButton 
                    className="icon-btn" 
                    onClick={onLogout} 
                    title="Sign out" 
                    style={{ padding: 6, background: 'transparent', flexShrink: 0 }}
                  >
                    <LogOut size={14} />
                  </AnimatedButton>
                )}
              </div>
            )}
          </>
        )}
        {collapsed && onLogout && (
          <AnimatedButton className="icon-btn" onClick={onLogout} title="Sign out" style={{ margin: '0 auto', padding: 6, background: 'transparent' }}>
            <LogOut size={14} />
          </AnimatedButton>
        )}
      </div>
    </aside>
  );
}
