import { useState, useEffect, useRef, useMemo } from 'react';
import { Command, Search, Crosshair, LayoutDashboard, Shield, Activity, Brain,
  Grid3X3, Link2, Globe, BookOpen, FileText, History, Map, Zap, X } from 'lucide-react';

const COMMANDS = [
  { id: 'dashboard',   label: 'SOC Dashboard',        icon: LayoutDashboard, desc: 'Overview, stats & kill chain map',    view: 'dashboard',   shortcut: '1' },
  { id: 'scanner',     label: 'OSINT Deep Scanner',   icon: Crosshair,       desc: 'Scan a domain for vulnerabilities',   view: 'scanner',     shortcut: '2' },
  { id: 'threats',     label: 'Active Threats',        icon: Shield,          desc: 'View and manage detected threats',    view: 'threats',     shortcut: '3' },
  { id: 'incidents',   label: 'Incidents',             icon: Activity,        desc: 'SOC incident response queue',         view: 'incidents',   shortcut: '4' },
  { id: 'predictions', label: 'AI Predictions',        icon: Brain,           desc: 'Machine learning threat predictions', view: 'predictions', shortcut: '5' },
  { id: 'mitre',       label: 'MITRE ATT&CK Matrix',  icon: Grid3X3,         desc: 'Attack tactic coverage heatmap',      view: 'mitre',       shortcut: '6' },
  { id: 'killchain',   label: 'Kill Chain Analysis',   icon: Link2,           desc: 'Real-time attack progression view',   view: 'killchain',   shortcut: '7' },
  { id: 'geomap',      label: 'Threat Geo Map',        icon: Globe,           desc: 'Global threat origin visualization',  view: 'geomap',      shortcut: '8' },
  { id: 'ioc',         label: 'IOC Workbench',         icon: Zap,             desc: 'Indicator of compromise analysis',    view: 'ioc',         shortcut: '9' },
  { id: 'playbooks',   label: 'Playbooks',             icon: BookOpen,        desc: 'Response playbook generator',         view: 'playbooks',   shortcut: '0' },
  { id: 'reports',     label: 'Reports',               icon: FileText,        desc: 'Generate and download SOC reports',   view: 'reports'  },
  { id: 'history',     label: 'Scan History',          icon: History,         desc: 'Past scans and archived sessions',    view: 'history'  },
  { id: 'posture',     label: 'Security Posture',      icon: Map,             desc: 'Overall security health assessment',  view: 'posture'  },
  { id: 'anomalies',   label: 'Anomaly Detection',     icon: Activity,        desc: 'Autoencoder anomaly analysis',        view: 'anomalies' },
];

export default function CommandPalette({ open, onClose, onNavigate }) {
  const [query, setQuery] = useState('');
  const inputRef = useRef(null);
  const [selected, setSelected] = useState(0);

  useEffect(() => {
    if (open) {
      setQuery('');
      setSelected(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  const filtered = useMemo(() => {
    if (!query.trim()) return COMMANDS;
    const q = query.toLowerCase();
    return COMMANDS.filter(c =>
      c.label.toLowerCase().includes(q) ||
      c.desc.toLowerCase().includes(q) ||
      c.id.toLowerCase().includes(q)
    );
  }, [query]);

  const handleKeyDown = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, filtered.length - 1)); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)); }
    if (e.key === 'Enter')     { e.preventDefault(); if (filtered[selected]) execute(filtered[selected]); }
    if (e.key === 'Escape')    { onClose(); }
  };

  const execute = (cmd) => {
    if (cmd.view) onNavigate(cmd.view);
    onClose();
  };

  if (!open) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
          backdropFilter: 'blur(6px)', zIndex: 9998,
          animation: 'fadeInBackdrop 0.15s ease',
        }}
      />

      {/* Palette */}
      <div style={{
        position: 'fixed', top: '15%', left: '50%', transform: 'translateX(-50%)',
        width: '90%', maxWidth: 600, zIndex: 9999,
        background: 'rgba(10, 14, 23, 0.95)',
        border: '1px solid rgba(55,138,221,0.35)',
        borderRadius: 14, overflow: 'hidden',
        boxShadow: '0 24px 80px rgba(0,0,0,0.7), 0 0 0 1px rgba(55,138,221,0.1)',
        animation: 'slideInPalette 0.15s cubic-bezier(0.16, 1, 0.3, 1)',
      }}>
        {/* Search input */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <Search size={16} color="#378ADD" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => { setQuery(e.target.value); setSelected(0); }}
            onKeyDown={handleKeyDown}
            placeholder="Search views, commands, or domains..."
            style={{
              flex: 1, background: 'none', border: 'none', outline: 'none',
              color: '#F0EFE9', fontSize: 15, fontFamily: "'Inter', sans-serif",
            }}
          />
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <kbd style={{ fontSize: 10, color: '#4B5563', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)', padding: '2px 6px', borderRadius: 4 }}>⌘K</kbd>
            <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#4B5563' }}>
              <X size={14} />
            </button>
          </div>
        </div>

        {/* Results */}
        <div style={{ maxHeight: 380, overflowY: 'auto', padding: '6px 0' }}>
          {filtered.length === 0 ? (
            <div style={{ padding: '20px', textAlign: 'center', color: '#4B5563', fontSize: 13 }}>
              No results for "{query}"
            </div>
          ) : (
            filtered.map((cmd, i) => {
              const Icon = cmd.icon;
              const isSelected = i === selected;
              return (
                <div
                  key={cmd.id}
                  onClick={() => execute(cmd)}
                  onMouseEnter={() => setSelected(i)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 12,
                    padding: '9px 16px', cursor: 'pointer',
                    background: isSelected ? 'rgba(55,138,221,0.1)' : 'transparent',
                    borderLeft: `2px solid ${isSelected ? '#378ADD' : 'transparent'}`,
                    transition: 'all 0.1s ease',
                  }}
                >
                  <div style={{
                    width: 30, height: 30, borderRadius: 8, flexShrink: 0,
                    background: isSelected ? 'rgba(55,138,221,0.15)' : 'rgba(255,255,255,0.04)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <Icon size={14} color={isSelected ? '#378ADD' : '#6B7280'} />
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 13, fontWeight: 500, color: isSelected ? '#F0EFE9' : '#B4B2A9' }}>
                      {cmd.label}
                    </div>
                    <div style={{ fontSize: 11, color: '#4B5563' }}>{cmd.desc}</div>
                  </div>
                  {cmd.shortcut && (
                    <kbd style={{ fontSize: 10, color: '#4B5563', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', padding: '2px 6px', borderRadius: 4 }}>
                      {cmd.shortcut}
                    </kbd>
                  )}
                  {isSelected && (
                    <span style={{ fontSize: 10, color: '#378ADD' }}>↵</span>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: '8px 16px', borderTop: '1px solid rgba(255,255,255,0.05)', display: 'flex', gap: 16 }}>
          {[['↑↓', 'Navigate'], ['↵', 'Open'], ['Esc', 'Close']].map(([k, l]) => (
            <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <kbd style={{ fontSize: 10, color: '#4B5563', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', padding: '1px 5px', borderRadius: 3 }}>{k}</kbd>
              <span style={{ fontSize: 10, color: '#4B5563' }}>{l}</span>
            </div>
          ))}
        </div>
      </div>

      <style>{`
        @keyframes fadeInBackdrop { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slideInPalette {
          from { opacity: 0; transform: translateX(-50%) translateY(-10px) scale(0.97); }
          to { opacity: 1; transform: translateX(-50%) translateY(0) scale(1); }
        }
      `}</style>
    </>
  );
}
