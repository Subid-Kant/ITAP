import { useState, useEffect } from 'react';
import { Bell, Server, Globe, Activity, Cpu, HardDrive } from 'lucide-react';
import { api } from '../api';
import { useAuth } from '../hooks/useAuth';

export default function IncidentsView({ stats }) {
  const { user } = useAuth();
  const isViewer = user?.role === 'viewer';
  const [activeTab, setActiveTab] = useState('server');
  const [serverStats, setServerStats] = useState(null);
  const [globalThreats, setGlobalThreats] = useState(null);

  useEffect(() => {
    const fetchMonitorData = async () => {
      try {
        if (activeTab === 'server') {
          const res = await api.getServerStatus();
          setServerStats(res);
        } else if (activeTab === 'global') {
          const res = await api.getGlobalThreats();
          setGlobalThreats(res);
        }
      } catch (err) {
        console.error("Failed to fetch monitor data", err);
      }
    };
    
    fetchMonitorData();
    const interval = setInterval(fetchMonitorData, 15000); // refresh every 15s
    return () => clearInterval(interval);
  }, [activeTab]);

  const dbIncidents = stats?.recent_incidents || [];
  const serverIncidents = dbIncidents.filter(i => i.source === 'server_monitor');
  const globalIncidents = dbIncidents.filter(i => i.source === 'global_feed');

  return (
    <div className="fade-in">
      
      <div style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
        <button 
          onClick={() => setActiveTab('server')}
          style={{ padding: '8px 16px', background: activeTab === 'server' ? 'rgba(55,138,221,0.2)' : 'transparent', border: `1px solid ${activeTab === 'server' ? '#378ADD' : '#334155'}`, color: '#F0EFE9', borderRadius: 6, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}
        >
          <Server size={16} /> Local Server Monitor
        </button>
        <button 
          onClick={() => setActiveTab('global')}
          style={{ padding: '8px 16px', background: activeTab === 'global' ? 'rgba(55,138,221,0.2)' : 'transparent', border: `1px solid ${activeTab === 'global' ? '#378ADD' : '#334155'}`, color: '#F0EFE9', borderRadius: 6, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}
        >
          <Globe size={16} /> Global Threat Feeds
        </button>
      </div>

      {activeTab === 'server' && (
        <div className="content-grid">
          <div className="panel" style={{ gridColumn: 'span 2' }}>
            <div className="panel-header"><div className="panel-title"><Activity size={16} /> Live Telemetry</div></div>
            <div className="panel-body">
              {serverStats ? (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 15 }}>
                  <div style={{ background: 'rgba(255,255,255,0.02)', padding: 15, borderRadius: 6 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}><span style={{ color: '#8892B0' }}><Cpu size={14} style={{verticalAlign:'middle'}}/> CPU Usage</span><span style={{ color: serverStats.cpu_percent > 80 ? '#FF3B5C' : '#22C55E'}}>{serverStats.cpu_percent}%</span></div>
                    <div style={{ width: '100%', height: 4, background: '#1e293b', borderRadius: 2 }}><div style={{ width: `${serverStats.cpu_percent}%`, height: '100%', background: serverStats.cpu_percent > 80 ? '#FF3B5C' : '#22C55E', borderRadius: 2, transition: 'width 0.3s ease' }}/></div>
                  </div>
                  <div style={{ background: 'rgba(255,255,255,0.02)', padding: 15, borderRadius: 6 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}><span style={{ color: '#8892B0' }}><HardDrive size={14} style={{verticalAlign:'middle'}}/> Memory</span><span style={{ color: serverStats.memory_percent > 80 ? '#FF3B5C' : '#22C55E'}}>{serverStats.memory_percent}%</span></div>
                    <div style={{ width: '100%', height: 4, background: '#1e293b', borderRadius: 2 }}><div style={{ width: `${serverStats.memory_percent}%`, height: '100%', background: serverStats.memory_percent > 80 ? '#FF3B5C' : '#22C55E', borderRadius: 2, transition: 'width 0.3s ease' }}/></div>
                    <div style={{ fontSize: 11, color: '#64748B', marginTop: 4, textAlign: 'right' }}>{serverStats.memory_used_gb} GB / {serverStats.memory_total_gb} GB</div>
                  </div>
                  <div style={{ background: 'rgba(255,255,255,0.02)', padding: 15, borderRadius: 6, gridColumn: 'span 2' }}>
                     <div style={{ color: '#8892B0', marginBottom: 5 }}>Disk Usage: <span style={{ color: serverStats.disk_percent > 85 ? '#FF3B5C' : '#F0EFE9'}}>{serverStats.disk_percent}%</span></div>
                     <div style={{ width: '100%', height: 4, background: '#1e293b', borderRadius: 2 }}><div style={{ width: `${serverStats.disk_percent}%`, height: '100%', background: serverStats.disk_percent > 85 ? '#FF3B5C' : '#378ADD', borderRadius: 2 }}/></div>
                     <div style={{ color: '#8892B0', marginTop: 10 }}>Active Network Connections: <span style={{ color: '#F0EFE9'}}>{serverStats.active_connections}</span></div>
                  </div>
                </div>
              ) : <div className="scanning"><div className="scanning-ring" /></div>}
            </div>
          </div>
          
          <div className="panel" style={{ gridColumn: 'span 2' }}>
            <div className="panel-header"><div className="panel-title"><Bell size={16} /> Server Incidents</div></div>
            <div className="panel-body no-pad" style={{ padding: '15px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {serverIncidents.map((inc, i) => (
                  <div key={i} style={{ background: 'rgba(255,255,255,0.02)', padding: 15, borderRadius: 6, borderLeft: `3px solid ${inc.severity === 'critical' ? '#FF3B5C' : inc.severity === 'high' ? '#F97316' : inc.severity === 'medium' ? '#F59E0B' : '#22C55E'}` }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                      <div style={{ color: '#F0EFE9', fontWeight: 600 }}>{inc.title}</div>
                      <span className={`severity-badge ${inc.severity}`}>{inc.severity}</span>
                    </div>
                    <div style={{ color: '#8892B0', fontSize: 13, marginBottom: 12, lineHeight: 1.5, whiteSpace: 'pre-wrap' }}>{inc.description || 'No description provided.'}</div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: '#64748B' }}>Detected: {new Date(inc.detected_at).toLocaleString()}</div>
                      <div style={{ display: 'flex', gap: 8 }}>
                         <button className="header-btn" style={{ fontSize: 11, padding: '4px 10px' }} disabled={isViewer} title={isViewer ? "Viewer mode restricted" : ""}>Acknowledge</button>
                      </div>
                    </div>
                  </div>
                ))}
                {serverIncidents.length === 0 && <div style={{ padding: 20, textAlign: 'center', color: '#64748B' }}>No local server incidents detected. System operating normally.</div>}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'global' && (
        <div className="content-grid">
          <div className="panel" style={{ gridColumn: 'span 2' }}>
            <div className="panel-header"><div className="panel-title"><Globe size={16} /> Live CISA KEV (Known Exploited Vulnerabilities) Alerts</div></div>
            <div className="panel-body no-pad" style={{ padding: '15px' }}>
               <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {globalIncidents.map((inc, i) => (
                  <div key={i} style={{ background: 'rgba(255,255,255,0.02)', padding: 15, borderRadius: 6, borderLeft: '3px solid #FF3B5C' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                      <div style={{ color: '#F0EFE9', fontWeight: 600 }}>{inc.title}</div>
                      <span className={`severity-badge critical`}>CRITICAL</span>
                    </div>
                    <div style={{ color: '#8892B0', fontSize: 13, marginBottom: 12, lineHeight: 1.5, whiteSpace: 'pre-wrap' }}>{inc.description}</div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: '#64748B' }}>Imported: {new Date(inc.detected_at).toLocaleString()}</div>
                      <div style={{ display: 'flex', gap: 8 }}>
                         <button className="header-btn primary" style={{ fontSize: 11, padding: '4px 10px' }} disabled={isViewer} title={isViewer ? "Viewer mode restricted" : ""}>Review</button>
                      </div>
                    </div>
                  </div>
                ))}
                {!globalThreats && globalIncidents.length === 0 && <div className="scanning"><div className="scanning-ring" /></div>}
                {globalThreats && globalIncidents.length === 0 && <div style={{ padding: 20, textAlign: 'center', color: '#64748B' }}>No critical global incidents matching criteria.</div>}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
