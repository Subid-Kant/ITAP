import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Activity, Zap, Cpu } from 'lucide-react';

const LOG_MESSAGES = [
  "Analyzing ingress traffic on port 443...",
  "LSTM model detecting pattern similarity to APT28...",
  "Correlating OSINT data from VirusTotal and Shodan...",
  "Anomaly detected in lateral movement patterns (Confidence: 89%)...",
  "NVD database sync complete. 12 new CVEs categorized...",
  "MITRE ATT&CK mapping updated: Technique T1059.001 detected...",
  "Autoencoder training delta stable: 0.002% variance...",
  "Scrubbing false positives from reputation feed...",
  "Threat DNA fingerprint generated: 8f2b...c91e...",
  "Geo-locating source IP 194.26.135.21 (Russia, Moscow)...",
  "Response playbook generated for Remote Code Execution...",
  "Security Posture Score recalculated: 94.2%...",
  "SIEM integration heartbeat: Operational...",
  "DDoS mitigation absorbing 45Gbps peak flow...",
  "Scanning target infrastructure for open S3 buckets...",
];

export default function LiveSystemLog() {
  const [logs, setLogs] = useState([]);
  const logEndRef = useRef(null);

  useEffect(() => {
    // Initial logs
    setLogs(LOG_MESSAGES.slice(0, 5).map((m, i) => ({
      id: i,
      msg: m,
      time: new Date(Date.now() - (5 - i) * 1000).toLocaleTimeString(),
      type: i % 4 === 0 ? 'alert' : 'info'
    })));

    const interval = setInterval(() => {
      const msg = LOG_MESSAGES[Math.floor(Math.random() * LOG_MESSAGES.length)];
      setLogs(prev => [...prev.slice(-14), {
        id: Date.now(),
        msg,
        time: new Date().toLocaleTimeString(),
        type: Math.random() > 0.8 ? 'alert' : 'info'
      }]);
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="panel glass" style={{ height: '100%', minHeight: '300px', display: 'flex', flexDirection: 'column' }}>
      <div className="panel-header">
        <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Terminal size={16} color="var(--accent-cyan)" />
          ITAP Neural Engine Stream
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
            <span className="status-badge" style={{ fontSize: 10 }}>● LIVE</span>
        </div>
      </div>
      <div className="panel-body" style={{ flex: 1, overflowY: 'auto', padding: '10px 15px', fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: 'var(--text-secondary)' }}>
        {logs.map((log) => (
          <div key={log.id} style={{ marginBottom: '6px', borderLeft: log.type === 'alert' ? '2px solid var(--accent-red)' : '2px solid transparent', paddingLeft: '8px' }}>
            <span style={{ color: 'var(--accent-blue)', marginRight: '8px' }}>[{log.time}]</span>
            <span style={{ color: log.type === 'alert' ? 'var(--accent-red)' : 'inherit' }}>{log.msg}</span>
          </div>
        ))}
        <div ref={logEndRef} />
      </div>
      <div style={{ padding: '8px 15px', borderTop: '1px solid rgba(255,255,255,0.05)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: 12, fontSize: 10 }}>
             <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><Activity size={10} /> 12.4k req/s</span>
             <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><Cpu size={10} /> 14% Load</span>
          </div>
          <div style={{ fontSize: 10, color: 'var(--accent-cyan)' }}>MODEL: ITAP-GEN-2</div>
      </div>
    </div>
  );
}
