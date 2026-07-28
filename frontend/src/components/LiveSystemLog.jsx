import { useEffect, useState } from 'react';
import { Terminal, Wifi, WifiOff } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';

const EVENT_TYPE_META = {
  threat_detected: { color: 'var(--severity-critical)', prefix: '[THREAT]', symbol: '⚠' },
  scan_complete: { color: 'var(--accent-blue)', prefix: '[SCAN]', symbol: '◉' },
  incident_created: { color: 'var(--severity-high)', prefix: '[INCIDENT]', symbol: '⚡' },
  system_event: { color: 'var(--accent-cyan)', prefix: '[SYSTEM]', symbol: '→' },
  connected: { color: 'var(--accent-green)', prefix: '[WS]', symbol: '✓' },
};

const FALLBACK_EVENTS = [
  { type: 'system_event', level: 'info', message: 'OSINT correlation engine initialized', detail: 'Shodan, VT, OTX active' },
  { type: 'system_event', level: 'info', message: 'LSTM threat predictor loaded', detail: 'v2.0 numpy engine' },
  { type: 'system_event', level: 'info', message: 'MITRE ATT&CK matrix loaded', detail: '14 tactics, 150+ techniques' },
  { type: 'system_event', level: 'warning', message: 'Anomaly threshold crossed', detail: 'Autoencoder score 0.91' },
  { type: 'threat_detected', data: { title: 'Reconnaissance scan detected', severity: 'medium' }, message: 'Reconnaissance scan detected' },
  { type: 'system_event', level: 'info', message: 'Kill-chain engine ready', detail: 'Phase prediction active' },
  { type: 'system_event', level: 'info', message: 'Playbook generator initialized', detail: '10 templates loaded' },
];

function EventLine({ event, index }) {
  const meta = EVENT_TYPE_META[event.type] || EVENT_TYPE_META.system_event;
  const message = event.message || event.data?.title || JSON.stringify(event).slice(0, 60);
  const detail = event.detail || event.data?.target || event.data?.severity || '';
  const level = event.level || event.data?.severity || 'info';

  const levelColor = {
    critical: 'var(--severity-critical)',
    error: 'var(--severity-critical)',
    warning: 'var(--severity-high)',
    info: meta.color,
  }[level] || meta.color;

  return (
    <div className="log-line" style={{ animationDelay: `${index * 0.05}s` }}>
      <span className="log-time">{new Date().toLocaleTimeString('en', { hour12: false })}</span>
      <span className="log-symbol" style={{ color: levelColor }}>{meta.symbol}</span>
      <span className="log-prefix" style={{ color: levelColor }}>{meta.prefix}</span>
      <span className="log-message">{message}</span>
      {detail && <span className="log-detail">— {detail}</span>}
    </div>
  );
}

export default function LiveSystemLog() {
  const { connected, events } = useWebSocket();
  const [displayEvents, setDisplayEvents] = useState([]);

  useEffect(() => {
    if (events.length > 0) {
      setDisplayEvents(events.slice(0, 20));
    } else {
      // Show animated fallback events when not connected
      const interval = setInterval(() => {
        setDisplayEvents(prev => {
          const next = FALLBACK_EVENTS[prev.length % FALLBACK_EVENTS.length];
          return [{ ...next, id: Date.now() }, ...prev].slice(0, 20);
        });
      }, 2500);
      return () => clearInterval(interval);
    }
  }, [events]);

  return (
    <div className="panel" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div className="panel-header">
        <div className="panel-title">
          <Terminal size={16} /> Live System Log
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
          {connected ? (
            <><Wifi size={12} color="var(--accent-green)" />
              <span style={{ color: 'var(--accent-green)' }}>LIVE</span></>
          ) : (
            <><WifiOff size={12} color="var(--text-muted)" />
              <span style={{ color: 'var(--text-muted)' }}>DEMO</span></>
          )}
        </div>
      </div>
      <div className="log-container">
        {displayEvents.map((evt, i) => (
          <EventLine key={evt.id || i} event={evt} index={i} />
        ))}
        {displayEvents.length === 0 && (
          <div style={{ padding: 16, color: 'var(--text-muted)', fontSize: 12 }}>
            Awaiting events...
          </div>
        )}
      </div>
    </div>
  );
}
