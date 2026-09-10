import { useState, useRef, useEffect } from 'react';
import { Clock, Play, Square, Activity, AlertTriangle, CheckCircle, X, ChevronDown } from 'lucide-react';

const INTERVAL_OPTIONS = [
  { label: 'Every 30 seconds', value: 30000 },
  { label: 'Every 1 minute', value: 60000 },
  { label: 'Every 5 minutes', value: 300000 },
  { label: 'Every 15 minutes', value: 900000 },
  { label: 'Every 30 minutes', value: 1800000 },
  { label: 'Every 1 hour', value: 3600000 },
];

function formatElapsed(ms) {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m ${sec}s`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

export default function SchedulerDropdown({ scheduler, onStart, onStop, onClose }) {
  const [domain, setDomain] = useState(scheduler.domain || '');
  const [intervalMs, setIntervalMs] = useState(scheduler.intervalMs || 60000);
  const dropdownRef = useRef(null);
  const [elapsed, setElapsed] = useState(0);

  // Live elapsed timer
  useEffect(() => {
    if (!scheduler.active || !scheduler.startedAt) return;
    const tick = () => setElapsed(Date.now() - scheduler.startedAt);
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [scheduler.active, scheduler.startedAt]);

  // Close on outside click
  useEffect(() => {
    const handler = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        onClose();
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [onClose]);

  const handleStart = () => {
    if (!domain.trim()) return;
    onStart(domain.trim(), intervalMs);
  };

  const riskColor = (score) => {
    if (score >= 75) return '#FF2E63';
    if (score >= 50) return '#F59E0B';
    if (score >= 25) return '#378ADD';
    return '#22C55E';
  };

  const scanHistory = scheduler.scanHistory || [];

  return (
    <div
      ref={dropdownRef}
      style={{
        position: 'absolute',
        top: '100%',
        right: 0,
        marginTop: 8,
        width: 380,
        background: 'rgba(15, 23, 42, 0.98)',
        backdropFilter: 'blur(20px)',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: 14,
        boxShadow: '0 20px 60px rgba(0,0,0,0.6), 0 0 40px rgba(0,163,255,0.08)',
        zIndex: 1000,
        overflow: 'hidden',
        animation: 'fadeSlideIn 0.2s ease-out',
      }}
    >
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '14px 18px', borderBottom: '1px solid rgba(255,255,255,0.06)',
        background: 'rgba(0,163,255,0.04)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Clock size={15} color="#00A3FF" />
          <span style={{ fontSize: 13, fontWeight: 700, color: '#F0EFE9' }}>Scan Scheduler</span>
        </div>
        <button
          onClick={onClose}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6B7280', padding: 2 }}
        >
          <X size={14} />
        </button>
      </div>

      <div style={{ padding: '16px 18px' }}>
        {/* Status Banner */}
        {scheduler.active && (
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '10px 14px', marginBottom: 14,
            background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)',
            borderRadius: 10,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                width: 8, height: 8, borderRadius: '50%', background: '#22C55E',
                animation: 'pulse 2s ease-in-out infinite',
              }} />
              <span style={{ fontSize: 12, fontWeight: 700, color: '#22C55E' }}>SCHEDULER ACTIVE</span>
            </div>
            <div style={{ display: 'flex', gap: 12, fontSize: 11, color: '#9CA3AF' }}>
              <span>{scheduler.totalScans} scan{scheduler.totalScans !== 1 ? 's' : ''}</span>
              <span>{formatElapsed(elapsed)}</span>
            </div>
          </div>
        )}

        {/* Domain Input */}
        <div style={{ marginBottom: 12 }}>
          <label style={{ fontSize: 11, fontWeight: 600, color: '#6B7280', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 6, display: 'block' }}>
            Target Domain / IP
          </label>
          <input
            type="text"
            value={scheduler.active ? scheduler.domain : domain}
            onChange={e => setDomain(e.target.value)}
            disabled={scheduler.active}
            placeholder="e.g. scanme.nmap.org"
            style={{
              width: '100%', padding: '9px 12px', fontSize: 13,
              background: scheduler.active ? 'rgba(255,255,255,0.02)' : 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8,
              color: '#F0EFE9', outline: 'none', boxSizing: 'border-box',
              fontFamily: "'JetBrains Mono', monospace",
              opacity: scheduler.active ? 0.5 : 1,
            }}
          />
        </div>

        {/* Interval Selector */}
        <div style={{ marginBottom: 16 }}>
          <label style={{ fontSize: 11, fontWeight: 600, color: '#6B7280', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 6, display: 'block' }}>
            Scan Interval
          </label>
          <div style={{ position: 'relative' }}>
            <select
              value={scheduler.active ? scheduler.intervalMs : intervalMs}
              onChange={e => setIntervalMs(Number(e.target.value))}
              disabled={scheduler.active}
              style={{
                width: '100%', padding: '9px 12px', fontSize: 13,
                background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: 8, color: '#F0EFE9', outline: 'none',
                appearance: 'none', cursor: scheduler.active ? 'not-allowed' : 'pointer',
                opacity: scheduler.active ? 0.5 : 1, boxSizing: 'border-box',
              }}
            >
              {INTERVAL_OPTIONS.map(opt => (
                <option key={opt.value} value={opt.value} style={{ background: '#0F172A' }}>
                  {opt.label}
                </option>
              ))}
            </select>
            <ChevronDown size={14} color="#6B7280" style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
          </div>
        </div>

        {/* Start / Stop Button */}
        {scheduler.active ? (
          <button
            onClick={onStop}
            style={{
              width: '100%', padding: '11px', fontSize: 13, fontWeight: 700,
              background: 'rgba(255,46,99,0.12)', border: '1px solid rgba(255,46,99,0.3)',
              borderRadius: 10, color: '#FF2E63', cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              transition: 'all 0.2s',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,46,99,0.2)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,46,99,0.12)'; }}
          >
            <Square size={14} /> Stop Scheduler Immediately
          </button>
        ) : (
          <button
            onClick={handleStart}
            disabled={!domain.trim()}
            style={{
              width: '100%', padding: '11px', fontSize: 13, fontWeight: 700,
              background: domain.trim() ? 'rgba(34,197,94,0.12)' : 'rgba(255,255,255,0.03)',
              border: `1px solid ${domain.trim() ? 'rgba(34,197,94,0.3)' : 'rgba(255,255,255,0.06)'}`,
              borderRadius: 10,
              color: domain.trim() ? '#22C55E' : '#4B5563',
              cursor: domain.trim() ? 'pointer' : 'not-allowed',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              transition: 'all 0.2s',
            }}
            onMouseEnter={e => { if (domain.trim()) e.currentTarget.style.background = 'rgba(34,197,94,0.2)'; }}
            onMouseLeave={e => { if (domain.trim()) e.currentTarget.style.background = 'rgba(34,197,94,0.12)'; }}
          >
            <Play size={14} /> Start Automated Scanning
          </button>
        )}

        {/* Scan History */}
        {scanHistory.length > 0 && (
          <div style={{ marginTop: 16 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: '#6B7280', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>
              Scan History ({scanHistory.length})
            </div>
            <div style={{
              maxHeight: 160, overflowY: 'auto', borderRadius: 8,
              border: '1px solid rgba(255,255,255,0.05)',
              background: 'rgba(0,0,0,0.2)',
            }}>
              {scanHistory.map((entry, i) => (
                <div
                  key={i}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '8px 12px',
                    borderBottom: i < scanHistory.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                    fontSize: 11,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ color: '#4B5563' }}>#{scanHistory.length - i}</span>
                    {entry.error ? (
                      <AlertTriangle size={12} color="#FF2E63" />
                    ) : (
                      <CheckCircle size={12} color="#22C55E" />
                    )}
                    <span style={{ color: '#9CA3AF', fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {entry.error ? (
                      <span style={{ color: '#FF2E63', fontSize: 10 }}>Failed</span>
                    ) : (
                      <>
                        <span style={{ color: riskColor(entry.riskScore), fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
                          {entry.riskScore}
                        </span>
                        <span style={{ color: '#4B5563', fontSize: 10 }}>risk</span>
                        {entry.threatsCreated > 0 && (
                          <span style={{ fontSize: 10, color: '#F59E0B', background: 'rgba(245,158,11,0.1)', padding: '1px 5px', borderRadius: 4 }}>
                            +{entry.threatsCreated} threats
                          </span>
                        )}
                      </>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Currently scanning indicator */}
        {scheduler.scanning && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8, marginTop: 12,
            padding: '8px 12px', background: 'rgba(0,163,255,0.06)',
            border: '1px solid rgba(0,163,255,0.15)', borderRadius: 8,
          }}>
            <Activity size={13} color="#00A3FF" style={{ animation: 'spin 1.5s linear infinite' }} />
            <span style={{ fontSize: 11, color: '#00A3FF', fontWeight: 600 }}>Scanning in progress...</span>
          </div>
        )}
      </div>
    </div>
  );
}
