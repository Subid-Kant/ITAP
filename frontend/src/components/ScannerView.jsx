import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Crosshair, AlertTriangle, RotateCcw, Server, Shield,
  ChevronDown, ChevronRight, Copy, Check, ExternalLink,
  Activity, MapPin, Building2, Globe, Cpu, Eye, EyeOff,
  Radar, Zap, ShieldCheck, ShieldAlert, Clock, Terminal,
  Bug, FileSearch, Tag, Link2
} from 'lucide-react';
import { api } from '../api';
import { useAuth } from '../hooks/useAuth';
import AnimatedButton from './ui/AnimatedButton';
import HoverCard from './ui/HoverCard';
import { StaggeredList, StaggeredItem } from './ui/StaggeredList';

// ─── Copy Button ──────────────────────────────────────────────
function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied ? '#22C55E' : '#6B7280', padding: '2px 4px', borderRadius: 4 }}
      title="Copy"
    >
      {copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

// ─── Severity Badge ────────────────────────────────────────────
function SevBadge({ level }) {
  const colors = { CRITICAL: '#FF2E63', HIGH: '#F59E0B', MEDIUM: '#378ADD', LOW: '#22C55E' };
  const c = colors[level?.toUpperCase()] || '#6B7280';
  return (
    <span style={{ fontSize: 10, fontWeight: 700, color: c, background: `${c}18`, border: `1px solid ${c}40`, padding: '2px 7px', borderRadius: 4, letterSpacing: 0.5 }}>
      {level}
    </span>
  );
}

// ─── Tab System ───────────────────────────────────────────────
function Tab({ label, active, onClick, badge }) {
  return (
    <AnimatedButton
      onClick={onClick}
      style={{
        background: 'none', border: 'none', cursor: 'pointer',
        padding: '10px 16px', fontSize: 12, fontWeight: 600,
        color: active ? '#00A3FF' : '#6B7280',
        transition: 'all 0.2s', display: 'flex', alignItems: 'center', gap: 6,
        whiteSpace: 'nowrap', position: 'relative'
      }}
    >
      {label}
      {badge > 0 && (
        <span style={{ background: active ? '#00A3FF' : '#374151', color: active ? '#000' : '#9CA3AF', borderRadius: 10, padding: '1px 6px', fontSize: 10, fontWeight: 700 }}>
          {badge}
        </span>
      )}
      {active && (
        <motion.div
          layoutId="scannertab"
          style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: 2, background: '#00A3FF' }}
          transition={{ type: 'spring', stiffness: 400, damping: 30 }}
        />
      )}
    </AnimatedButton>
  );
}

// ─── CVE Accordion Row ────────────────────────────────────────
function CVERow({ cve, isAdmin }) {
  const [open, setOpen] = useState(false);
  const severityColors = { CRITICAL: '#FF2E63', HIGH: '#F59E0B', MEDIUM: '#378ADD', LOW: '#22C55E', UNKNOWN: '#6B7280' };
  const c = severityColors[cve.severity?.toUpperCase()] || '#6B7280';
  const [pocVisible, setPocVisible] = useState(false);

  return (
    <div style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'grid', gridTemplateColumns: '1fr auto auto auto auto',
          alignItems: 'center', gap: 12, padding: '10px 16px', cursor: 'pointer',
          background: open ? `${c}08` : 'transparent', transition: 'background 0.2s',
        }}
      >
        <div>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 600, color: '#00A3FF' }}>{cve.cve_id || '—'}</div>
          <div style={{ fontSize: 11, color: '#6B7280', marginTop: 2 }}>{cve.description?.slice(0, 90)}...</div>
        </div>
        <SevBadge level={cve.severity} />
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700, color: c }}>{cve.cvss_score?.toFixed(1)}</span>
        {cve.has_exploit && <span style={{ fontSize: 10, color: '#FF2E63', background: '#FF2E6318', border: '1px solid #FF2E6340', padding: '2px 6px', borderRadius: 4 }}>EXPLOIT</span>}
        {open ? <ChevronDown size={14} color="#6B7280" /> : <ChevronRight size={14} color="#6B7280" />}
      </div>

      {open && (
        <div style={{ padding: '12px 16px 16px', display: 'flex', flexDirection: 'column', gap: 14, background: `${c}06` }}>
          {/* Exact Location */}
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#6B7280', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>📍 Exact Location</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#F0EFE9', background: 'rgba(0,0,0,0.3)', padding: '8px 12px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.06)' }}>
              {cve.exact_location || '—'}
            </div>
          </div>

          {/* CVSS Vector */}
          {cve.cvss_vector && (
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#6B7280', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>⚡ CVSS Vector</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <code style={{ fontSize: 11, color: c, background: `${c}12`, padding: '4px 10px', borderRadius: 4, fontFamily: "'JetBrains Mono', monospace" }}>
                  {cve.cvss_vector}
                </code>
                <CopyBtn text={cve.cvss_vector} />
              </div>
            </div>
          )}

          {/* Description */}
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#6B7280', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>📋 Vulnerability Description</div>
            <div style={{ fontSize: 12, color: '#B4B2A9', lineHeight: 1.6 }}>{cve.description}</div>
          </div>

          {/* Exploitation Technique */}
          {cve.exploitation_technique && (
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#F59E0B', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>⚠️ Exploitation Technique</div>
              <div style={{ fontSize: 12, color: '#B4B2A9', lineHeight: 1.6 }}>{cve.exploitation_technique}</div>
            </div>
          )}

          {/* Vulnerable Parameter */}
          {cve.vulnerable_parameter && (
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#6B7280', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>🎯 Vulnerable Parameter / Entry Point</div>
              <code style={{ fontSize: 12, color: '#00F5D4', background: 'rgba(0,245,212,0.08)', padding: '4px 10px', borderRadius: 4, fontFamily: "'JetBrains Mono', monospace" }}>
                {cve.vulnerable_parameter}
              </code>
            </div>
          )}

          {/* Exploit References */}
          {cve.exploit_refs?.length > 0 && (
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#6B7280', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>🔗 References</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {cve.exploit_refs.map((ref, i) => (
                  <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                    style={{ fontSize: 11, color: '#00A3FF', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <ExternalLink size={10} /> {ref}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* PoC Command — Admin only */}
          {isAdmin && cve.poc_command && (
            <div style={{ border: '1px solid rgba(255,46,99,0.3)', borderRadius: 8, overflow: 'hidden' }}>
              <div
                onClick={() => setPocVisible(v => !v)}
                style={{ background: 'rgba(255,46,99,0.08)', padding: '8px 12px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}
              >
                {pocVisible ? <EyeOff size={12} color="#FF2E63" /> : <Eye size={12} color="#FF2E63" />}
                <span style={{ fontSize: 11, fontWeight: 700, color: '#FF2E63' }}>⚠️ PoC Reference (Admin Only)</span>
              </div>
              {pocVisible && (
                <div style={{ padding: '10px 12px', background: 'rgba(0,0,0,0.4)' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
                    <pre style={{ fontSize: 11, color: '#FF2E63', fontFamily: "'JetBrains Mono', monospace", flex: 1, margin: 0, whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>
                      {cve.poc_command}
                    </pre>
                    <CopyBtn text={cve.poc_command} />
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Verified Badge ──────────────────────────────────────────
function VerifiedBadge({ verified, nmapOnly }) {
  if (nmapOnly) {
    return (
      <span style={{ fontSize: 9, fontWeight: 700, color: '#00F5D4', background: 'rgba(0,245,212,0.12)', border: '1px solid rgba(0,245,212,0.3)', padding: '1px 6px', borderRadius: 3, letterSpacing: 0.5, display: 'flex', alignItems: 'center', gap: 3 }}>
        <Radar size={8} /> NMAP ONLY
      </span>
    );
  }
  if (verified) {
    return (
      <span style={{ fontSize: 9, fontWeight: 700, color: '#22C55E', background: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.3)', padding: '1px 6px', borderRadius: 3, letterSpacing: 0.5, display: 'flex', alignItems: 'center', gap: 3 }}>
        <ShieldCheck size={8} /> VERIFIED
      </span>
    );
  }
  return (
    <span style={{ fontSize: 9, fontWeight: 700, color: '#6B7280', background: 'rgba(107,114,128,0.12)', border: '1px solid rgba(107,114,128,0.3)', padding: '1px 6px', borderRadius: 3, letterSpacing: 0.5, display: 'flex', alignItems: 'center', gap: 3 }}>
      <ShieldAlert size={8} /> OSINT
    </span>
  );
}

// ─── Service Card ─────────────────────────────────────────────
function ServiceCard({ svc, showVerified }) {
  const colors = { CRITICAL: '#FF2E63', HIGH: '#F59E0B', MEDIUM: '#378ADD', LOW: '#22C55E' };
  const c = colors[svc.risk_level] || '#6B7280';
  return (
    <div style={{ background: 'rgba(10,14,23,0.6)', border: `1px solid ${c}30`, borderRadius: 8, padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 16 }}>
      <div style={{ width: 40, height: 40, borderRadius: 8, background: `${c}18`, border: `1px solid ${c}30`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
        <Server size={18} color={c} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontWeight: 600, fontSize: 13, color: '#F0EFE9' }}>{svc.service || 'Unknown'}</span>
          {showVerified && <VerifiedBadge verified={svc.nmap_verified} nmapOnly={svc.nmap_only} />}
        </div>
        <div style={{ fontSize: 11, color: '#6B7280', fontFamily: "'JetBrains Mono', monospace" }}>
          Port {svc.port}/{svc.transport} {svc.version && `· v${svc.version}`}
        </div>
        {svc.banner && <div style={{ fontSize: 10, color: '#4B5563', marginTop: 2, fontFamily: "'JetBrains Mono', monospace", overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{svc.banner}</div>}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4, flexShrink: 0 }}>
        <SevBadge level={svc.risk_level} />
        {svc.cves?.length > 0 && (
          <span style={{ fontSize: 10, color: '#6B7280' }}>{svc.cves.length} CVE{svc.cves.length !== 1 ? 's' : ''}</span>
        )}
      </div>
    </div>
  );
}

// ─── Nmap Results Tab ─────────────────────────────────────────
function NmapResultsTab({ nmap }) {
  if (!nmap) return <div style={{ padding: 24, color: '#6B7280', textAlign: 'center' }}>Nmap was not enabled for this scan. Toggle "Active Scan" and re-scan.</div>;
  if (nmap.status === 'error') {
    return (
      <div style={{ padding: 16, background: 'rgba(239,68,68,0.06)', borderRadius: 8, border: '1px solid rgba(239,68,68,0.2)' }}>
        <div style={{ color: '#EF4444', fontWeight: 600, marginBottom: 4 }}>Nmap Scan Failed</div>
        <div style={{ color: '#9CA3AF', fontSize: 12 }}>{nmap.error}</div>
      </div>
    );
  }

  const vulns = nmap.active_vulnerabilities || [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Nmap Stats */}
      <StaggeredList className="stats-grid">
        <StaggeredItem className="stat-card">
          <div className="stat-value" style={{ color: '#00F5D4' }}>{nmap.ports_discovered || 0}</div>
          <div className="stat-label">Ports Found</div>
        </StaggeredItem>
        <StaggeredItem className="stat-card">
          <div className="stat-value">{nmap.services_detected || 0}</div>
          <div className="stat-label">Services</div>
        </StaggeredItem>
        <StaggeredItem className="stat-card">
          <div className="stat-value" style={{ color: vulns.length > 0 ? '#FF2E63' : '#22C55E' }}>{vulns.length}</div>
          <div className="stat-label">Active Vulns</div>
        </StaggeredItem>
        <StaggeredItem className="stat-card">
          <div className="stat-value">{nmap.duration_seconds || 0}s</div>
          <div className="stat-label">Scan Time</div>
        </StaggeredItem>
      </StaggeredList>

      {/* OS Detection */}
      {nmap.os_detection && (
        <div style={{ background: 'rgba(0,245,212,0.06)', border: '1px solid rgba(0,245,212,0.2)', borderRadius: 8, padding: '10px 14px' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#00F5D4', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
            <Cpu size={11} /> OS Detection
          </div>
          <div style={{ fontSize: 13, color: '#F0EFE9', fontWeight: 600 }}>{nmap.os_detection.name}</div>
          <div style={{ fontSize: 11, color: '#6B7280', marginTop: 2 }}>Accuracy: {nmap.os_detection.accuracy}%</div>
        </div>
      )}

      {/* Nmap Command */}
      {nmap.nmap_command && (
        <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: '10px 14px' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#6B7280', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
            <Terminal size={11} /> Nmap Command
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <code style={{ fontSize: 11, color: '#00A3FF', fontFamily: "'JetBrains Mono', monospace", flex: 1 }}>{nmap.nmap_command}</code>
            <CopyBtn text={nmap.nmap_command} />
          </div>
        </div>
      )}

      {/* Active Vulnerabilities */}
      {vulns.length > 0 && (
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#FF2E63', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
            <Zap size={11} /> Actively Verified Vulnerabilities
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {vulns.map((v, i) => {
              const sevColors = { CRITICAL: '#FF2E63', HIGH: '#F59E0B', MEDIUM: '#378ADD', LOW: '#22C55E' };
              const vc = sevColors[v.severity] || '#6B7280';
              return (
                <div key={i} style={{ background: `${vc}08`, border: `1px solid ${vc}25`, borderRadius: 8, padding: '10px 14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <SevBadge level={v.severity} />
                    <span style={{ fontSize: 12, fontWeight: 600, color: '#F0EFE9' }}>{v.script}</span>
                    <span style={{ fontSize: 10, color: '#6B7280', fontFamily: "'JetBrains Mono', monospace" }}>{v.exact_location}</span>
                  </div>
                  {v.cve_ids?.length > 0 && (
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 6 }}>
                      {v.cve_ids.map((cve, j) => (
                        <code key={j} style={{ fontSize: 10, color: '#00A3FF', background: 'rgba(0,163,255,0.1)', padding: '2px 6px', borderRadius: 4, fontFamily: "'JetBrains Mono', monospace" }}>{cve}</code>
                      ))}
                    </div>
                  )}
                  <div style={{ fontSize: 11, color: '#9CA3AF', lineHeight: 1.6, whiteSpace: 'pre-wrap', maxHeight: 120, overflow: 'auto' }}>{v.description}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {vulns.length === 0 && (
        <div style={{ padding: 16, textAlign: 'center', color: '#22C55E', background: 'rgba(34,197,94,0.06)', borderRadius: 8, border: '1px solid rgba(34,197,94,0.2)' }}>
          <ShieldCheck size={20} style={{ display: 'inline', marginRight: 6 }} />
          No actively exploitable vulnerabilities found by Nmap. Target appears hardened.
        </div>
      )}
    </div>
  );
}


// ─── Remediation Tab ─────────────────────────────────────────
function RemediationTab({ predictions }) {
  const allSteps = useMemo(() => {
    const steps = [];
    predictions?.forEach(p => {
      (p.remediation || []).forEach(step => {
        steps.push({ ...step, threat: p.predicted_attack_type, severity: p.severity });
      });
    });
    const order = { immediate: 0, 'short-term': 1, 'long-term': 2 };
    return steps.sort((a, b) => (order[a.priority] ?? 3) - (order[b.priority] ?? 3));
  }, [predictions]);

  if (!allSteps.length) return <div style={{ padding: 24, color: '#6B7280', textAlign: 'center' }}>No remediation steps available yet. Run a scan to generate recommendations.</div>;

  const priorityConfig = {
    immediate: { color: '#FF2E63', label: '🔴 IMMEDIATE', bg: 'rgba(255,46,99,0.08)' },
    'short-term': { color: '#F59E0B', label: '🟠 SHORT-TERM', bg: 'rgba(245,158,11,0.08)' },
    'long-term': { color: '#22C55E', label: '🟢 LONG-TERM', bg: 'rgba(34,197,94,0.08)' },
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: '12px 0' }}>
      {allSteps.map((step, i) => {
        const pc = priorityConfig[step.priority] || priorityConfig['long-term'];
        return (
          <div key={i} style={{ background: pc.bg, border: `1px solid ${pc.color}25`, borderRadius: 8, padding: '10px 14px', display: 'flex', gap: 12, alignItems: 'flex-start' }}>
            <div style={{ width: 22, height: 22, borderRadius: '50%', background: pc.color, color: '#000', fontSize: 10, fontWeight: 800, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
              {i + 1}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: pc.color }}>{pc.label}</span>
                <span style={{ fontSize: 10, color: '#4B5563' }}>· {step.threat}</span>
              </div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#F0EFE9', marginBottom: 3 }}>{step.action}</div>
              <div style={{ fontSize: 11, color: '#9CA3AF', lineHeight: 1.6 }}>{step.detail}</div>
            </div>
            <CopyBtn text={step.detail} />
          </div>
        );
      })}
    </div>
  );
}

// ─── Threat Surface Mini Map ──────────────────────────────────
function ThreatSurface({ surface }) {
  if (!surface?.length) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {surface.slice(0, 6).map((item, i) => {
        const colors = { CRITICAL: '#FF2E63', HIGH: '#F59E0B', MEDIUM: '#378ADD', LOW: '#22C55E' };
        const c = colors[item.severity] || '#6B7280';
        return (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 10px', background: `${c}08`, border: `1px solid ${c}20`, borderRadius: 6 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: c, flexShrink: 0 }} />
            <div style={{ flex: 1, fontSize: 11, color: '#B4B2A9' }}>
              <span style={{ fontWeight: 600, color: '#F0EFE9' }}>{item.component}</span>
              {item.location && <span style={{ color: '#6B7280' }}> · {item.location}</span>}
            </div>
            <SevBadge level={item.severity} />
          </div>
        );
      })}
    </div>
  );
}

// ─── Scan Mode Toggle ─────────────────────────────────────────
function ScanModeToggle({ nmapEnabled, setNmapEnabled, nmapType, setNmapType, isAdmin }) {
  if (!isAdmin) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, padding: '8px 14px',
        background: nmapEnabled ? 'rgba(0,245,212,0.06)' : 'rgba(255,255,255,0.02)',
        border: `1px solid ${nmapEnabled ? 'rgba(0,245,212,0.25)' : 'rgba(255,255,255,0.06)'}`,
        borderRadius: 10, transition: 'all 0.3s',
      }}>
        {/* Toggle Switch */}
        <button
          onClick={() => setNmapEnabled(!nmapEnabled)}
          style={{
            width: 42, height: 22, borderRadius: 11, border: 'none', cursor: 'pointer',
            background: nmapEnabled ? '#00F5D4' : '#374151',
            position: 'relative', transition: 'background 0.3s', flexShrink: 0,
            padding: 0
          }}
        >
          <motion.div 
            style={{
              width: 16, height: 16, borderRadius: '50%',
              background: nmapEnabled ? '#0A0E17' : '#6B7280',
              position: 'absolute', top: 3, left: 3
            }}
            animate={{ x: nmapEnabled ? 20 : 0 }}
            transition={{ type: 'spring', stiffness: 500, damping: 30 }}
          />
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Radar size={14} color={nmapEnabled ? '#00F5D4' : '#6B7280'} />
          <span style={{ fontSize: 12, fontWeight: 600, color: nmapEnabled ? '#00F5D4' : '#6B7280' }}>
            Active Scan (Nmap)
          </span>
        </div>

        {/* Scan Type Selector */}
        {nmapEnabled && (
          <div style={{ display: 'flex', gap: 4, marginLeft: 'auto' }}>
            {['quick', 'standard', 'deep'].map(t => (
              <button
                key={t}
                onClick={() => setNmapType(t)}
                style={{
                  fontSize: 10, fontWeight: 700, padding: '3px 10px', borderRadius: 6,
                  border: `1px solid ${nmapType === t ? '#00F5D4' : 'rgba(255,255,255,0.08)'}`,
                  background: nmapType === t ? 'rgba(0,245,212,0.15)' : 'transparent',
                  color: nmapType === t ? '#00F5D4' : '#6B7280',
                  cursor: 'pointer', textTransform: 'uppercase', letterSpacing: 0.5,
                  transition: 'all 0.2s',
                }}
              >
                {t === 'quick' && '⚡ '}{t === 'deep' && '🔬 '}{t}
              </button>
            ))}
          </div>
        )}
      </div>


    </div>
  );
}

// ─── Main ScannerView ─────────────────────────────────────────
export default function ScannerView({ onScanComplete, scannerState, setScannerState }) {
  const { user } = useAuth();
  const isViewer = user?.role === 'viewer';
  const isAdmin = user?.role === 'admin';
  const [scanning, setScanning] = useState(false);
  const [activeTab, setActiveTab] = useState('summary');
  const [nmapEnabled, setNmapEnabled] = useState(false);
  const [nmapType, setNmapType] = useState('standard');

  const domain = scannerState?.domain ?? '';
  const results = scannerState?.results ?? null;
  const error = scannerState?.error ?? '';

  const setDomain = (val) => setScannerState(s => ({ ...s, domain: val }));
  const setResults = (val) => setScannerState(s => ({ ...s, results: val }));
  const setError = (val) => setScannerState(s => ({ ...s, error: val }));

  const handleScan = async () => {
    if (!domain.trim() || isViewer) return;
    setScanning(true);
    setError('');
    setResults(null);
    setActiveTab('summary');
    try {
      const target = await api.createTarget({ domain: domain.trim() });
      const scan = await api.runScan({
        target_id: target.id,
        scan_types: ['shodan', 'virustotal', 'cve'],
        nmap_enabled: nmapEnabled,
        nmap_scan_type: nmapType,
      });
      setResults(scan);
      if (onScanComplete) onScanComplete();
    } catch (e) {
      setError(e.message || 'Scan failed. Please ensure backend services are running and the target is reachable.');
    } finally {
      setScanning(false);
    }
  };

  const handleClear = () => {
    setScannerState({ domain: '', results: null, error: '' });
    setActiveTab('summary');
    setNmapEnabled(false);
    setNmapEnabled(false);
  };

  const vulnBySvc = results?.vulnerabilities_by_service || [];
  let allCves = vulnBySvc.flatMap(s => (s.cves || []).map(c => ({ ...c, _service: s.service })));

  if (results?.nmap?.active_vulnerabilities) {
    allCves = [...allCves, ...results.nmap.active_vulnerabilities.map(v => ({
      cve_id: v.script,
      description: v.description,
      cvss_score: v.cvss_score || 0,
      severity: v.severity,
      _service: 'Nmap Scan',
    }))];
  }


  const threatSurface = results?.threat_surface || [];
  const fp = results?.osint_fingerprint || {};
  const predictions = results?.predictions || [];
  const nmapData = results?.nmap || null;
  const hasNmap = nmapData && nmapData.status === 'completed';
  const isHybrid = scanning ? (nmapEnabled) : (hasNmap);

  const tabs = [
    { id: 'summary', label: 'Summary' },
    { id: 'services', label: 'Services', badge: vulnBySvc.length },
    { id: 'vulnerabilities', label: 'Vulnerabilities', badge: allCves.length },
    { id: 'nmap', label: '🛡️ Nmap', badge: hasNmap ? (nmapData.vulnerabilities_found || 0) : null },

    { id: 'predictions', label: 'AI Predictions', badge: predictions.length },
    { id: 'remediation', label: 'Remediation', badge: predictions.flatMap(p => p.remediation || []).length },
  ];

  const riskColors = { CRITICAL: '#FF2E63', HIGH: '#F59E0B', MEDIUM: '#378ADD', LOW: '#22C55E' };
  const riskColor = riskColors[results?.risk_level] || '#6B7280';

  return (
    <div className="fade-in">
      {/* Scan Input */}
      <div className="scan-form">
        <input
          className="scan-input" type="text"
          placeholder="Enter domain or IP (e.g. example.com, 192.168.1.1)"
          value={domain} onChange={e => setDomain(e.target.value)}
          disabled={scanning || isViewer}
          onKeyDown={e => e.key === 'Enter' && handleScan()}
          style={{ transition: 'box-shadow 0.3s ease', outline: 'none' }}
          onFocus={(e) => e.target.style.boxShadow = '0 0 0 2px rgba(0, 163, 255, 0.4)'}
          onBlur={(e) => e.target.style.boxShadow = 'none'}
        />
        <AnimatedButton variant="primary" onClick={handleScan} disabled={scanning || isViewer} title={isViewer ? 'Viewer mode — scan restricted' : ''}>
          {isHybrid ? <Radar size={14} /> : <Crosshair size={14} />}
          {scanning ? (isHybrid ? 'Hybrid Scanning...' : 'Scanning...') : (isHybrid ? 'Hybrid Scan' : 'Deep Scan')}
        </AnimatedButton>
        {results && (
          <AnimatedButton variant="default" onClick={handleClear} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <RotateCcw size={14} /> Clear
          </AnimatedButton>
        )}
      </div>

      {/* Active Scan Toggles */}
      <ScanModeToggle
        nmapEnabled={nmapEnabled}
        setNmapEnabled={setNmapEnabled}
        nmapType={nmapType}
        setNmapType={setNmapType}
        isAdmin={isAdmin}
      />


      {/* Scanning Animation */}
      {scanning && (
        <div style={{ padding: 40, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 20 }}>
          <motion.div 
            animate={{ rotate: 360 }} 
            transition={{ repeat: Infinity, duration: 2, ease: "linear" }}
            style={{ width: 80, height: 80, borderRadius: '50%', border: '2px solid rgba(0, 163, 255, 0.2)', borderTopColor: '#00A3FF', position: 'relative' }}
          >
            <div style={{ position: 'absolute', inset: 4, borderRadius: '50%', border: '2px dashed rgba(157, 80, 255, 0.3)', animation: 'spin 4s linear infinite reverse' }} />
            <Radar size={32} color="#00A3FF" style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)' }} />
          </motion.div>
          <div className="scanning-text" style={{ textAlign: 'center' }}>
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
              {isHybrid ? (
                <>Hybrid scanning {domain}... OSINT + {nmapEnabled && `Nmap (${nmapType})`}<br/><span style={{fontSize: 11, color: '#6B7280'}}>Active scans may take a few minutes</span></>
              ) : (
                <>Deep scanning {domain}... Querying Shodan · VirusTotal · CVE/NVD · OTX</>
              )}
            </motion.div>
          </div>
        </div>
      )}

      {error && <div style={{ color: '#EF4444', padding: 16, background: 'rgba(239,68,68,0.06)', borderRadius: 8, border: '1px solid rgba(239,68,68,0.2)' }}>{error}</div>}

      {results && (
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ type: 'spring', stiffness: 300, damping: 25 }}>
          {/* Header Risk Bar */}
          <HoverCard tiltFactor={3} style={{ marginBottom: 16 }}>
            <div className="panel-header">
              <div className="panel-title">{hasNmap ? <Radar size={16} /> : <Crosshair size={16} />} {hasNmap ? 'Hybrid' : 'Deep'} Scan — {results.target || domain}</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ fontSize: 12, color: '#6B7280' }}>
                  {fp.org && <><Building2 size={11} style={{ display: 'inline', marginRight: 4 }} />{fp.org}</>}
                  {fp.country && <><Globe size={11} style={{ display: 'inline', margin: '0 4px 0 8px' }} />{fp.city}, {fp.country}</>}
                </span>
                <span className={`severity-badge ${results.risk_level?.toLowerCase() || 'medium'}`}
                  style={{ boxShadow: `0 0 12px ${riskColor}40` }}>
                  Risk: {results.risk_level} ({results.risk_score}/100)
                </span>
              </div>
            </div>

            {/* Tabs */}
            <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)', overflowX: 'auto' }}>
              {tabs.map(t => (
                <Tab key={t.id} label={t.label} active={activeTab === t.id} onClick={() => setActiveTab(t.id)} badge={t.badge} />
              ))}
            </div>

            <div className="panel-body">
              <AnimatePresence mode="wait">
                <motion.div
                  key={activeTab}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.2 }}
                >
                  {/* ── SUMMARY TAB ── */}
                  {activeTab === 'summary' && (
                    <div>
                      <StaggeredList className="stats-grid" style={{ marginBottom: 16 }}>
                        <StaggeredItem className="stat-card"><div className="stat-value">{results.summary?.open_ports || 0}</div><div className="stat-label">Open Ports</div></StaggeredItem>
                        <StaggeredItem className="stat-card"><div className="stat-value">{results.summary?.known_vulns || 0}</div><div className="stat-label">Shodan CVEs</div></StaggeredItem>
                        <StaggeredItem className="stat-card"><div className="stat-value" style={{ color: results.summary?.vt_malicious > 0 ? '#FF2E63' : '#22C55E' }}>{results.summary?.vt_malicious || 0}</div><div className="stat-label">VT Malicious</div></StaggeredItem>
                        <StaggeredItem className="stat-card"><div className="stat-value">{allCves.length}</div><div className="stat-label">Deep CVEs Found</div></StaggeredItem>
                        <StaggeredItem className="stat-card"><div className="stat-value">{results.summary?.otx_pulses || 0}</div><div className="stat-label">OTX Pulses</div></StaggeredItem>
                      </StaggeredList>

                  {/* Threat Surface */}
                  {threatSurface.length > 0 && (
                    <div style={{ marginBottom: 16 }}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: '#6B7280', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
                        <Activity size={11} style={{ display: 'inline', marginRight: 4 }} /> Attack Surface Map
                      </div>
                      <ThreatSurface surface={threatSurface} />
                    </div>
                  )}

                  {/* Fingerprint */}
                  {fp.os && (
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 8 }}>
                      {fp.os && <span style={{ fontSize: 11, color: '#9CA3AF', background: 'rgba(255,255,255,0.04)', padding: '3px 10px', borderRadius: 20 }}><Cpu size={10} style={{ display: 'inline', marginRight: 4 }} />{fp.os}</span>}
                      {fp.hostnames?.[0] && <span style={{ fontSize: 11, color: '#9CA3AF', background: 'rgba(255,255,255,0.04)', padding: '3px 10px', borderRadius: 20 }}><MapPin size={10} style={{ display: 'inline', marginRight: 4 }} />{fp.hostnames[0]}</span>}
                    </div>
                  )}

                  {results.threats_created?.length > 0 && (
                    <div style={{ color: '#22C55E', fontSize: 13, display: 'flex', alignItems: 'center', gap: 6, marginTop: 12 }}>
                      <Shield size={14} /> {results.threats_created.length} threat{results.threats_created.length !== 1 ? 's' : ''} added to SOC Dashboard
                    </div>
                  )}
                </div>
              )}

                  {/* ── SERVICES TAB ── */}
                  {activeTab === 'services' && (
                    <StaggeredList style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {vulnBySvc.length === 0 ? (
                        <div style={{ color: '#6B7280', textAlign: 'center', padding: 24 }}>No service data discovered. Try a domain with Shodan results.</div>
                      ) : vulnBySvc.map((svc, i) => <StaggeredItem key={i}><ServiceCard svc={svc} showVerified={hasNmap} /></StaggeredItem>)}
                    </StaggeredList>
                  )}

                  {/* ── VULNERABILITIES TAB ── */}
                  {activeTab === 'vulnerabilities' && (
                    <div style={{ margin: '0 -16px' }}>
                      {allCves.length === 0 ? (
                        <div style={{ color: '#6B7280', textAlign: 'center', padding: 24 }}>No CVEs found across discovered services.</div>
                      ) : (
                        <div>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto auto auto', gap: 12, padding: '6px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                            {['CVE / Description', 'Severity', 'CVSS', '', ''].map((h, i) => (
                              <div key={i} style={{ fontSize: 10, fontWeight: 700, color: '#4B5563', textTransform: 'uppercase', letterSpacing: 0.8 }}>{h}</div>
                            ))}
                          </div>
                          <StaggeredList>
                            {allCves.map((cve, i) => <StaggeredItem key={i}><CVERow cve={cve} isAdmin={isAdmin} /></StaggeredItem>)}
                          </StaggeredList>
                        </div>
                      )}
                    </div>
                  )}

                  {/* ── PREDICTIONS TAB ── */}
                  {activeTab === 'predictions' && (
                    <StaggeredList style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                      {predictions.length === 0 ? (
                        <div style={{ color: '#6B7280', textAlign: 'center', padding: 24 }}>No ML predictions generated.</div>
                      ) : predictions.map((p, i) => {
                        const pColors = { CRITICAL: '#FF2E63', HIGH: '#F59E0B', MEDIUM: '#378ADD', LOW: '#22C55E' };
                        const pc = pColors[p.severity] || '#6B7280';
                        return (
                          <StaggeredItem key={i} style={{ background: `${pc}08`, border: `1px solid ${pc}30`, borderRadius: 10, padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                              <SevBadge level={p.severity} />
                              <span style={{ fontWeight: 600, fontSize: 13, color: '#F0EFE9', flex: 1 }}>{p.predicted_attack_type}</span>
                              {p.predicted_cve && <code style={{ fontSize: 11, color: '#00A3FF', fontFamily: "'JetBrains Mono', monospace" }}>{p.predicted_cve}</code>}
                            </div>
                            {/* Probability bar */}
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                              <div style={{ fontSize: 10, color: '#6B7280', width: 80 }}>Probability</div>
                              <div style={{ flex: 1, height: 5, background: 'rgba(255,255,255,0.06)', borderRadius: 3, maxWidth: 200 }}>
                                <motion.div initial={{ width: 0 }} animate={{ width: `${p.probability * 100}%` }} transition={{ duration: 1, delay: i * 0.1 }} style={{ height: '100%', background: pc, borderRadius: 3, boxShadow: `0 0 8px ${pc}80` }} />
                              </div>
                              <span style={{ fontSize: 12, fontFamily: "'JetBrains Mono', monospace", color: pc, fontWeight: 700 }}>{(p.probability * 100).toFixed(1)}%</span>
                              <span style={{ fontSize: 11, color: p.confidence === 'high' ? '#FF2E63' : p.confidence === 'medium' ? '#F59E0B' : '#22C55E' }}>{p.confidence}</span>
                            </div>
                            {p.root_cause && (
                              <div style={{ fontSize: 11, color: '#9CA3AF', lineHeight: 1.6, borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 10 }}>
                                <span style={{ fontWeight: 600, color: '#6B7280' }}>Root Cause: </span>{p.root_cause.slice(0, 200)}...
                              </div>
                            )}
                          </StaggeredItem>
                        );
                      })}
                    </StaggeredList>
                  )}

                  {/* ── NMAP TAB ── */}
                  {activeTab === 'nmap' && <NmapResultsTab nmap={nmapData} />}

                  {/* ── REMEDIATION TAB ── */}
                  {activeTab === 'remediation' && <RemediationTab predictions={predictions} />}
                </motion.div>
              </AnimatePresence>
            </div>
          </HoverCard>
        </motion.div>
      )}
    </div>
  );
}
