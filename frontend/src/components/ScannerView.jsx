import { useState, useMemo } from 'react';
import {
  Crosshair, AlertTriangle, RotateCcw, Server, Shield,
  ChevronDown, ChevronRight, Copy, Check, ExternalLink,
  Activity, MapPin, Building2, Globe, Cpu, Eye, EyeOff
} from 'lucide-react';
import { api } from '../api';
import { useAuth } from '../hooks/useAuth';

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
    <button
      onClick={onClick}
      style={{
        background: 'none', border: 'none', cursor: 'pointer',
        padding: '10px 16px', fontSize: 12, fontWeight: 600,
        color: active ? '#00A3FF' : '#6B7280',
        borderBottom: `2px solid ${active ? '#00A3FF' : 'transparent'}`,
        transition: 'all 0.2s', display: 'flex', alignItems: 'center', gap: 6,
        whiteSpace: 'nowrap',
      }}
    >
      {label}
      {badge > 0 && (
        <span style={{ background: active ? '#00A3FF' : '#374151', color: active ? '#000' : '#9CA3AF', borderRadius: 10, padding: '1px 6px', fontSize: 10, fontWeight: 700 }}>
          {badge}
        </span>
      )}
    </button>
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

// ─── Service Card ─────────────────────────────────────────────
function ServiceCard({ svc }) {
  const colors = { CRITICAL: '#FF2E63', HIGH: '#F59E0B', MEDIUM: '#378ADD', LOW: '#22C55E' };
  const c = colors[svc.risk_level] || '#6B7280';
  return (
    <div style={{ background: 'rgba(10,14,23,0.6)', border: `1px solid ${c}30`, borderRadius: 8, padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 16 }}>
      <div style={{ width: 40, height: 40, borderRadius: 8, background: `${c}18`, border: `1px solid ${c}30`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
        <Server size={18} color={c} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 600, fontSize: 13, color: '#F0EFE9' }}>{svc.service || 'Unknown'}</div>
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

// ─── Remediation Tab ─────────────────────────────────────────
function RemediationTab({ predictions, isAdmin }) {
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

// ─── Main ScannerView ─────────────────────────────────────────
export default function ScannerView({ onScanComplete, scannerState, setScannerState }) {
  const { user } = useAuth();
  const isViewer = user?.role === 'viewer';
  const isAdmin = user?.role === 'admin';
  const [scanning, setScanning] = useState(false);
  const [activeTab, setActiveTab] = useState('summary');

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
      const scan = await api.runScan({ target_id: target.id, scan_types: ['shodan', 'virustotal', 'cve'] });
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
  };

  const vulnBySvc = results?.vulnerabilities_by_service || [];
  const allCves = vulnBySvc.flatMap(s => (s.cves || []).map(c => ({ ...c, _service: s.service })));
  const threatSurface = results?.threat_surface || [];
  const fp = results?.osint_fingerprint || {};
  const predictions = results?.predictions || [];

  const tabs = [
    { id: 'summary', label: 'Summary' },
    { id: 'services', label: 'Services', badge: vulnBySvc.length },
    { id: 'vulnerabilities', label: 'Vulnerabilities', badge: allCves.length },
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
        />
        <button className="header-btn primary" onClick={handleScan} disabled={scanning || isViewer} title={isViewer ? 'Viewer mode — scan restricted' : ''}>
          <Crosshair size={14} /> {scanning ? 'Scanning...' : 'Deep Scan'}
        </button>
        {results && (
          <button className="header-btn" onClick={handleClear} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <RotateCcw size={14} /> Clear
          </button>
        )}
      </div>

      {/* Scanning Animation */}
      {scanning && (
        <div className="scanning">
          <div className="scanning-ring" />
          <div className="scanning-text">Deep scanning {domain}... Querying Shodan · VirusTotal · CVE/NVD · OTX</div>
        </div>
      )}

      {error && <div style={{ color: '#EF4444', padding: 16, background: 'rgba(239,68,68,0.06)', borderRadius: 8, border: '1px solid rgba(239,68,68,0.2)' }}>{error}</div>}

      {results && (
        <div className="stagger">
          {/* Header Risk Bar */}
          <div className="panel" style={{ marginBottom: 16 }}>
            <div className="panel-header">
              <div className="panel-title"><Crosshair size={16} /> Deep Scan — {results.target || domain}</div>
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
              {/* ── SUMMARY TAB ── */}
              {activeTab === 'summary' && (
                <div>
                  <div className="stats-grid" style={{ marginBottom: 16 }}>
                    <div className="stat-card"><div className="stat-value">{results.summary?.open_ports || 0}</div><div className="stat-label">Open Ports</div></div>
                    <div className="stat-card"><div className="stat-value">{results.summary?.known_vulns || 0}</div><div className="stat-label">Shodan CVEs</div></div>
                    <div className="stat-card"><div className="stat-value" style={{ color: results.summary?.vt_malicious > 0 ? '#FF2E63' : '#22C55E' }}>{results.summary?.vt_malicious || 0}</div><div className="stat-label">VT Malicious</div></div>
                    <div className="stat-card"><div className="stat-value">{allCves.length}</div><div className="stat-label">Deep CVEs Found</div></div>
                    <div className="stat-card"><div className="stat-value">{results.summary?.otx_pulses || 0}</div><div className="stat-label">OTX Pulses</div></div>
                  </div>

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
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {vulnBySvc.length === 0 ? (
                    <div style={{ color: '#6B7280', textAlign: 'center', padding: 24 }}>No service data discovered. Try a domain with Shodan results.</div>
                  ) : vulnBySvc.map((svc, i) => <ServiceCard key={i} svc={svc} />)}
                </div>
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
                      {allCves.map((cve, i) => <CVERow key={i} cve={cve} isAdmin={isAdmin} />)}
                    </div>
                  )}
                </div>
              )}

              {/* ── PREDICTIONS TAB ── */}
              {activeTab === 'predictions' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {predictions.length === 0 ? (
                    <div style={{ color: '#6B7280', textAlign: 'center', padding: 24 }}>No ML predictions generated.</div>
                  ) : predictions.map((p, i) => {
                    const pColors = { CRITICAL: '#FF2E63', HIGH: '#F59E0B', MEDIUM: '#378ADD', LOW: '#22C55E' };
                    const pc = pColors[p.severity] || '#6B7280';
                    return (
                      <div key={i} style={{ background: `${pc}08`, border: `1px solid ${pc}30`, borderRadius: 10, padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <SevBadge level={p.severity} />
                          <span style={{ fontWeight: 600, fontSize: 13, color: '#F0EFE9', flex: 1 }}>{p.predicted_attack_type}</span>
                          {p.predicted_cve && <code style={{ fontSize: 11, color: '#00A3FF', fontFamily: "'JetBrains Mono', monospace" }}>{p.predicted_cve}</code>}
                        </div>
                        {/* Probability bar */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <div style={{ fontSize: 10, color: '#6B7280', width: 80 }}>Probability</div>
                          <div style={{ flex: 1, height: 5, background: 'rgba(255,255,255,0.06)', borderRadius: 3, maxWidth: 200 }}>
                            <div style={{ width: `${p.probability * 100}%`, height: '100%', background: pc, borderRadius: 3, transition: 'width 0.8s ease', boxShadow: `0 0 8px ${pc}80` }} />
                          </div>
                          <span style={{ fontSize: 12, fontFamily: "'JetBrains Mono', monospace", color: pc, fontWeight: 700 }}>{(p.probability * 100).toFixed(1)}%</span>
                          <span style={{ fontSize: 11, color: p.confidence === 'high' ? '#FF2E63' : p.confidence === 'medium' ? '#F59E0B' : '#22C55E' }}>{p.confidence}</span>
                        </div>
                        {p.root_cause && (
                          <div style={{ fontSize: 11, color: '#9CA3AF', lineHeight: 1.6, borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 10 }}>
                            <span style={{ fontWeight: 600, color: '#6B7280' }}>Root Cause: </span>{p.root_cause.slice(0, 200)}...
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {/* ── REMEDIATION TAB ── */}
              {activeTab === 'remediation' && <RemediationTab predictions={predictions} isAdmin={isAdmin} />}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
