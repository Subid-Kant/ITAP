import { useState, useRef } from 'react';
import { Search, Upload, Shield, Globe, Hash, Link, AlertTriangle, CheckCircle, ChevronDown, ChevronUp, Copy, Activity, Eye, Server, Wifi } from 'lucide-react';
import { api } from '../api';
import { useToast } from './ToastNotification';
import HoverCard from './ui/HoverCard';
import { StaggeredList, StaggeredItem } from './ui/StaggeredList';
import AnimatedButton from './ui/AnimatedButton';
import { motion, AnimatePresence } from 'framer-motion';

const IOC_TYPES = [
  { value: 'domain', label: 'Domain', icon: Globe },
  { value: 'ip', label: 'IP Address', icon: Globe },
  { value: 'hash', label: 'File Hash', icon: Hash },
  { value: 'url', label: 'URL', icon: Link },
];

function ConfidenceMeter({ score }) {
  const pct = Math.round(score * 100);
  const color = pct >= 80 ? 'var(--severity-critical)' : pct >= 60 ? 'var(--severity-high)' : pct >= 40 ? 'var(--severity-medium)' : 'var(--accent-green)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 3, transition: 'width 0.6s ease' }} />
      </div>
      <span style={{ fontSize: 12, fontFamily: "'JetBrains Mono', monospace", color }}>{pct}%</span>
    </div>
  );
}

function VTDetectionBar({ malicious, suspicious, harmless, undetected }) {
  const total = (malicious || 0) + (suspicious || 0) + (harmless || 0) + (undetected || 0);
  if (total === 0) return <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>No data</span>;
  const pctMal = (malicious / total) * 100;
  const pctSus = (suspicious / total) * 100;
  const pctHarm = (harmless / total) * 100;
  return (
    <div>
      <div style={{ display: 'flex', height: 8, borderRadius: 4, overflow: 'hidden', background: 'rgba(255,255,255,0.06)', marginBottom: 6 }}>
        {pctMal > 0 && <div style={{ width: `${pctMal}%`, background: 'var(--severity-critical)', transition: 'width 0.4s ease' }} />}
        {pctSus > 0 && <div style={{ width: `${pctSus}%`, background: 'var(--severity-high)', transition: 'width 0.4s ease' }} />}
        {pctHarm > 0 && <div style={{ width: `${pctHarm}%`, background: 'var(--accent-green)', transition: 'width 0.4s ease' }} />}
      </div>
      <div style={{ display: 'flex', gap: 12, fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>
        <span style={{ color: 'var(--severity-critical)' }}>⬤ {malicious} malicious</span>
        <span style={{ color: 'var(--severity-high)' }}>⬤ {suspicious} suspicious</span>
        <span style={{ color: 'var(--accent-green)' }}>⬤ {harmless} clean</span>
        <span style={{ color: 'var(--text-muted)' }}>⬤ {undetected} unknown</span>
      </div>
    </div>
  );
}

function SourceBadge({ name, active }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '3px 8px', borderRadius: 100, fontSize: 10, fontWeight: 600,
      letterSpacing: 0.5, textTransform: 'uppercase',
      background: active ? 'rgba(0,200,83,0.12)' : 'rgba(255,255,255,0.04)',
      border: `1px solid ${active ? 'rgba(0,200,83,0.3)' : 'rgba(255,255,255,0.08)'}`,
      color: active ? 'var(--accent-green)' : 'var(--text-muted)',
    }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: active ? 'var(--accent-green)' : 'var(--text-muted)' }} />
      {name}
    </span>
  );
}

function IOCCard({ result, onCopy }) {
  const [expanded, setExpanded] = useState(false);
  const risk = result.risk_score || 0;
  const riskColor = risk >= 80 ? 'var(--severity-critical)' : risk >= 60 ? 'var(--severity-high)' : risk >= 40 ? 'var(--severity-medium)' : 'var(--accent-green)';
  const vt = result.osint_sources?.virustotal || {};
  const otx = result.osint_sources?.otx || {};
  const shodan = result.osint_sources?.shodan || {};
  const censys = result.osint_sources?.censys || {};
  const isLive = result.live_data;

  return (
    <HoverCard className="panel ioc-card" style={{ marginBottom: 12, borderColor: `${riskColor}33` }} tiltFactor={1}>
      <div className="ioc-card-header" onClick={() => setExpanded(e => !e)}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1 }}>
          <div className="ioc-risk-badge" style={{ background: `${riskColor}22`, borderColor: riskColor, color: riskColor }}>
            {risk}
          </div>
          <div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: 'var(--text-primary)', fontWeight: 600 }}>
              {result.indicator}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 2 }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>
                {result.type}
              </span>
              {isLive && (
                <span style={{
                  fontSize: 9, padding: '1px 6px', borderRadius: 100, fontWeight: 700,
                  background: 'rgba(0,200,83,0.15)', color: 'var(--accent-green)',
                  border: '1px solid rgba(0,200,83,0.3)', letterSpacing: 0.5, textTransform: 'uppercase'
                }}>
                  LIVE
                </span>
              )}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {result.tags?.slice(0, 3).map(tag => (
            <span key={tag} className="ioc-tag">{tag}</span>
          ))}
          <button className="icon-btn" onClick={e => { e.stopPropagation(); onCopy(result.indicator); }}>
            <Copy size={12} />
          </button>
          {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div className="ioc-card-body" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}>

            {/* Source badges */}
            {result.source_names?.length > 0 && (
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 14 }}>
                {['VirusTotal', 'AlienVault OTX', 'Shodan', 'Censys'].map(s => (
                  <SourceBadge key={s} name={s} active={result.source_names?.includes(s)} />
                ))}
              </div>
            )}

            {/* Summary grid */}
            <div className="ioc-grid">
              <div className="ioc-field">
                <div className="ioc-field-label">Confidence</div>
                <ConfidenceMeter score={result.confidence || 0} />
              </div>
              <div className="ioc-field">
                <div className="ioc-field-label">Sources Reporting</div>
                <div className="ioc-field-value">{result.sources_reporting}</div>
              </div>
              <div className="ioc-field">
                <div className="ioc-field-label">First Seen</div>
                <div className="ioc-field-value" style={{ fontFamily: "'JetBrains Mono'" }}>
                  {result.first_seen ? new Date(result.first_seen).toLocaleDateString() : '—'}
                </div>
              </div>
              <div className="ioc-field">
                <div className="ioc-field-label">Last Seen</div>
                <div className="ioc-field-value" style={{ fontFamily: "'JetBrains Mono'" }}>
                  {result.last_seen ? new Date(result.last_seen).toLocaleDateString() : '—'}
                </div>
              </div>
              {result.geolocation && (
                <div className="ioc-field">
                  <div className="ioc-field-label">Geolocation</div>
                  <div className="ioc-field-value">
                    {result.geolocation.country}{result.geolocation.city ? `, ${result.geolocation.city}` : ''}
                    {result.geolocation.asn && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{result.geolocation.asn}</div>}
                  </div>
                </div>
              )}
              {result.threat_actors?.length > 0 && (
                <div className="ioc-field">
                  <div className="ioc-field-label">Threat Actors</div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {result.threat_actors.map(a => (
                      <span key={a} className="actor-tag">{a}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* ── VirusTotal Detail ── */}
            {vt && (vt.malicious > 0 || vt.harmless > 0) && (
              <div className="osint-source-section">
                <div className="osint-source-header">
                  <Eye size={13} /> VirusTotal Detection
                </div>
                <VTDetectionBar malicious={vt.malicious} suspicious={vt.suspicious} harmless={vt.harmless} undetected={vt.undetected} />
                {vt.suggested_threat_label && (
                  <div style={{ marginTop: 8, fontSize: 12, color: 'var(--severity-high)' }}>
                    Threat: <strong>{vt.suggested_threat_label}</strong>
                  </div>
                )}
                {vt.meaningful_name && (
                  <div style={{ marginTop: 4, fontSize: 11, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono'" }}>
                    {vt.meaningful_name}
                  </div>
                )}
              </div>
            )}

            {/* ── OTX Detail ── */}
            {otx && otx.pulse_count > 0 && (
              <div className="osint-source-section">
                <div className="osint-source-header">
                  <Activity size={13} /> AlienVault OTX — {otx.pulse_count} pulse{otx.pulse_count !== 1 ? 's' : ''}
                </div>
                {otx.pulses?.slice(0, 3).map((p, i) => (
                  <div key={i} className="otx-pulse-item">
                    <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>{p.name}</div>
                    {p.adversary && <span className="actor-tag" style={{ fontSize: 9, marginTop: 2 }}>{p.adversary}</span>}
                    {p.tags?.length > 0 && (
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                        {p.tags.slice(0, 5).map(t => (
                          <span key={t} className="ioc-tag" style={{ fontSize: 9 }}>{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* ── Shodan Detail ── */}
            {shodan && shodan.ports?.length > 0 && (
              <div className="osint-source-section">
                <div className="osint-source-header">
                  <Server size={13} /> Shodan — {shodan.ports.length} open port{shodan.ports.length !== 1 ? 's' : ''}
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
                  {shodan.ports.map(p => (
                    <span key={p} style={{
                      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                      fontFamily: "'JetBrains Mono'", background: 'rgba(0,163,255,0.08)',
                      border: '1px solid rgba(0,163,255,0.2)', color: 'var(--accent-blue)'
                    }}>{p}</span>
                  ))}
                </div>
                {shodan.org && <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Org: {shodan.org}</div>}
                {shodan.vulns?.length > 0 && (
                  <div style={{ marginTop: 6 }}>
                    <div style={{ fontSize: 10, color: 'var(--severity-critical)', fontWeight: 600, marginBottom: 4 }}>KNOWN VULNS</div>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {shodan.vulns.slice(0, 8).map(v => (
                        <span key={v} style={{
                          padding: '2px 6px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                          background: 'rgba(255,62,62,0.1)', border: '1px solid rgba(255,62,62,0.25)',
                          color: 'var(--severity-critical)', fontFamily: "'JetBrains Mono'"
                        }}>{v}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── Censys Detail ── */}
            {censys && censys.service_count > 0 && (
              <div className="osint-source-section">
                <div className="osint-source-header">
                  <Wifi size={13} /> Censys — {censys.service_count} service{censys.service_count !== 1 ? 's' : ''}
                </div>
                {censys.ports?.length > 0 && (
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {censys.ports.map(p => (
                      <span key={p} style={{
                        padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                        fontFamily: "'JetBrains Mono'", background: 'rgba(157,80,255,0.08)',
                        border: '1px solid rgba(157,80,255,0.2)', color: 'var(--accent-purple)'
                      }}>{p}</span>
                    ))}
                  </div>
                )}
                {censys.os && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>OS: {censys.os}</div>}
              </div>
            )}

            {/* Related IOCs */}
            {result.related_iocs?.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div className="ioc-field-label" style={{ marginBottom: 8 }}>Related IOCs</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {result.related_iocs.map((rel, i) => (
                    <div key={i} className="related-ioc">
                      <span className="ioc-type-badge">{rel.type}</span>
                      <span style={{ fontFamily: "'JetBrains Mono'", fontSize: 12 }}>{rel.value}</span>
                      <span className="relationship-badge">{rel.relationship}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </HoverCard>
  );
}

export default function IOCWorkbench() {
  const { addToast } = useToast();
  const [indicator, setIndicator] = useState('');
  const [iocType, setIocType] = useState('domain');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [bulkText, setBulkText] = useState('');
  const [mode, setMode] = useState('single'); // single | bulk
  const fileRef = useRef(null);

  const handleSingle = async () => {
    if (!indicator.trim()) return;
    setLoading(true);
    try {
      const result = await api.enrichIOC(indicator.trim(), iocType);
      setResults([result, ...results]);
      addToast(`IOC enriched: ${indicator.trim()}`, 'success');
    } catch (e) {
      addToast('Enrichment failed — check connection or API keys', 'warning');
    } finally {
      setLoading(false);
    }
  };

  const handleBulk = async () => {
    const lines = bulkText.split('\n').map(l => l.trim()).filter(Boolean);
    if (!lines.length) return;
    if (lines.length > 50) {
      addToast('Maximum 50 IOCs per bulk request', 'error');
      return;
    }
    setLoading(true);
    try {
      const indicators = lines.map(l => ({ indicator: l, type: iocType }));
      const res = await api.bulkIOC(indicators);
      setResults([...(res.results || []), ...results]);
      addToast(`Enriched ${res.total} IOCs`, 'success');
      setBulkText('');
    } catch {
      addToast('Bulk enrichment failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text).then(() => addToast('Copied to clipboard', 'info'));
  };

  const handleFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => setBulkText(ev.target.result);
    reader.readAsText(file);
  };

  return (
    <div className="fade-in">
      <HoverCard className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <div className="panel-title"><Search size={16} /> IOC Enrichment Workbench</div>
          <div style={{ display: 'flex', gap: 8 }}>
            {['single', 'bulk'].map(m => (
              <AnimatedButton key={m} className={`tab-btn ${mode === m ? 'active' : ''}`} onClick={() => setMode(m)}>
                {m === 'single' ? 'Single IOC' : 'Bulk Import'}
              </AnimatedButton>
            ))}
          </div>
        </div>

        <div className="panel-body">
          {/* IOC Type Selector */}
          <div className="ioc-type-row">
            {IOC_TYPES.map(t => (
              <AnimatedButton key={t.value} className={`ioc-type-btn ${iocType === t.value ? 'active' : ''}`}
                onClick={() => setIocType(t.value)}>
                <t.icon size={13} />
                {t.label}
              </AnimatedButton>
            ))}
          </div>

          {mode === 'single' ? (
            <div className="scan-form" style={{ marginTop: 12 }}>
              <input
                id="ioc-input"
                className="scan-input"
                type="text"
                placeholder={`Enter ${iocType} to enrich (e.g. suspicious.domain.com)`}
                value={indicator}
                onChange={e => setIndicator(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSingle()}
              />
              <AnimatedButton className="header-btn primary" onClick={handleSingle} disabled={loading || !indicator.trim()}>
                <Search size={14} />
                {loading ? 'Enriching...' : 'Enrich IOC'}
              </AnimatedButton>
            </div>
          ) : (
            <div style={{ marginTop: 12 }}>
              <textarea
                className="scan-input bulk-textarea"
                placeholder={"Paste IOCs (one per line, max 50)\ne.g.\n192.168.1.100\nmalicious.domain.com\nabc123def456..."}
                value={bulkText}
                onChange={e => setBulkText(e.target.value)}
                rows={6}
              />
              <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                <AnimatedButton className="header-btn" onClick={() => fileRef.current?.click()}>
                  <Upload size={14} /> Import File
                </AnimatedButton>
                <input ref={fileRef} type="file" accept=".txt,.csv" style={{ display: 'none' }} onChange={handleFile} />
                <AnimatedButton className="header-btn primary" onClick={handleBulk}
                  disabled={loading || !bulkText.trim()}>
                  <Search size={14} /> {loading ? 'Processing...' : `Enrich ${bulkText.split('\n').filter(l => l.trim()).length} IOCs`}
                </AnimatedButton>
              </div>
            </div>
          )}
        </div>
      </HoverCard>

      {/* Results */}
      {results.length > 0 && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 14, fontWeight: 600 }}>
              <CheckCircle size={14} color="var(--accent-green)" style={{ marginRight: 6 }} />
              {results.length} IOC{results.length !== 1 ? 's' : ''} enriched
            </div>
            <AnimatedButton className="header-btn" style={{ padding: '4px 10px', fontSize: 12 }}
              onClick={() => setResults([])}>
              Clear Results
            </AnimatedButton>
          </div>
          <StaggeredList>
            {results.map((r, i) => (
              <StaggeredItem key={`${r.indicator}-${i}`}>
                <IOCCard result={r} onCopy={handleCopy} />
              </StaggeredItem>
            ))}
          </StaggeredList>
        </div>
      )}

      {results.length === 0 && (
        <HoverCard className="panel" style={{ padding: 40, textAlign: 'center' }}>
          <Shield size={48} color="var(--text-muted)" style={{ marginBottom: 16 }} />
          <div style={{ color: 'var(--text-muted)', fontSize: 14 }}>
            Enter an IP, domain, file hash, or URL above to enrich with cross-source threat intelligence
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 8, opacity: 0.6 }}>
            Powered by VirusTotal · AlienVault OTX · Shodan · Censys
          </div>
        </HoverCard>
      )}
    </div>
  );
}
