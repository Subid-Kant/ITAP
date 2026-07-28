import { useState, useRef } from 'react';
import { Search, Upload, Shield, Globe, Hash, Link, AlertTriangle, CheckCircle, ChevronDown, ChevronUp, Copy } from 'lucide-react';
import { api } from '../api';
import { useToast } from './ToastNotification';

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

function IOCCard({ result, onCopy }) {
  const [expanded, setExpanded] = useState(false);
  const risk = result.risk_score || 0;
  const riskColor = risk >= 80 ? 'var(--severity-critical)' : risk >= 60 ? 'var(--severity-high)' : risk >= 40 ? 'var(--severity-medium)' : 'var(--accent-green)';

  return (
    <div className="panel ioc-card" style={{ marginBottom: 12, borderColor: `${riskColor}33` }}>
      <div className="ioc-card-header" onClick={() => setExpanded(e => !e)}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1 }}>
          <div className="ioc-risk-badge" style={{ background: `${riskColor}22`, borderColor: riskColor, color: riskColor }}>
            {risk}
          </div>
          <div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: 'var(--text-primary)', fontWeight: 600 }}>
              {result.indicator}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, textTransform: 'uppercase', letterSpacing: 1 }}>
              {result.type}
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

      {expanded && (
        <div className="ioc-card-body">
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
                  {result.geolocation.country} · {result.geolocation.asn}
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
        </div>
      )}
    </div>
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
      addToast('Enrichment failed — using demo mode', 'warning');
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
      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <div className="panel-title"><Search size={16} /> IOC Enrichment Workbench</div>
          <div style={{ display: 'flex', gap: 8 }}>
            {['single', 'bulk'].map(m => (
              <button key={m} className={`tab-btn ${mode === m ? 'active' : ''}`} onClick={() => setMode(m)}>
                {m === 'single' ? 'Single IOC' : 'Bulk Import'}
              </button>
            ))}
          </div>
        </div>

        <div className="panel-body">
          {/* IOC Type Selector */}
          <div className="ioc-type-row">
            {IOC_TYPES.map(t => (
              <button key={t.value} className={`ioc-type-btn ${iocType === t.value ? 'active' : ''}`}
                onClick={() => setIocType(t.value)}>
                <t.icon size={13} />
                {t.label}
              </button>
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
              <button className="header-btn primary" onClick={handleSingle} disabled={loading || !indicator.trim()}>
                <Search size={14} />
                {loading ? 'Enriching...' : 'Enrich IOC'}
              </button>
            </div>
          ) : (
            <div style={{ marginTop: 12 }}>
              <textarea
                className="scan-input bulk-textarea"
                placeholder="Paste IOCs (one per line, max 50)&#10;e.g.&#10;192.168.1.100&#10;malicious.domain.com&#10;abc123def456..."
                value={bulkText}
                onChange={e => setBulkText(e.target.value)}
                rows={6}
              />
              <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                <button className="header-btn" onClick={() => fileRef.current?.click()}>
                  <Upload size={14} /> Import File
                </button>
                <input ref={fileRef} type="file" accept=".txt,.csv" style={{ display: 'none' }} onChange={handleFile} />
                <button className="header-btn primary" onClick={handleBulk}
                  disabled={loading || !bulkText.trim()}>
                  <Search size={14} /> {loading ? 'Processing...' : `Enrich ${bulkText.split('\n').filter(l => l.trim()).length} IOCs`}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Results */}
      {results.length > 0 && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 14, fontWeight: 600 }}>
              <CheckCircle size={14} color="var(--accent-green)" style={{ marginRight: 6 }} />
              {results.length} IOC{results.length !== 1 ? 's' : ''} enriched
            </div>
            <button className="header-btn" style={{ padding: '4px 10px', fontSize: 12 }}
              onClick={() => setResults([])}>
              Clear Results
            </button>
          </div>
          {results.map((r, i) => (
            <IOCCard key={`${r.indicator}-${i}`} result={r} onCopy={handleCopy} />
          ))}
        </div>
      )}

      {results.length === 0 && (
        <div className="panel" style={{ padding: 40, textAlign: 'center' }}>
          <Shield size={48} color="var(--text-muted)" style={{ marginBottom: 16 }} />
          <div style={{ color: 'var(--text-muted)', fontSize: 14 }}>
            Enter an IP, domain, file hash, or URL above to enrich with cross-source threat intelligence
          </div>
        </div>
      )}
    </div>
  );
}
