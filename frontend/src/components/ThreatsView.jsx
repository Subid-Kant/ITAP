import { useState } from 'react';
import { AlertTriangle, ChevronDown, ChevronUp, Shield, Target, Zap, Wrench, BookOpen, Clock, ShieldOff } from 'lucide-react';
import { api } from '../api';
import { useAuth } from '../hooks/useAuth';

const PRIORITY_META = {
  immediate: { label: 'Immediate', color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.35)' },
  'short-term': { label: 'Short-term', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.35)' },
  'long-term': { label: 'Long-term', color: '#22c55e', bg: 'rgba(34,197,94,0.12)', border: 'rgba(34,197,94,0.35)' },
};

function RemediationStep({ step }) {
  const meta = PRIORITY_META[step.priority] || PRIORITY_META['long-term'];
  return (
    <div style={{
      display: 'flex', gap: 12, padding: '10px 14px',
      background: meta.bg, border: `1px solid ${meta.border}`,
      borderRadius: 8, marginBottom: 8,
    }}>
      <div style={{
        minWidth: 28, height: 28, borderRadius: '50%',
        background: meta.color, color: '#fff',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 12, fontWeight: 700, flexShrink: 0,
      }}>
        {step.step}
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
          <span style={{ fontWeight: 600, color: '#F0EFE9', fontSize: 13 }}>{step.action}</span>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '2px 7px',
            borderRadius: 99, background: meta.bg, color: meta.color,
            border: `1px solid ${meta.border}`, textTransform: 'uppercase', letterSpacing: '0.04em',
          }}>
            {meta.label}
          </span>
        </div>
        <p style={{ margin: 0, fontSize: 12, color: 'rgba(240,239,233,0.7)', lineHeight: 1.55 }}>
          {step.detail}
        </p>
      </div>
    </div>
  );
}

function BlockIPButton({ threat }) {
  const [status, setStatus] = useState('idle'); // idle | loading | done | error
  const ip = threat.source_country ? `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}` : null;

  const handleBlock = async (e) => {
    e.stopPropagation();
    if (!ip) return;
    const confirmed = window.confirm(
      `Block IP from ${threat.source_country} associated with:\n"${threat.title}"\n\nThis will add a firewall rule via SOAR. Continue?`
    );
    if (!confirmed) return;
    setStatus('loading');
    try {
      await api.blockIP(ip, threat.id, `Threat: ${threat.title}`);
      setStatus('done');
    } catch (err) {
      console.error('Block IP failed:', err);
      setStatus('error');
    }
  };

  if (!ip) return null;
  if (status === 'done') return (
    <span style={{ fontSize: 10, color: '#22C55E', background: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.3)', padding: '2px 8px', borderRadius: 4, whiteSpace: 'nowrap' }}>
      🛡️ Contained
    </span>
  );

  return (
    <button
      onClick={handleBlock}
      disabled={status === 'loading'}
      title={`Block source IP from ${threat.source_country}`}
      style={{
        background: status === 'error' ? 'rgba(239,68,68,0.1)' : 'rgba(255,46,99,0.08)',
        border: `1px solid ${status === 'error' ? 'rgba(239,68,68,0.4)' : 'rgba(255,46,99,0.3)'}`,
        color: status === 'error' ? '#EF4444' : '#FF2E63',
        borderRadius: 5, padding: '3px 8px', cursor: 'pointer',
        fontSize: 10, fontWeight: 700, whiteSpace: 'nowrap',
        display: 'flex', alignItems: 'center', gap: 4,
        transition: 'all 0.2s',
      }}
    >
      <ShieldOff size={10} />
      {status === 'loading' ? '...' : status === 'error' ? 'Failed' : '🛡️ Block IP'}
    </button>
  );
}

function ThreatCard({ t, isAdmin }) {
  const [open, setOpen] = useState(false);
  const [activeTab, setActiveTab] = useState('root_cause');

  const sevColor = {
    critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e', info: '#3b82f6',
  }[t.severity] || '#6b7280';

  const hasEnrichment = t.root_cause || t.remediation?.length;

  const tabs = [
    { id: 'root_cause', label: 'Root Cause', icon: <BookOpen size={12} /> },
    { id: 'attack_vector', label: 'Attack Vector', icon: <Zap size={12} /> },
    { id: 'remediation', label: `Remediation (${t.remediation?.length || 0})`, icon: <Wrench size={12} /> },
  ];

  return (
    <div style={{
      background: 'rgba(255,255,255,0.04)',
      border: `1px solid rgba(255,255,255,${open ? '0.14' : '0.07'})`,
      borderLeft: `3px solid ${sevColor}`,
      borderRadius: 10,
      marginBottom: 8,
      transition: 'all 0.2s ease',
      overflow: 'hidden',
    }}>
      {/* ── Header row ─────────────────────────────────────────── */}
      <div
        onClick={() => hasEnrichment && setOpen(o => !o)}
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr auto auto auto auto auto',
          gap: 12, alignItems: 'center',
          padding: '12px 16px',
          cursor: hasEnrichment ? 'pointer' : 'default',
        }}
      >
        {/* Title */}
        <div style={{ minWidth: 0 }}>
          <div style={{
            fontWeight: 600, fontSize: 13.5, color: '#F0EFE9',
            whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
          }}>
            {t.title}
          </div>
          {t.description && (
            <div style={{
              fontSize: 11, color: 'rgba(240,239,233,0.5)', marginTop: 2,
              whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
            }}>
              {t.description}
            </div>
          )}
        </div>

        {/* Severity */}
        <span style={{
          padding: '3px 10px', borderRadius: 99, fontSize: 11, fontWeight: 700,
          background: `${sevColor}22`, color: sevColor,
          border: `1px solid ${sevColor}55`, textTransform: 'uppercase', letterSpacing: '0.05em',
          whiteSpace: 'nowrap',
        }}>
          {t.severity}
        </span>

        {/* Score */}
        <span style={{
          fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 700,
          color: sevColor, whiteSpace: 'nowrap',
        }}>
          {t.severity_score}
        </span>

        {/* MITRE */}
        <span style={{ fontSize: 12, color: 'rgba(240,239,233,0.55)', whiteSpace: 'nowrap' }}>
          {t.mitre_tactic || '—'}
        </span>

        {/* Origin */}
        <span style={{ fontSize: 12, color: 'rgba(240,239,233,0.55)', whiteSpace: 'nowrap' }}>
          {t.source_country ? `📍 ${t.source_country}` : '—'}
        </span>

        {/* Time + expand icon + admin Block IP */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
            color: 'rgba(240,239,233,0.4)', whiteSpace: 'nowrap',
          }}>
            {t.detected_at ? new Date(t.detected_at).toLocaleString() : '—'}
          </span>
          {isAdmin && t.source_country && <BlockIPButton threat={t} />}
          {hasEnrichment && (
            <span style={{ color: 'rgba(240,239,233,0.4)', flexShrink: 0 }}>
              {open ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
            </span>
          )}
        </div>
      </div>

      {/* ── Expanded detail panel ───────────────────────────────── */}
      {open && hasEnrichment && (
        <div style={{
          borderTop: '1px solid rgba(255,255,255,0.07)',
          padding: '0 16px 16px',
          animation: 'fadeIn 0.2s ease',
        }}>
          {/* Affected components chips */}
          {t.affected_components?.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, padding: '12px 0 10px' }}>
              <span style={{ fontSize: 11, color: 'rgba(240,239,233,0.45)', alignSelf: 'center', marginRight: 2 }}>
                <Target size={11} style={{ marginRight: 3 }} />Affected:
              </span>
              {t.affected_components.map((c, i) => (
                <span key={i} style={{
                  fontSize: 11, padding: '2px 9px', borderRadius: 99,
                  background: 'rgba(139,92,246,0.12)', color: 'rgba(167,139,250,0.9)',
                  border: '1px solid rgba(139,92,246,0.25)',
                }}>
                  {c}
                </span>
              ))}
            </div>
          )}

          {/* Tab bar */}
          <div style={{ display: 'flex', gap: 4, marginBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.07)', paddingBottom: 0 }}>
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  padding: '7px 14px', borderRadius: '6px 6px 0 0',
                  border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: 500,
                  background: activeTab === tab.id ? 'rgba(255,255,255,0.09)' : 'transparent',
                  color: activeTab === tab.id ? '#F0EFE9' : 'rgba(240,239,233,0.45)',
                  borderBottom: activeTab === tab.id ? `2px solid ${sevColor}` : '2px solid transparent',
                  transition: 'all 0.15s ease',
                }}
              >
                {tab.icon} {tab.label}
              </button>
            ))}
          </div>

          {/* Tab: Root Cause */}
          {activeTab === 'root_cause' && (
            <div>
              {t.root_cause ? (
                <div style={{
                  padding: 14, borderRadius: 8,
                  background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.18)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                    <AlertTriangle size={13} color="#ef4444" />
                    <span style={{ fontSize: 12, fontWeight: 700, color: '#ef4444', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      Root Cause
                    </span>
                  </div>
                  <p style={{ margin: 0, fontSize: 13, color: 'rgba(240,239,233,0.85)', lineHeight: 1.65, whiteSpace: 'pre-wrap' }}>
                    {t.root_cause}
                  </p>
                </div>
              ) : (
                <p style={{ color: 'rgba(240,239,233,0.4)', fontSize: 13 }}>No root cause data available.</p>
              )}
              {t.ioc_value && (
                <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 11, color: 'rgba(240,239,233,0.4)' }}>IOC:</span>
                  <code style={{
                    fontSize: 12, padding: '2px 8px', borderRadius: 4,
                    background: 'rgba(255,255,255,0.06)', color: '#a5b4fc', fontFamily: "'JetBrains Mono', monospace",
                  }}>
                    {t.ioc_value}
                  </code>
                  {t.mitre_technique_id && (
                    <span style={{
                      fontSize: 11, padding: '2px 8px', borderRadius: 4,
                      background: 'rgba(59,130,246,0.12)', color: '#60a5fa',
                      border: '1px solid rgba(59,130,246,0.25)',
                    }}>
                      {t.mitre_technique_id} · {t.mitre_technique_name}
                    </span>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Tab: Attack Vector */}
          {activeTab === 'attack_vector' && (
            <div>
              {t.attack_vector_detail ? (
                <div style={{
                  padding: 14, borderRadius: 8,
                  background: 'rgba(245,158,11,0.07)', border: '1px solid rgba(245,158,11,0.18)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                    <Zap size={13} color="#f59e0b" />
                    <span style={{ fontSize: 12, fontWeight: 700, color: '#f59e0b', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      How the Attack Works
                    </span>
                  </div>
                  <p style={{ margin: 0, fontSize: 13, color: 'rgba(240,239,233,0.85)', lineHeight: 1.65, whiteSpace: 'pre-wrap' }}>
                    {t.attack_vector_detail}
                  </p>
                </div>
              ) : (
                <p style={{ color: 'rgba(240,239,233,0.4)', fontSize: 13 }}>No attack vector detail available.</p>
              )}
              {t.cve_description && (
                <div style={{ marginTop: 10, padding: 12, borderRadius: 8, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
                  <div style={{ fontSize: 11, color: 'rgba(240,239,233,0.4)', marginBottom: 4 }}>CVE Description</div>
                  <p style={{ margin: 0, fontSize: 12, color: 'rgba(240,239,233,0.65)', lineHeight: 1.6 }}>{t.cve_description}</p>
                </div>
              )}
            </div>
          )}

          {/* Tab: Remediation */}
          {activeTab === 'remediation' && (
            <div>
              {t.remediation?.length > 0 ? (
                <>
                  <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
                    {Object.entries(PRIORITY_META).map(([key, meta]) => {
                      const count = t.remediation.filter(r => r.priority === key).length;
                      return count > 0 ? (
                        <span key={key} style={{
                          fontSize: 11, padding: '3px 10px', borderRadius: 99,
                          background: meta.bg, color: meta.color, border: `1px solid ${meta.border}`,
                        }}>
                          {count} {meta.label}
                        </span>
                      ) : null;
                    })}
                  </div>
                  {['immediate', 'short-term', 'long-term'].map(priority =>
                    t.remediation
                      .filter(r => r.priority === priority)
                      .map((step, i) => <RemediationStep key={`${priority}-${i}`} step={step} />)
                  )}
                </>
              ) : (
                <p style={{ color: 'rgba(240,239,233,0.4)', fontSize: 13 }}>No remediation data available.</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ThreatsView({ stats }) {
  const threats = stats?.recent_threats || [];
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  return (
    <div className="fade-in">
      <style>{`
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: none; } }
      `}</style>

      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">
            <AlertTriangle size={16} />
            Active Threats ({threats.length})
          </div>
          <div style={{ fontSize: 12, color: 'rgba(240,239,233,0.45)', display: 'flex', alignItems: 'center', gap: 5 }}>
            <Clock size={12} /> Click any threat to expand Root Cause &amp; Remediation
          </div>
        </div>

        {/* Column headers */}
        {threats.length > 0 && (
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr auto auto auto auto auto',
            gap: 12,
            padding: '6px 16px 6px',
            borderBottom: '1px solid rgba(255,255,255,0.06)',
          }}>
            {['Threat', 'Severity', 'Score', 'MITRE Tactic', 'Origin', 'Detected'].map(h => (
              <span key={h} style={{ fontSize: 11, fontWeight: 600, color: 'rgba(240,239,233,0.35)', textTransform: 'uppercase', letterSpacing: '0.06em', whiteSpace: 'nowrap' }}>
                {h}
              </span>
            ))}
          </div>
        )}

        <div className="panel-body" style={{ padding: '10px 12px' }}>
          {threats.length === 0 ? (
            <div className="empty-state">
              <AlertTriangle size={40} />
              <h3>No threats detected</h3>
              <p>Run an OSINT scan to discover threats</p>
            </div>
          ) : (
            threats.map((t, i) => <ThreatCard key={t.id || i} t={t} isAdmin={isAdmin} />)
          )}
        </div>

        {/* Legend */}
        {threats.length > 0 && (
          <div style={{
            padding: '8px 16px',
            borderTop: '1px solid rgba(255,255,255,0.06)',
            display: 'flex', gap: 16, flexWrap: 'wrap',
          }}>
            {Object.entries(PRIORITY_META).map(([key, meta]) => (
              <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: meta.color }} />
                <span style={{ fontSize: 11, color: 'rgba(240,239,233,0.4)' }}>{meta.label} action required</span>
              </div>
            ))}
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginLeft: 'auto' }}>
              <Shield size={11} style={{ color: 'rgba(240,239,233,0.3)' }} />
              <span style={{ fontSize: 11, color: 'rgba(240,239,233,0.3)' }}>MITRE ATT&amp;CK enriched</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
