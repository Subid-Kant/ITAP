// ITAP — Audit Log view (admin only).
// Read-only window into the append-only trail written by
// app/services/audit_service.py: who did what, when, from where, and what
// changed. The API refuses non-admin roles with 403 — that case renders as an
// explicit "admin only" panel rather than an empty table, so a denied role can
// never mistake access control for an empty trail.
import { useState, useEffect, useCallback, Fragment } from 'react';
import { ShieldCheck, RefreshCw, ChevronDown, ChevronRight, Search, Filter } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { api } from '../api';
import HoverCard from './ui/HoverCard';
import AnimatedButton from './ui/AnimatedButton';

const KNOWN_ACTIONS = [
  'auth.login', 'auth.login.failure', 'auth.logout',
  'target.delete', 'history.delete_all', 'system.new_session',
  'ip.block', 'ip.unblock',
];

const OUTCOME_STYLE = {
  success: { color: '#3fb950', border: 'rgba(63,185,80,0.35)', bg: 'rgba(63,185,80,0.10)' },
  failure: { color: '#f85149', border: 'rgba(248,81,73,0.35)', bg: 'rgba(248,81,73,0.10)' },
  denied: { color: '#d29922', border: 'rgba(210,153,34,0.35)', bg: 'rgba(210,153,34,0.10)' },
};

const PRE_STYLE = {
  margin: 0, padding: '6px 10px', background: 'rgba(0,0,0,0.35)',
  border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)',
  fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#9ecbff',
  maxWidth: 420, overflowX: 'auto',
};

const containerVariants = { hidden: {}, show: { transition: { staggerChildren: 0.05 } } };
const itemVariants = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso.endsWith('Z') ? iso : iso + 'Z');
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
}

function Select({ value, onChange, children, title }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      title={title}
      style={{
        background: 'var(--bg-card)', color: 'var(--text-primary)',
        border: '1px solid var(--border-primary)', borderRadius: 'var(--radius-sm)',
        padding: '7px 10px', fontSize: 12, cursor: 'pointer', outline: 'none',
      }}
    >
      {children}
    </select>
  );
}

export default function AuditLogView() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [denied, setDenied] = useState(false);
  const [expanded, setExpanded] = useState(null);
  const [filters, setFilters] = useState({
    limit: '100', since_days: '', action: '', outcome: '', actor: '',
  });

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      setDenied(false);
      const params = {};
      if (filters.limit) params.limit = filters.limit;
      if (filters.since_days) params.since_days = filters.since_days;
      if (filters.action) params.action = filters.action;
      if (filters.outcome) params.outcome = filters.outcome;
      if (filters.actor.trim()) params.actor = filters.actor.trim();
      const res = await api.getAuditLog(params);
      setData(res);
      setExpanded(null);
    } catch (err) {
      if (err?.status === 403) {
        setDenied(true);
        setData(null);
      } else {
        setError(err?.message || 'Failed to load the audit trail');
      }
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => { load(); }, [load]);

  const set = (key) => (value) => setFilters((f) => ({ ...f, [key]: value }));

  const actionOptions = [...new Set([
    ...KNOWN_ACTIONS,
    ...(data?.entries || []).map((e) => e.action),
  ])].sort();

  if (denied) {
    return (
      <HoverCard className="panel" style={{ padding: 32, textAlign: 'center' }}>
        <ShieldCheck size={40} color="var(--accent-blue)" style={{ marginBottom: 12 }} />
        <h2 style={{ fontSize: 16, marginBottom: 6 }}>Administrator access required</h2>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
          The audit trail is admin-only by design — analysts and viewers cannot read it.
        </p>
      </HoverCard>
    );
  }

  const entries = data?.entries || [];

  return (
    <motion.div variants={containerVariants} initial="hidden" animate="show">
      <motion.div variants={itemVariants}>
        <HoverCard className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <ShieldCheck size={16} /> Audit Log
              <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400, marginLeft: 8 }}>
                append-only record of privileged actions · admin only
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              {data && (
                <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>
                  {data.count} shown / {data.total_rows} total
                </span>
              )}
              <AnimatedButton variant="secondary" onClick={load} disabled={loading} title="Refresh">
                <RefreshCw size={14} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
              </AnimatedButton>
            </div>
          </div>

          {/* Filters */}
          <div style={{
            display: 'flex', flexWrap: 'wrap', gap: 8, padding: '12px 16px',
            borderTop: '1px solid var(--border-subtle)', alignItems: 'center',
          }}>
            <Filter size={14} color="var(--text-muted)" />
            <Select value={filters.action} onChange={set('action')} title="Action">
              <option value="">All actions</option>
              {actionOptions.map((a) => <option key={a} value={a}>{a}</option>)}
            </Select>
            <Select value={filters.outcome} onChange={set('outcome')} title="Outcome">
              <option value="">All outcomes</option>
              <option value="success">success</option>
              <option value="failure">failure</option>
              <option value="denied">denied</option>
            </Select>
            <Select value={filters.since_days} onChange={set('since_days')} title="Time window">
              <option value="">All time</option>
              <option value="1">Last 24 h</option>
              <option value="7">Last 7 days</option>
              <option value="30">Last 30 days</option>
              <option value="90">Last 90 days</option>
            </Select>
            <Select value={filters.limit} onChange={set('limit')} title="Row limit">
              {[25, 50, 100, 250, 500].map((n) => <option key={n} value={String(n)}>Limit {n}</option>)}
            </Select>
            <div style={{ position: 'relative', flex: '1 1 180px', minWidth: 160 }}>
              <Search size={13} color="var(--text-muted)" style={{ position: 'absolute', left: 9, top: 9 }} />
              <input
                value={filters.actor}
                onChange={(e) => set('actor')(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && load()}
                placeholder="Filter by actor (username)…"
                style={{
                  width: '100%', boxSizing: 'border-box', padding: '7px 10px 7px 28px',
                  background: 'var(--bg-card)', color: 'var(--text-primary)',
                  border: '1px solid var(--border-primary)', borderRadius: 'var(--radius-sm)',
                  fontSize: 12, outline: 'none',
                }}
              />
            </div>
          </div>

          {/* Body */}
          <div className="panel-body no-pad">
            {error && (
              <div style={{ padding: 20, color: '#f85149', fontSize: 13 }}>{error}</div>
            )}
            {!error && loading && !data && (
              <div style={{ padding: 20, color: 'var(--text-muted)', fontSize: 13 }}>Loading trail…</div>
            )}
            {!error && !loading && data && entries.length === 0 && (
              <div style={{ padding: 24, color: 'var(--text-muted)', fontSize: 13, textAlign: 'center' }}>
                No audit entries match these filters.
              </div>
            )}
            {!error && entries.length > 0 && (
              <table className="threat-table">
                <thead>
                  <tr>
                    <th style={{ width: 30 }}></th>
                    <th>Time (UTC)</th>
                    <th>Actor</th>
                    <th>Role</th>
                    <th>Action</th>
                    <th>Outcome</th>
                    <th>Resource</th>
                    <th>IP</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((e) => (
                    <Fragment key={e.id}>
                      <motion.tr
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        onClick={() => setExpanded(expanded === e.id ? null : e.id)}
                        style={{ cursor: 'pointer' }}
                      >
                        <td style={{ textAlign: 'center' }}>
                          {expanded === e.id
                            ? <ChevronDown size={13} color="var(--text-muted)" />
                            : <ChevronRight size={13} color="var(--text-muted)" />}
                        </td>
                        <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, whiteSpace: 'nowrap' }}>
                          {fmtTime(e.created_at)}
                        </td>
                        <td style={{ fontWeight: 600 }}>{e.actor}</td>
                        <td style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                          {e.actor_role || '—'}
                        </td>
                        <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>{e.action}</td>
                        <td>
                          <span style={{
                            fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: 'uppercase',
                            padding: '2px 8px', borderRadius: 10,
                            color: (OUTCOME_STYLE[e.outcome] || OUTCOME_STYLE.success).color,
                            border: `1px solid ${(OUTCOME_STYLE[e.outcome] || OUTCOME_STYLE.success).border}`,
                            background: (OUTCOME_STYLE[e.outcome] || OUTCOME_STYLE.success).bg,
                          }}>
                            {e.outcome}
                          </span>
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {e.resource_type || '—'}{e.resource_id ? ` · ${String(e.resource_id).slice(0, 8)}` : ''}
                        </td>
                        <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>
                          {e.ip_address || '—'}
                        </td>
                      </motion.tr>
                      <AnimatePresence>
                        {expanded === e.id && (
                          <tr key={`${e.id}-detail`}>
                            <td colSpan={8} style={{ background: 'rgba(255,255,255,0.02)', padding: '10px 16px' }}>
                              <div style={{ fontSize: 12, color: 'var(--text-primary)', marginBottom: 8 }}>
                                {e.detail || <span style={{ color: 'var(--text-muted)' }}>No detail recorded.</span>}
                              </div>
                              <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 11, alignItems: 'flex-start' }}>
                                {e.request_id && (
                                  <span style={{ color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>
                                    request_id={e.request_id}
                                  </span>
                                )}
                                {e.before_state && (
                                  <pre style={PRE_STYLE}>before: {JSON.stringify(e.before_state, null, 2)}</pre>
                                )}
                                {e.after_state && (
                                  <pre style={PRE_STYLE}>after: {JSON.stringify(e.after_state, null, 2)}</pre>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </AnimatePresence>
                    </Fragment>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </HoverCard>
      </motion.div>
    </motion.div>
  );
}
