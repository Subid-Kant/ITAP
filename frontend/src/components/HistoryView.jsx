import { useState, useEffect } from 'react';
import { Database, Calendar, Shield, Activity, Target, ChevronRight, ArrowLeft, Trash2, RefreshCw, Archive } from 'lucide-react';
import { api } from '../api';

export default function HistoryView() {
  const [historyList, setHistoryList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedTargetId, setSelectedTargetId] = useState(null);
  const [targetDetails, setTargetDetails] = useState(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailsError, setDetailsError] = useState(null);
  const [error, setError] = useState(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.get('/history/summary');
      setHistoryList(res.history || []);
    } catch (err) {
      console.error('Failed to fetch history:', err);
      setError('Failed to load history data');
    } finally {
      setLoading(false);
    }
  };

  const loadTargetDetails = async (targetId) => {
    setSelectedTargetId(targetId);
    setTargetDetails(null);
    setDetailsError(null);
    setDetailsLoading(true);
    try {
      const res = await api.get(`/history/target/${targetId}`);
      setTargetDetails(res);
    } catch (err) {
      console.error('Failed to load target details:', err);
      setDetailsError('Failed to load scan details. Please try again.');
    } finally {
      setDetailsLoading(false);
    }
  };

  const handleDeleteAll = async () => {
    if (!window.confirm('⚠️ Are you sure you want to permanently delete ALL scan history?\n\nThis will remove all targets, scans, threats, and incidents from the database.\nThis action cannot be undone.')) return;
    try {
      setDeleting(true);
      await api.deleteAllHistory();
      setHistoryList([]);
      setSelectedTargetId(null);
      setTargetDetails(null);
    } catch (err) {
      console.error('Failed to delete history:', err);
      alert('Failed to delete history: ' + (err.message || 'Unknown error'));
    } finally {
      setDeleting(false);
    }
  };

  const handleBack = () => {
    setSelectedTargetId(null);
    setTargetDetails(null);
    setDetailsError(null);
  };

  // ── Loading state ──────────────────────────────────────────
  if (loading) {
    return (
      <div style={{ padding: 24, display: 'flex', alignItems: 'center', gap: 12, color: 'var(--text-muted)' }}>
        <div className="scanning-ring" style={{ width: 20, height: 20 }} />
        Loading history...
      </div>
    );
  }

  // ── Error state ────────────────────────────────────────────
  if (error) {
    return (
      <div style={{ padding: 24, color: 'var(--danger)', display: 'flex', alignItems: 'center', gap: 12 }}>
        {error}
        <button
          onClick={fetchHistory}
          style={{ marginLeft: 12, padding: '4px 12px', background: 'var(--bg-card)', border: '1px solid var(--border-light)', borderRadius: 6, cursor: 'pointer', color: 'var(--text-main)', fontSize: 13 }}
        >
          Retry
        </button>
      </div>
    );
  }

  // ── Detailed View ──────────────────────────────────────────
  if (selectedTargetId) {
    return (
      <div style={{ padding: 24 }}>
        <button
          onClick={handleBack}
          style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'none', border: 'none', color: 'var(--accent-blue)', cursor: 'pointer', marginBottom: 24, fontSize: 14 }}
        >
          <ArrowLeft size={16} /> Back to History
        </button>

        {/* Loading state for details */}
        {detailsLoading && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, color: 'var(--text-muted)', padding: '32px 0' }}>
            <div className="scanning-ring" style={{ width: 20, height: 20 }} />
            Loading scan details...
          </div>
        )}

        {/* Error state for details */}
        {detailsError && !detailsLoading && (
          <div style={{ color: 'var(--danger)', padding: 24, background: 'var(--bg-card)', borderRadius: 8, border: '1px solid var(--border-light)', display: 'flex', alignItems: 'center', gap: 12 }}>
            {detailsError}
            <button
              onClick={() => loadTargetDetails(selectedTargetId)}
              style={{ marginLeft: 12, padding: '4px 12px', background: 'var(--bg-card)', border: '1px solid var(--border-light)', borderRadius: 6, cursor: 'pointer', color: 'var(--text-main)', fontSize: 13 }}
            >
              Retry
            </button>
          </div>
        )}

        {/* Details loaded successfully */}
        {targetDetails && !detailsLoading && (
          <>
            <div className="panel" style={{ marginBottom: 24 }}>
              <div className="panel-header">
                <div className="panel-title">
                  <Target size={16} />
                  {targetDetails.target.domain}
                  {targetDetails.target.is_archived && (
                    <span style={{ marginLeft: 10, padding: '2px 8px', background: 'rgba(55,138,221,0.15)', borderRadius: 4, fontSize: 11, color: 'var(--accent-blue)' }}>
                      ARCHIVED
                    </span>
                  )}
                </div>
                {targetDetails.target.ip_address && (
                  <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>
                    {targetDetails.target.ip_address}
                  </span>
                )}
              </div>
              <div className="panel-body">
                <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>
                  Scanned on: {new Date(targetDetails.target.created_at).toLocaleString()}
                </div>
                <div style={{ display: 'flex', gap: 16, marginTop: 12 }}>
                  <div className="stat-card" style={{ flex: '0 0 auto' }}>
                    <div className="stat-value">{targetDetails.scans.length}</div>
                    <div className="stat-label">Scans Run</div>
                  </div>
                  <div className="stat-card" style={{ flex: '0 0 auto' }}>
                    <div className="stat-value">{targetDetails.threats.length}</div>
                    <div className="stat-label">Threats Found</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Threats Table */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title"><Shield size={16} /> Detected Threats ({targetDetails.threats.length})</div>
              </div>
              <div className="panel-body no-pad">
                {targetDetails.threats.length === 0 ? (
                  <div style={{ padding: 24, color: 'var(--text-muted)', textAlign: 'center' }}>
                    <Shield size={32} color="var(--success)" style={{ margin: '0 auto 12px', display: 'block' }} />
                    No threats were detected for this scan.
                  </div>
                ) : (
                  <table className="threat-table">
                    <thead>
                      <tr>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Detected At</th>
                      </tr>
                    </thead>
                    <tbody>
                      {targetDetails.threats.map(threat => (
                        <tr key={threat.id}>
                          <td style={{ fontWeight: 500, color: '#F0EFE9' }}>{threat.title}</td>
                          <td>
                            <span className={`severity-badge ${threat.severity?.toLowerCase() || 'medium'}`}>
                              {threat.severity}
                            </span>
                          </td>
                          <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                            {threat.detected_at ? new Date(threat.detected_at).toLocaleString() : '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            {/* Scans Table */}
            {targetDetails.scans.length > 0 && (
              <div className="panel" style={{ marginTop: 16 }}>
                <div className="panel-header">
                  <div className="panel-title"><Activity size={16} /> Scan Records ({targetDetails.scans.length})</div>
                </div>
                <div className="panel-body no-pad">
                  <table className="threat-table">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Risk Score</th>
                        <th>Started At</th>
                      </tr>
                    </thead>
                    <tbody>
                      {targetDetails.scans.map(scan => (
                        <tr key={scan.id}>
                          <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{scan.type}</td>
                          <td><span className={`status-badge ${scan.status}`}>● {scan.status}</span></td>
                          <td>{scan.risk_score ?? '—'}</td>
                          <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                            {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    );
  }

  // ── Summary / List View ────────────────────────────────────
  return (
    <div style={{ padding: 24 }}>
      <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h2 style={{ margin: 0, marginBottom: 4 }}>System History</h2>
          <p style={{ color: 'var(--text-muted)', margin: 0, fontSize: 13 }}>
            All OSINT scan sessions. Click "View Report" to see threats detected per target.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={fetchHistory}
            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', background: 'var(--bg-card)', border: '1px solid var(--border-light)', borderRadius: 6, cursor: 'pointer', color: 'var(--text-main)', fontSize: 13 }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
          {historyList.length > 0 && (
            <button
              onClick={handleDeleteAll}
              disabled={deleting}
              style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 6, cursor: deleting ? 'not-allowed' : 'pointer', color: '#EF4444', fontSize: 13, opacity: deleting ? 0.6 : 1 }}
            >
              <Trash2 size={14} /> {deleting ? 'Deleting...' : 'Delete All History'}
            </button>
          )}
        </div>
      </div>

      {historyList.length === 0 ? (
        <div className="panel" style={{ textAlign: 'center', padding: 48 }}>
          <Database size={48} color="var(--text-muted)" style={{ margin: '0 auto 16px', display: 'block' }} />
          <h3>No scan history</h3>
          <p style={{ color: 'var(--text-muted)' }}>Scan a domain from the OSINT Scanner to see results here.</p>
        </div>
      ) : (
        <div className="panel">
          <div className="panel-body no-pad">
            <table className="threat-table">
              <thead>
                <tr>
                  <th>Target Domain</th>
                  <th>Scan Date</th>
                  <th>Threats Found</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {historyList.map(item => (
                  <tr key={item.target_id}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 500, color: '#F0EFE9' }}>
                        <Target size={14} color="var(--accent-blue)" />
                        {item.domain}
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)', fontSize: 13 }}>
                        <Calendar size={13} />
                        {new Date(item.created_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <AlertIcon count={item.threats_count} />
                        <span style={{ fontWeight: 600, color: item.threats_count > 0 ? '#F59E0B' : '#22C55E' }}>
                          {item.threats_count}
                        </span>
                      </div>
                    </td>
                    <td>
                      {item.is_archived ? (
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-muted)', fontSize: 12 }}>
                          <Archive size={12} /> Archived
                        </span>
                      ) : (
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#22C55E', fontSize: 12 }}>
                          ● Active
                        </span>
                      )}
                    </td>
                    <td>
                      <button
                        onClick={() => loadTargetDetails(item.target_id)}
                        style={{
                          background: 'none', border: 'none', color: 'var(--accent-blue)',
                          cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                          fontSize: 13, fontWeight: 500, padding: '4px 0'
                        }}
                      >
                        View Report <ChevronRight size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function AlertIcon({ count }) {
  if (count === 0) return <Shield size={14} color="var(--success)" />;
  if (count < 5) return <Activity size={14} color="var(--warning)" />;
  return <Activity size={14} color="var(--danger)" />;
}
