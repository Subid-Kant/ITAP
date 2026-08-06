import { useState, useEffect } from 'react';
import { Database, Calendar, Shield, Activity, Target, ChevronRight, ArrowLeft } from 'lucide-react';
import { api } from '../services/api';

export default function HistoryView() {
  const [historyList, setHistoryList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedTargetId, setSelectedTargetId] = useState(null);
  const [targetDetails, setTargetDetails] = useState(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [error, setError] = useState(null);

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
    try {
      setDetailsLoading(true);
      const res = await api.get(`/history/target/${targetId}`);
      setTargetDetails(res);
    } catch (err) {
      console.error('Failed to load target details:', err);
    } finally {
      setDetailsLoading(false);
    }
  };

  if (loading) {
    return <div style={{ padding: 24 }}>Loading history...</div>;
  }

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

  // Detailed View
  if (selectedTargetId && targetDetails) {
    return (
      <div style={{ padding: 24 }}>
        <button 
          onClick={() => setSelectedTargetId(null)}
          style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'none', border: 'none', color: 'var(--accent-blue)', cursor: 'pointer', marginBottom: 24 }}
        >
          <ArrowLeft size={16} /> Back to History
        </button>
        
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header">
            <h3>Archived Scan: {targetDetails.target.domain}</h3>
            {targetDetails.target.ip_address && <span style={{ marginLeft: 16, color: 'var(--text-muted)' }}>{targetDetails.target.ip_address}</span>}
          </div>
          <div className="card-content">
            <p>Scanned on: {new Date(targetDetails.target.created_at).toLocaleString()}</p>
          </div>
        </div>

        <div className="dashboard-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }}>
          {/* Threats Table */}
          <div className="card" style={{ gridColumn: '1 / -1' }}>
            <div className="card-header">
              <h3>Detected Threats ({targetDetails.threats.length})</h3>
            </div>
            <div className="card-content">
              {targetDetails.threats.length === 0 ? (
                <p>No threats were found for this scan.</p>
              ) : (
                <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-light)' }}>
                      <th style={{ padding: '8px 0' }}>Title</th>
                      <th>Severity</th>
                      <th>Detected At</th>
                    </tr>
                  </thead>
                  <tbody>
                    {targetDetails.threats.map(threat => (
                      <tr key={threat.id} style={{ borderBottom: '1px solid var(--border-light)' }}>
                        <td style={{ padding: '8px 0' }}>{threat.title}</td>
                        <td>
                          <span style={{ 
                            padding: '2px 8px', 
                            borderRadius: 12, 
                            fontSize: 12, 
                            textTransform: 'uppercase',
                            background: threat.severity === 'critical' ? 'var(--danger)' : 
                                        threat.severity === 'high' ? 'var(--warning)' : 
                                        'var(--border-light)'
                          }}>
                            {threat.severity}
                          </span>
                        </td>
                        <td>{new Date(threat.detected_at).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Summary View
  return (
    <div style={{ padding: 24 }}>
      <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>System History</h2>
          <p style={{ color: 'var(--text-muted)' }}>View archived scan sessions and historical threat data.</p>
        </div>
        <button className="header-btn" onClick={fetchHistory} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 12px', background: 'var(--bg-card)', border: '1px solid var(--border-light)', borderRadius: 6, cursor: 'pointer', color: 'var(--text-main)' }}>
          <Database size={14} /> Refresh History
        </button>
      </div>

      {historyList.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: 48 }}>
          <Database size={48} color="var(--text-muted)" style={{ margin: '0 auto 16px' }} />
          <h3>No historical data</h3>
          <p style={{ color: 'var(--text-muted)' }}>Previous scans will appear here when a new session is started.</p>
        </div>
      ) : (
        <div className="card">
          <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-light)' }}>
                <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>Target Domain</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>Scan Date</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>Threats Found</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 600 }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {historyList.map(item => (
                <tr key={item.target_id} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={{ padding: '12px 16px', fontWeight: 500 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Target size={16} color="var(--accent-blue)" />
                      {item.domain}
                    </div>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)' }}>
                      <Calendar size={14} />
                      {new Date(item.created_at).toLocaleDateString()}
                    </div>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <AlertIcon count={item.threats_count} />
                      {item.threats_count}
                    </div>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <button 
                      onClick={() => loadTargetDetails(item.target_id)}
                      style={{ 
                        background: 'none', border: 'none', color: 'var(--accent-blue)', 
                        cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                        fontSize: 14, fontWeight: 500
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
      )}
    </div>
  );
}

function AlertIcon({ count }) {
  if (count === 0) return <Shield size={14} color="var(--success)" />;
  if (count < 5) return <Activity size={14} color="var(--warning)" />;
  return <Activity size={14} color="var(--danger)" />;
}
