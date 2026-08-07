import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Target, ChevronRight, Activity, ShieldAlert, CheckCircle,
  AlertTriangle, Terminal, Eye, Shield, Zap, Clock, TrendingUp,
  ChevronDown, ChevronUp, Copy, Check, RefreshCw
} from 'lucide-react';
import { api } from '../api';

const PHASES = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact'
];

const PRIORITY_CONFIG = {
  CRITICAL: { color: '#FF3B5C', bg: 'rgba(255,59,92,0.12)', label: '🔴 CRITICAL' },
  HIGH:     { color: '#F59E0B', bg: 'rgba(245,158,11,0.12)', label: '🟠 HIGH' },
  MEDIUM:   { color: '#378ADD', bg: 'rgba(55,138,221,0.12)', label: '🔵 MEDIUM' },
};

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <button
      onClick={copy}
      title="Copy command"
      style={{
        background: 'none', border: 'none', cursor: 'pointer',
        color: copied ? '#22C55E' : '#6B7280', padding: '2px 4px',
        borderRadius: 4, transition: 'color 0.2s', flexShrink: 0
      }}
    >
      {copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

function PhaseDetailPanel({ phaseData, isCompleted, isCurrent }) {
  const [expanded, setExpanded] = useState(true);
  if (!phaseData) return null;
  const pConfig = PRIORITY_CONFIG[phaseData.priority] || PRIORITY_CONFIG.MEDIUM;

  return (
    <div style={{
      background: 'rgba(10,14,23,0.6)',
      border: `1px solid ${isCurrent ? '#F59E0B' : isCompleted ? 'rgba(255,59,92,0.3)' : 'rgba(55,138,221,0.25)'}`,
      borderRadius: 10,
      overflow: 'hidden',
      transition: 'all 0.3s ease',
    }}>
      {/* Header */}
      <div
        onClick={() => setExpanded(e => !e)}
        style={{
          display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px',
          cursor: 'pointer',
          background: isCurrent ? 'rgba(245,158,11,0.08)' : isCompleted ? 'rgba(255,59,92,0.08)' : 'rgba(55,138,221,0.06)',
        }}
      >
        <span style={{ fontSize: 11, fontWeight: 700, color: pConfig.color,
          background: pConfig.bg, padding: '2px 7px', borderRadius: 4, whiteSpace: 'nowrap' }}>
          {pConfig.label}
        </span>
        <span style={{ fontSize: 12, color: '#B4B2A9', flex: 1, lineHeight: 1.4 }}>
          {phaseData.summary}
        </span>
        {expanded ? <ChevronUp size={14} color="#6B7280" /> : <ChevronDown size={14} color="#6B7280" />}
      </div>

      {/* Body */}
      {expanded && (
        <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Indicators of Compromise */}
          {phaseData.indicators?.length > 0 && (
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#FF3B5C', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 5 }}>
                <Eye size={10} /> Indicators of Compromise
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {phaseData.indicators.map((ind, i) => (
                  <span key={i} style={{ fontSize: 10, color: '#F59E0B', background: 'rgba(245,158,11,0.08)', padding: '3px 8px', borderRadius: 12, border: '1px solid rgba(245,158,11,0.2)' }}>
                    {ind}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Mitigation Measures */}
          {phaseData.mitigations?.length > 0 && (
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#22C55E', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 5 }}>
                <Shield size={10} /> Mitigation Measures
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {phaseData.mitigations.map((m, i) => (
                  <div key={i} style={{ fontSize: 11, color: '#B4B2A9', display: 'flex', alignItems: 'flex-start', gap: 6 }}>
                    <span style={{ color: '#22C55E', marginTop: 1, flexShrink: 0 }}>✓</span>
                    {m}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Commands */}
          {phaseData.commands?.length > 0 && (
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#378ADD', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 5 }}>
                <Terminal size={10} /> Response Commands
              </div>
              <div style={{ background: '#050709', borderRadius: 6, border: '1px solid rgba(55,138,221,0.15)', overflow: 'hidden' }}>
                {phaseData.commands.map((cmd, i) => (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    padding: '5px 10px',
                    borderBottom: i < phaseData.commands.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                    background: cmd.startsWith('#') ? 'rgba(55,138,221,0.05)' : 'transparent'
                  }}>
                    <span style={{ color: cmd.startsWith('#') ? '#378ADD' : '#22C55E', fontSize: 10, flexShrink: 0 }}>
                      {cmd.startsWith('#') ? '//' : '$'}
                    </span>
                    <code style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 10, color: cmd.startsWith('#') ? '#6B7280' : '#E2E8F0',
                      flex: 1, wordBreak: 'break-all', lineHeight: 1.5
                    }}>{cmd}</code>
                    {!cmd.startsWith('#') && <CopyButton text={cmd} />}
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

export default function KillChainView({ stats }) {
  const [killChainData, setKillChainData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedPhaseIdx, setSelectedPhaseIdx] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [selectedThreatId, setSelectedThreatId] = useState('');

  // All available threats with kill chain phase data
  const availableThreats = useMemo(() =>
    (stats?.recent_threats || []).filter(t => t.kill_chain_phase || t.mitre_tactic),
    [stats]
  );

  // Selected threat object
  const selectedThreat = useMemo(() =>
    availableThreats.find(t => t.id === selectedThreatId) || null,
    [availableThreats, selectedThreatId]
  );

  // Derive current phase from threats (use selected threat's phase if one is chosen)
  const detectedTactics = useMemo(
    () => new Set((stats?.mitre_attack_coverage || []).map(c => c.tactic)),
    [stats]
  );

  const currentIdx = useMemo(() => {
    // If a specific threat is selected, use its kill chain phase
    if (selectedThreat?.kill_chain_phase) {
      const idx = PHASES.indexOf(selectedThreat.kill_chain_phase);
      if (idx !== -1) return idx;
    }
    return PHASES.reduce((max, phase, idx) => {
      const match = [...detectedTactics].some(t =>
        t.toLowerCase().includes(phase.toLowerCase().split(' ')[0].toLowerCase())
      );
      return match ? Math.max(max, idx) : max;
    }, 2);
  }, [detectedTactics, selectedThreat]);

  const currentPhase = PHASES[currentIdx];

  const relatedThreat = useMemo(() =>
    selectedThreat || stats?.recent_threats?.find(t =>
      t.mitre_tactic && t.mitre_tactic.toLowerCase().includes(currentPhase.toLowerCase().split(' ')[0].toLowerCase())
    ),
    [stats, currentPhase, selectedThreat]
  );

  const loadKillChain = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getKillChain(currentPhase, relatedThreat?.id || '');
      setKillChainData(data);
      // Auto-select the current phase detail on first load
      if (selectedPhaseIdx === null) setSelectedPhaseIdx(currentIdx);
    } catch (e) {
      console.error('Failed to fetch kill chain data', e);
    } finally {
      setLoading(false);
    }
  }, [currentPhase, relatedThreat?.id]);

  useEffect(() => {
    loadKillChain();
  }, [currentPhase, refreshKey]);

  // Determine which phase is selected and what data to show
  const selectedPhase = selectedPhaseIdx !== null ? PHASES[selectedPhaseIdx] : currentPhase;
  const isSelectedCompleted = selectedPhaseIdx !== null && selectedPhaseIdx < currentIdx;
  const isSelectedCurrent   = selectedPhaseIdx === currentIdx;
  const isSelectedPredicted = selectedPhaseIdx !== null && selectedPhaseIdx > currentIdx;

  const selectedPhaseData = useMemo(() => {
    if (!killChainData) return null;
    if (isSelectedCompleted || isSelectedCurrent) {
      return killChainData.completed_phase_details?.find(p => p.phase === selectedPhase);
    }
    return killChainData.predicted_next_phases?.find(p => p.phase === selectedPhase);
  }, [killChainData, selectedPhase, isSelectedCompleted, isSelectedCurrent]);

  if (!stats || stats.active_threats === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60vh', textAlign: 'center' }}>
        <div style={{ background: 'rgba(55,138,221,0.1)', padding: 30, borderRadius: '50%', marginBottom: 20 }}>
          <Target size={48} color="#378ADD" />
        </div>
        <h2 style={{ color: '#F0EFE9', marginBottom: 10 }}>No Active Kill Chains</h2>
        <p style={{ color: '#8892B0', maxWidth: 420, lineHeight: 1.6 }}>
          Your environment has no ongoing attacks. Once threats are detected, the AI will map them to the MITRE ATT&CK framework and predict subsequent phases here.
        </p>
      </div>
    );
  }

  const progression = killChainData?.attack_progression_pct ?? ((currentIdx + 1) / PHASES.length * 100).toFixed(0);
  const dwellDays = killChainData?.dwell_time_estimate_days ?? 1;

  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>

      {/* ── Threat Selector Dropdown ── */}
      {availableThreats.length > 0 && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '10px 16px', background: 'rgba(55,138,221,0.06)',
          border: '1px solid rgba(55,138,221,0.2)', borderRadius: 10,
        }}>
          <Target size={14} color="#378ADD" />
          <span style={{ fontSize: 12, fontWeight: 600, color: '#6B7280', whiteSpace: 'nowrap' }}>View Kill Chain For:</span>
          <select
            value={selectedThreatId}
            onChange={e => { setSelectedThreatId(e.target.value); setRefreshKey(k => k + 1); }}
            style={{
              flex: 1, background: 'rgba(10,14,23,0.8)', color: '#F0EFE9',
              border: '1px solid rgba(55,138,221,0.25)', borderRadius: 6,
              padding: '6px 10px', fontSize: 12, cursor: 'pointer', outline: 'none',
            }}
          >
            <option value="">Auto-detect (highest threat stage)</option>
            {availableThreats.map(t => (
              <option key={t.id} value={t.id}>
                [{t.severity?.toUpperCase()}] {t.title} — Phase: {t.kill_chain_phase || t.mitre_tactic}
              </option>
            ))}
          </select>
          {selectedThreat && (
            <span style={{ fontSize: 10, color: '#F59E0B', background: 'rgba(245,158,11,0.1)', padding: '3px 8px', borderRadius: 4, whiteSpace: 'nowrap' }}>
              📍 Pinned to phase: {selectedThreat.kill_chain_phase || selectedThreat.mitre_tactic}
            </span>
          )}
        </div>
      )}

      {/* ── Top Summary Banner ── */}
      <div style={{
        display: 'grid', gridTemplateColumns: '1fr auto auto auto',
        alignItems: 'center', gap: 16,
        background: 'rgba(13,17,28,0.7)', border: '1px solid rgba(55,138,221,0.2)',
        borderRadius: 12, padding: '12px 20px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Target size={18} color="#378ADD" />
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: '#F0EFE9' }}>Data-Driven Cyber Kill Chain</div>
            <div style={{ fontSize: 11, color: '#6B7280' }}>Click any phase for detailed commands &amp; measures</div>
          </div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 20, fontWeight: 800, color: '#378ADD' }}>{progression}%</div>
          <div style={{ fontSize: 9, color: '#6B7280', textTransform: 'uppercase', letterSpacing: 1 }}>Progression</div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 20, fontWeight: 800, color: '#F59E0B' }}>{dwellDays}d</div>
          <div style={{ fontSize: 9, color: '#6B7280', textTransform: 'uppercase', letterSpacing: 1 }}>Est. Dwell</div>
        </div>
        <button
          onClick={() => setRefreshKey(k => k + 1)}
          disabled={loading}
          style={{
            background: 'rgba(55,138,221,0.1)', border: '1px solid rgba(55,138,221,0.3)',
            color: '#378ADD', padding: '6px 12px', borderRadius: 8, cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 5, fontSize: 12,
            opacity: loading ? 0.5 : 1, transition: 'all 0.2s'
          }}
        >
          <RefreshCw size={13} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} /> Refresh
        </button>
      </div>

      {/* ── Kill Chain Phase Strip ── */}
      <div className="panel">
        <div className="panel-body" style={{ padding: '12px 16px' }}>
          <div style={{ overflowX: 'auto', paddingBottom: 4 }}>
            <div style={{ display: 'flex', gap: 4, alignItems: 'center', minWidth: 'max-content' }}>
              {PHASES.map((phase, idx) => {
                const isCompleted = idx < currentIdx;
                const isCurrent   = idx === currentIdx;
                const isPredicted = idx > currentIdx && idx <= currentIdx + 3;
                const isSelected  = idx === selectedPhaseIdx;

                let borderColor = 'rgba(255,255,255,0.07)';
                let bg = 'rgba(17,21,32,0.8)';
                let numColor = '#4B5563';
                if (isCompleted) { borderColor = '#FF3B5C'; bg = 'rgba(255,59,92,0.1)'; numColor = '#FF3B5C'; }
                if (isCurrent)   { borderColor = '#F59E0B'; bg = 'rgba(245,158,11,0.15)'; numColor = '#F59E0B'; }
                if (isPredicted) { borderColor = '#378ADD'; bg = 'rgba(55,138,221,0.08)'; numColor = '#378ADD'; }
                if (isSelected)  { borderColor = '#A78BFA'; bg = 'rgba(167,139,250,0.18)'; }

                return (
                  <div key={phase} style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                    <div
                      onClick={() => setSelectedPhaseIdx(idx)}
                      title={phase}
                      style={{
                        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3,
                        minWidth: 76, padding: '7px 5px',
                        borderRadius: 8, border: `1px ${isPredicted && !isSelected ? 'dashed' : 'solid'} ${borderColor}`,
                        background: bg,
                        cursor: 'pointer',
                        transition: 'all 0.2s ease',
                        transform: isSelected ? 'translateY(-2px)' : 'none',
                        boxShadow: isSelected ? `0 4px 14px rgba(167,139,250,0.3)` : isCurrent ? '0 0 10px rgba(245,158,11,0.2)' : 'none',
                        outline: isSelected ? '2px solid #A78BFA' : 'none',
                        outlineOffset: 2,
                      }}
                    >
                      <div style={{ fontSize: 11, fontWeight: 700, color: numColor }}>{idx + 1}</div>
                      <div style={{ fontSize: 8, fontWeight: 600, textTransform: 'uppercase', textAlign: 'center',
                        color: isCompleted || isCurrent || isPredicted ? numColor : '#4B5563',
                        lineHeight: 1.25, whiteSpace: 'pre-line'
                      }}>
                        {phase.replace(/ (?=\S)/g, '\n').slice(0, 28)}
                      </div>
                      {isCurrent && (
                        <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#F59E0B',
                          boxShadow: '0 0 6px #F59E0B', animation: 'pulse-amber 2s infinite' }} />
                      )}
                    </div>
                    {idx < PHASES.length - 1 && (
                      <ChevronRight size={11} color={idx < currentIdx ? '#FF3B5C' : '#2D3748'} />
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Legend */}
          <div style={{ display: 'flex', gap: 16, marginTop: 12, flexWrap: 'wrap' }}>
            {[
              { color: '#FF3B5C', label: '● COMPLETED — Confirmed by threat telemetry' },
              { color: '#F59E0B', label: '● CURRENT — Most advanced phase detected' },
              { color: '#378ADD', label: '◌ PREDICTED — AI-forecasted upcoming phases' },
              { color: '#A78BFA', label: '◈ SELECTED — Click to drill into any phase' },
            ].map(({ color, label }) => (
              <div key={label} style={{ fontSize: 10, color, display: 'flex', alignItems: 'center', gap: 4 }}>
                {label}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Selected Phase Detail + Prediction Table ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>

        {/* LEFT: Selected Phase Detail */}
        <div className="panel" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="panel-header">
            <div className="panel-title">
              <Zap size={15} />
              {isSelectedCurrent ? '⚡ Current Phase' : isSelectedCompleted ? '✅ Completed Phase' : '🔮 Predicted Phase'}
              : <span style={{ color: isSelectedCurrent ? '#F59E0B' : isSelectedCompleted ? '#FF3B5C' : '#378ADD', marginLeft: 5 }}>
                  {selectedPhase}
                </span>
            </div>
            {isSelectedPredicted && selectedPhaseData && (
              <span style={{
                fontSize: 10, fontWeight: 700, color: '#F59E0B',
                background: 'rgba(245,158,11,0.12)', padding: '2px 8px', borderRadius: 10
              }}>
                {(selectedPhaseData.probability * 100).toFixed(0)}% likelihood
              </span>
            )}
          </div>

          <div className="panel-body" style={{ flex: 1, overflowY: 'auto', maxHeight: 480 }}>
            {loading && !killChainData ? (
              <div className="scanning"><div className="scanning-ring" /></div>
            ) : selectedPhaseData ? (
              <PhaseDetailPanel
                phaseData={selectedPhaseData}
                isCompleted={isSelectedCompleted}
                isCurrent={isSelectedCurrent}
              />
            ) : (
              <div style={{ textAlign: 'center', padding: 30, color: '#4B5563' }}>
                <Activity size={30} style={{ marginBottom: 10, opacity: 0.4 }} />
                <div style={{ fontSize: 12 }}>Click a phase above to see detailed commands and measures</div>
              </div>
            )}

            {/* Root Cause if from real threat */}
            {isSelectedCurrent && killChainData?.root_cause && (
              <div style={{ marginTop: 12, padding: '10px 12px', background: 'rgba(255,59,92,0.07)', borderRadius: 8, border: '1px solid rgba(255,59,92,0.2)' }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#FF3B5C', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 5 }}>
                  🔍 Root Cause (from Active Threat)
                </div>
                <p style={{ fontSize: 11, color: '#B4B2A9', lineHeight: 1.6, margin: 0 }}>
                  {killChainData.root_cause}
                </p>
              </div>
            )}
          </div>
        </div>

        {/* RIGHT: AI Prediction Table + Defensive Actions */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>

          {/* Prediction Table */}
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title"><Activity size={15} /> AI Prediction: Next Phases</div>
              <span style={{ fontSize: 10, color: '#6B7280' }}>Click row to inspect</span>
            </div>
            <div className="panel-body no-pad">
              {loading && !killChainData ? (
                <div className="scanning"><div className="scanning-ring" /></div>
              ) : (
                <table className="threat-table" style={{ tableLayout: 'fixed' }}>
                  <colgroup>
                    <col style={{ width: '28%' }} />
                    <col style={{ width: '18%' }} />
                    <col style={{ width: '54%' }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>Phase</th>
                      <th>Prob.</th>
                      <th>What to do</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(killChainData?.predicted_next_phases || []).slice(0, 5).map((p, i) => {
                      const phaseGlobalIdx = PHASES.indexOf(p.phase);
                      const isRowSelected = selectedPhaseIdx === phaseGlobalIdx;
                      const pConfig = PRIORITY_CONFIG[p.priority] || PRIORITY_CONFIG.MEDIUM;
                      return (
                        <tr
                          key={i}
                          onClick={() => setSelectedPhaseIdx(phaseGlobalIdx)}
                          style={{
                            cursor: 'pointer',
                            background: isRowSelected ? 'rgba(167,139,250,0.1)' : 'transparent',
                            transition: 'background 0.2s',
                            outline: isRowSelected ? '1px solid rgba(167,139,250,0.3)' : 'none',
                          }}
                        >
                          <td style={{ fontWeight: 600, color: '#F0EFE9', fontSize: 11 }}>
                            <div>{p.phase}</div>
                            <span style={{ fontSize: 9, color: pConfig.color, background: pConfig.bg, padding: '1px 5px', borderRadius: 3, marginTop: 2, display: 'inline-block' }}>
                              {p.priority}
                            </span>
                          </td>
                          <td>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                              <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                                <div style={{ width: `${p.probability * 100}%`, height: '100%', borderRadius: 2, background: p.probability > 0.8 ? '#FF3B5C' : '#F59E0B' }} />
                              </div>
                              <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono'", color: p.probability > 0.8 ? '#FF3B5C' : '#F59E0B' }}>
                                {(p.probability * 100).toFixed(0)}%
                              </span>
                            </div>
                          </td>
                          <td style={{ fontSize: 10, color: '#8892B0', paddingRight: 10 }}>
                            <div style={{ color: '#B4B2A9', marginBottom: 3, lineHeight: 1.4 }}>
                              {p.mitigations?.[0] || p.defensive_action?.slice(0, 70) + '…'}
                            </div>
                            {p.likely_techniques?.[0] && (
                              <div style={{ color: '#4B5563', fontSize: 9 }}>
                                Technique: {p.likely_techniques[0]}
                              </div>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Immediate Action Card */}
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title"><ShieldAlert size={15} /> Immediate Actions Now</div>
              <span style={{ fontSize: 10, color: '#F59E0B' }}>For: {currentPhase}</span>
            </div>
            <div className="panel-body" style={{ padding: '10px 14px' }}>
              {killChainData?.current_phase_details ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {/* Status */}
                  <div style={{ fontSize: 12, color: '#B4B2A9', lineHeight: 1.5, padding: '8px 10px', background: 'rgba(245,158,11,0.07)', borderRadius: 6, borderLeft: '3px solid #F59E0B' }}>
                    {killChainData.current_phase_details.summary}
                  </div>
                  {/* Top 2 mitigations */}
                  {(killChainData.current_phase_details.mitigations || []).slice(0, 3).map((m, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '6px 8px', background: 'rgba(34,197,94,0.06)', borderRadius: 6 }}>
                      <CheckCircle size={12} color="#22C55E" style={{ marginTop: 1, flexShrink: 0 }} />
                      <span style={{ fontSize: 11, color: '#B4B2A9', lineHeight: 1.4 }}>{m}</span>
                    </div>
                  ))}
                  {/* First command */}
                  {killChainData.current_phase_details.commands?.[0] && (
                    <div style={{ background: '#050709', borderRadius: 6, border: '1px solid rgba(55,138,221,0.15)', padding: '6px 10px', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ color: '#22C55E', fontSize: 10 }}>$</span>
                      <code style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: '#E2E8F0', flex: 1, wordBreak: 'break-all' }}>
                        {killChainData.current_phase_details.commands[0]}
                      </code>
                      <CopyButton text={killChainData.current_phase_details.commands[0]} />
                    </div>
                  )}
                  <div style={{ fontSize: 10, color: '#6B7280', textAlign: 'right' }}>
                    Click "{currentPhase}" phase above for all {killChainData.current_phase_details.commands?.length || 0} commands →
                  </div>
                </div>
              ) : (
                <div style={{ color: '#4B5563', fontSize: 12 }}>Loading action data…</div>
              )}
            </div>
          </div>

        </div>
      </div>

      <style>{`
        @keyframes pulse-amber {
          0%, 100% { opacity: 1; box-shadow: 0 0 6px #F59E0B; }
          50% { opacity: 0.4; box-shadow: 0 0 2px #F59E0B; }
        }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
