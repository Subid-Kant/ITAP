import { useState } from 'react';
import { BookOpen } from 'lucide-react';
import { api } from '../api';

const THREAT_TYPES = ['Remote Code Execution', 'SQL Injection', 'Denial of Service', 'Phishing', 'Brute Force', 'Zero-Day / Unknown'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

export default function PlaybookView() {
  const [threatType, setThreatType] = useState('Remote Code Execution');
  const [severity, setSeverity] = useState('critical');
  const [playbook, setPlaybook] = useState(null);
  const [loading, setLoading] = useState(false);

  const generate = async () => {
    setLoading(true);
    try {
      const result = await api.generatePlaybook({ incident_id: 'demo', threat_type: threatType, severity });
      setPlaybook(result);
    } catch {
      setPlaybook(getDemoPlaybook(threatType, severity));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fade-in">
      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <div className="panel-title"><BookOpen size={16} /> AI Playbook Generator</div>
        </div>
        <div className="panel-body">
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
            <select value={threatType} onChange={e => setThreatType(e.target.value)}
              style={{ padding: '10px 14px', borderRadius: 8, border: '1px solid rgba(55,138,221,0.2)', background: '#151b2b', color: '#F0EFE9', fontSize: 13, fontFamily: 'inherit' }}>
              {THREAT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <select value={severity} onChange={e => setSeverity(e.target.value)}
              style={{ padding: '10px 14px', borderRadius: 8, border: '1px solid rgba(55,138,221,0.2)', background: '#151b2b', color: '#F0EFE9', fontSize: 13, fontFamily: 'inherit' }}>
              {SEVERITIES.map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
            </select>
            <button className="header-btn primary" onClick={generate} disabled={loading}>
              <BookOpen size={14} /> {loading ? 'Generating...' : 'Generate Playbook'}
            </button>
          </div>
          {loading && <div className="scanning"><div className="scanning-ring" /><div className="scanning-text">AI generating playbook...</div></div>}
        </div>
      </div>

      {playbook && (
        <div className="panel fade-in">
          <div className="panel-header">
            <div className="panel-title"><BookOpen size={16} /> {playbook.title}</div>
            <span className={`severity-badge ${severity}`}>{playbook.priority || severity.toUpperCase()}</span>
          </div>
          <div className="panel-body">
            <div className="playbook">
              {(playbook.playbook_steps || []).map((s, i) => (
                <div key={i} className="playbook-step">
                  <div className="playbook-step-number">{s.step_number || i + 1}</div>
                  <div className="playbook-step-content">
                    <h4>{s.action}</h4>
                    <p>{s.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function getDemoPlaybook(type, severity) {
  const steps = {
    'Remote Code Execution': [
      { step_number: 1, action: 'Immediate Isolation', detail: 'Isolate the affected system from the network. Do NOT power off — preserve volatile memory.' },
      { step_number: 2, action: 'Capture Forensic Evidence', detail: 'Memory dump, network logs (pcap), active processes and connections.' },
      { step_number: 3, action: 'Identify Attack Vector', detail: 'Review web server logs for suspicious requests. Check for encoded payloads.' },
      { step_number: 4, action: 'Contain the Threat', detail: 'Block attacker IP. Revoke compromised credentials. Apply virtual patch (WAF).' },
      { step_number: 5, action: 'Remediate', detail: 'Apply security patch for identified CVE. Harden service configuration.' },
      { step_number: 6, action: 'Recovery & Monitoring', detail: 'Restore from clean backup. Re-enable with enhanced monitoring.' },
    ],
    'SQL Injection': [
      { step_number: 1, action: 'Identify Injection Point', detail: 'Review logs for UNION, OR 1=1, DROP keywords in requests.' },
      { step_number: 2, action: 'Block Attacker', detail: 'Block IP at WAF/firewall. Enable SQL injection rule sets.' },
      { step_number: 3, action: 'Assess Data Exposure', detail: 'Check for unauthorized SELECT, UPDATE, DELETE operations.' },
      { step_number: 4, action: 'Patch Application', detail: 'Replace dynamic SQL with parameterised queries. Implement input validation.' },
    ],
  };
  return {
    title: `${type} Response Playbook`,
    priority: severity.toUpperCase(),
    playbook_steps: steps[type] || steps['Remote Code Execution'],
  };
}
