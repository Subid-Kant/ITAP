import { useState, useEffect, useCallback, useRef } from 'react';
import { api } from '../api';

export function useDashboard(isAuthenticated = false) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [isLive, setIsLive] = useState(false);
  const intervalRef = useRef(null);

  const refresh = useCallback(async () => {
    if (!isAuthenticated) return;
    try {
      setLoading(true);
      const data = await api.getDashboardStats();
      setStats(data);
      setIsLive(true);
    } catch (e) {
      console.error('Dashboard fetch error:', e);
      if (!stats) {
        setStats(getDemoStats());
      }
      setIsLive(false);
    } finally {
      setLoading(false);
    }
  }, [isAuthenticated]);

  useEffect(() => {
    if (!isAuthenticated) return;
    refresh();
    // Auto-refresh every 30 seconds for live data
    intervalRef.current = setInterval(refresh, 30000);
    return () => clearInterval(intervalRef.current);
  }, [refresh, isAuthenticated]);

  return { stats, loading, refresh, isLive };
}

function getDemoStats() {
  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  const tactics = ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Lateral Movement', 'Exfiltration', 'Impact'];
  const countries = [
    { country: 'Russia', lat: 55.75, lon: 37.61, severity: 'critical', title: 'APT29 C2 Communication' },
    { country: 'China', lat: 39.90, lon: 116.40, severity: 'high', title: 'Port Scanning Activity' },
    { country: 'United States', lat: 40.71, lon: -74.00, severity: 'medium', title: 'Brute Force Attempt' },
    { country: 'Germany', lat: 52.52, lon: 13.40, severity: 'high', title: 'SQL Injection Probe' },
    { country: 'North Korea', lat: 39.03, lon: 125.75, severity: 'critical', title: 'Lazarus Group Activity' },
    { country: 'Iran', lat: 35.68, lon: 51.38, severity: 'high', title: 'Spearphishing Campaign' },
    { country: 'Brazil', lat: -23.55, lon: -46.63, severity: 'medium', title: 'DDoS Source' },
    { country: 'India', lat: 19.07, lon: 72.87, severity: 'low', title: 'Vulnerability Scanner' },
  ];
  const threats = Array.from({ length: 12 }, (_, i) => ({
    id: `t-${i}`,
    title: ['RCE via Log4Shell', 'SQL Injection on /api/auth', 'Brute Force SSH', 'Ransomware Indicator', 'C2 Beacon Detected', 'XSS Reflected', 'Privilege Escalation CVE-2024-3094', 'Data Exfiltration Attempt', 'Phishing Domain Active', 'Zero-Day Exploit Pattern', 'DNS Tunneling Detected', 'Cryptominer Payload'][i],
    severity: severities[i % 5],
    severity_score: (10 - i * 0.7).toFixed(1),
    mitre_tactic: tactics[i % tactics.length],
    source_country: countries[i % countries.length].country,
    detected_at: new Date(Date.now() - i * 3600000 * Math.random() * 5).toISOString(),
  }));
  const incidents = Array.from({ length: 6 }, (_, i) => ({
    id: `inc-${i}`,
    title: ['Critical RCE Incident', 'Data Breach Investigation', 'DDoS Attack Mitigation', 'Phishing Campaign Response', 'Insider Threat Alert', 'Ransomware Containment'][i],
    severity: severities[i % 4],
    status: ['open', 'investigating', 'open', 'resolved', 'investigating', 'open'][i],
    detected_at: new Date(Date.now() - i * 7200000).toISOString(),
  }));
  return {
    total_targets: 0, active_threats: 0, critical_threats: 0, open_incidents: 0,
    predictions_active: 0, anomalies_detected: 0,
    threats_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    threats_by_country: countries,
    recent_threats: threats,
    recent_incidents: incidents,
    mitre_attack_coverage: threats.filter(t => t.mitre_tactic).map(t => ({
      tactic: t.mitre_tactic, technique_id: `T${1000 + Math.floor(Math.random() * 600)}`, technique_name: t.title, severity: t.severity,
    })),
    timestamp: new Date().toISOString(),
  };
}

export { getDemoStats };
