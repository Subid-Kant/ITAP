import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Activity, ShieldAlert, Wifi, AlertTriangle,
  RefreshCw, Globe, Server, Zap, Map
} from 'lucide-react';
import { MapContainer, TileLayer, Marker, Polyline, Popup, useMap } from 'react-leaflet';
import L from 'leaflet';
import { api } from '../api';

const SEV_COLOR = {
  critical: '#FF3B5C',
  high:     '#F97316',
  medium:   '#F59E0B',
  low:      '#22C55E',
  safe:     '#22C55E',
};

const CLS_COLOR = {
  MALICIOUS:  '#FF3B5C',
  SUSPICIOUS: '#F97316',
  SAFE:       '#22C55E',
};

const RISK_GRADIENT = (score) => {
  if (score >= 75) return '#FF3B5C';
  if (score >= 50) return '#F97316';
  if (score >= 25) return '#F59E0B';
  return '#22C55E';
};

// ── Leaflet Custom Icons ─────────────────────────────────────────────────────

const createDotIcon = (color, isCritical) => {
  return L.divIcon({
    className: 'custom-leaflet-icon',
    html: `
      <div style="position: relative; width: 14px; height: 14px; transform: translate(-50%, -50%);">
        <div style="position: absolute; inset: -4px; border-radius: 50%; background: ${color}; opacity: 0.3; animation: map-pulse 2s ease infinite;"></div>
        <div style="position: absolute; inset: 0; border-radius: 50%; background: ${color}; border: 1.5px solid #060910;"></div>
      </div>
    `,
    iconSize: [0, 0], // Center exactly on coordinates
  });
};

const createHostIcon = () => {
  return L.divIcon({
    className: 'custom-leaflet-icon',
    html: `
      <div style="position: relative; width: 20px; height: 20px; transform: translate(-50%, -50%);">
        <div style="position: absolute; inset: -10px; border-radius: 50%; border: 1px solid #378ADD; opacity: 0.3; animation: map-pulse 2.5s ease infinite;"></div>
        <div style="position: absolute; inset: -5px; border-radius: 50%; border: 1.5px solid #378ADD; opacity: 0.5;"></div>
        <div style="position: absolute; top: 50%; left: -8px; width: 8px; height: 1.5px; background: #378ADD;"></div>
        <div style="position: absolute; top: 50%; right: -8px; width: 8px; height: 1.5px; background: #378ADD;"></div>
        <div style="position: absolute; left: 50%; top: -8px; width: 1.5px; height: 8px; background: #378ADD;"></div>
        <div style="position: absolute; left: 50%; bottom: -8px; width: 1.5px; height: 8px; background: #378ADD;"></div>
        <div style="position: absolute; inset: 6px; border-radius: 50%; background: #378ADD;"></div>
      </div>
    `,
    iconSize: [0, 0],
  });
};

// Component to dynamically update map center/zoom
function MapUpdater({ center, zoom }) {
  const map = useMap();
  useEffect(() => {
    map.setView(center, zoom, { animate: true });
  }, [center, zoom, map]);
  return null;
}

// ── Risk Score Ring ──────────────────────────────────────────────────────────
function RiskGauge({ score }) {
  const color = RISK_GRADIENT(score);
  const radius = 28;
  const circ = 2 * Math.PI * radius;
  const dash = (score / 100) * circ;

  return (
    <div style={{ position: 'relative', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg width={70} height={70} style={{ transform: 'rotate(-90deg)' }}>
        <circle r={radius} cx={35} cy={35} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={6} />
        <circle
          r={radius} cx={35} cy={35} fill="none"
          stroke={color} strokeWidth={6}
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 1s ease' }}
        />
      </svg>
      <div style={{ position: 'absolute', textAlign: 'center' }}>
        <div style={{ fontSize: 14, fontWeight: 800, color, lineHeight: 1 }}>{score}</div>
        <div style={{ fontSize: 9, color: '#64748B', lineHeight: 1 }}>RISK</div>
      </div>
    </div>
  );
}

// ── Badge ────────────────────────────────────────────────────────────────────
function Badge({ label, color }) {
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, letterSpacing: 0.5,
      padding: '2px 7px', borderRadius: 20,
      background: `${color}22`, color, border: `1px solid ${color}44`,
      textTransform: 'uppercase',
    }}>
      {label}
    </span>
  );
}

// ── Main Component ───────────────────────────────────────────────────────────
export default function GeoMapView() {
  const [scanData, setScanData]           = useState(null);
  const [globalData, setGlobalData]       = useState(null);
  const [loading, setLoading]             = useState(true);
  const [lastRefresh, setLastRefresh]     = useState(null);
  const [filter, setFilter]               = useState('all'); // all | malicious | suspicious | safe
  const [viewMode, setViewMode]           = useState('machine'); // machine | global
  const [autoRefresh, setAutoRefresh]     = useState(true);
  const intervalRef                       = useRef(null);

  const fetchData = useCallback(async () => {
    try {
      const [scan, global] = await Promise.allSettled([
        api.getMachineScan(),
        api.getGlobalThreats(),
      ]);
      if (scan.status === 'fulfilled') setScanData(scan.value);
      if (global.status === 'fulfilled') setGlobalData(global.value);
      setLastRefresh(new Date());
    } catch (e) {
      console.error('GeoMap fetch error:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(fetchData, 60_000);
    } else {
      clearInterval(intervalRef.current);
    }
    return () => clearInterval(intervalRef.current);
  }, [autoRefresh, fetchData]);

  // ── Data preparation ─────────────────────────────────────────────────────

  // Machine scan connections
  const machineConns = (scanData?.connections || []).filter(c => {
    if (filter === 'malicious')  return c.classification === 'MALICIOUS';
    if (filter === 'suspicious') return c.classification === 'SUSPICIOUS' || c.classification === 'MALICIOUS';
    if (filter === 'safe')       return c.classification === 'SAFE';
    return true;
  });

  // Global CISA KEV threats
  const globalThreats = (globalData?.cisa_kev || []).slice(0, 20).map(k => ({
    country: k.estimated_origin,
    lat: k.lat,
    lon: k.lon,
    severity: 'critical',
    title: k.cveID,
    desc: k.vulnerabilityName,
  }));

  const hostLat  = scanData?.host?.lat  || 25.315; // default center fallback
  const hostLon  = scanData?.host?.lon  || 83.0058;
  const hostCity = scanData?.host?.city || 'Unknown';
  const hostIP   = scanData?.host?.ip   || '…';
  const riskScore = scanData?.risk_score || 0;

  const displayConns    = viewMode === 'machine' ? machineConns : globalThreats;
  const threatCount     = viewMode === 'machine'
    ? (scanData?.threat_count || 0)
    : globalThreats.length;
  const criticalCount   = viewMode === 'machine'
    ? (scanData?.malicious_count || 0)
    : globalThreats.filter(t => t.severity === 'critical').length;
  const topThreatCountry = viewMode === 'machine'
    ? (scanData?.top_threat_country || 'None')
    : ((() => {
        const c = {};
        globalThreats.forEach(t => { c[t.country] = (c[t.country]||0)+1; });
        return Object.keys(c).sort((a,b)=>c[b]-c[a])[0] || 'None';
      })());

  const initialCenter = [hostLat, hostLon];

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* ── Top Stats Bar ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12 }}>

        {/* Host Card */}
        <div style={cardStyle('#378ADD')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ color: '#378ADD', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>Your Machine</div>
              <div style={{ color: '#F0EFE9', fontSize: 16, fontWeight: 700, marginTop: 4, fontFamily: 'monospace' }}>{hostIP}</div>
              <div style={{ color: '#8892B0', fontSize: 12, marginTop: 2 }}>{hostCity}, {scanData?.host?.country || '…'}</div>
              <div style={{ color: '#4A5568', fontSize: 10, marginTop: 2 }}>{scanData?.os_info?.system || ''} {scanData?.os_info?.release || ''}</div>
            </div>
            <Server size={20} color="#378ADD" style={{ opacity: 0.7 }} />
          </div>
        </div>

        {/* Risk Score */}
        <div style={cardStyle(RISK_GRADIENT(riskScore))}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <RiskGauge score={riskScore} />
            <div>
              <div style={{ color: '#8892B0', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1 }}>Risk Score</div>
              <div style={{ color: RISK_GRADIENT(riskScore), fontSize: 13, fontWeight: 700, marginTop: 4 }}>
                {riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW'}
              </div>
              <div style={{ color: '#64748B', fontSize: 11, marginTop: 2 }}>{scanData?.total_connections || 0} connections mapped</div>
            </div>
          </div>
        </div>

        {/* Malicious */}
        <div style={cardStyle('#FF3B5C')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ color: '#FF3B5C', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>Malicious</div>
              <div style={{ color: '#F0EFE9', fontSize: 28, fontWeight: 800, lineHeight: 1, marginTop: 4 }}>{scanData?.malicious_count ?? '—'}</div>
              <div style={{ color: '#8892B0', fontSize: 11, marginTop: 4 }}>Confirmed threats</div>
            </div>
            <ShieldAlert size={20} color="#FF3B5C" style={{ opacity: 0.7 }} />
          </div>
        </div>

        {/* Suspicious */}
        <div style={cardStyle('#F97316')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ color: '#F97316', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>Suspicious</div>
              <div style={{ color: '#F0EFE9', fontSize: 28, fontWeight: 800, lineHeight: 1, marginTop: 4 }}>{scanData?.suspicious_count ?? '—'}</div>
              <div style={{ color: '#8892B0', fontSize: 11, marginTop: 4 }}>Flagged connections</div>
            </div>
            <AlertTriangle size={20} color="#F97316" style={{ opacity: 0.7 }} />
          </div>
        </div>

        {/* Top Threat Origin */}
        <div style={cardStyle('#A78BFA')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ color: '#A78BFA', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>Top Origin</div>
              <div style={{ color: '#F0EFE9', fontSize: 15, fontWeight: 700, marginTop: 4 }}>{topThreatCountry}</div>
              <div style={{ color: '#8892B0', fontSize: 11, marginTop: 4 }}>Highest threat country</div>
            </div>
            <Globe size={20} color="#A78BFA" style={{ opacity: 0.7 }} />
          </div>
        </div>

      </div>

      {/* ── Main Map Panel (Leaflet) ── */}
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">
            <Map size={16} />
            {viewMode === 'machine' ? 'Live Network Threat Map — Your Machine' : 'Global CISA KEV Intelligence Map'}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {/* Auto-refresh indicator */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: autoRefresh ? '#22C55E' : '#64748B' }}>
              <span style={{
                width: 7, height: 7, borderRadius: '50%', background: autoRefresh ? '#22C55E' : '#64748B',
                display: 'inline-block',
                animation: autoRefresh ? 'pulse 2s infinite' : 'none',
              }} />
              {autoRefresh ? 'LIVE' : 'PAUSED'}
              {lastRefresh && <span style={{ color: '#4A5568' }}>· {lastRefresh.toLocaleTimeString()}</span>}
            </div>

            {/* View toggle */}
            <button
              onClick={() => setViewMode(v => v === 'machine' ? 'global' : 'machine')}
              style={btnStyle('#378ADD')}
            >
              {viewMode === 'machine' ? <><Globe size={12}/> Global KEV</> : <><Server size={12}/> My Machine</>}
            </button>

            {/* Refresh */}
            <button onClick={fetchData} style={btnStyle('#4A5568')} title="Refresh now">
              <RefreshCw size={12} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
            </button>

            {/* Auto-refresh toggle */}
            <button
              onClick={() => setAutoRefresh(a => !a)}
              style={btnStyle(autoRefresh ? '#22C55E' : '#4A5568')}
            >
              <Zap size={12}/> {autoRefresh ? 'Auto' : 'Manual'}
            </button>
          </div>
        </div>

        <div className="panel-body" style={{ padding: 0, position: 'relative', background: '#070a10', overflow: 'hidden' }}>

          {/* ── Filter Bar ── */}
          {viewMode === 'machine' && (
            <div style={{ position: 'absolute', top: 12, left: 12, zIndex: 1000, display: 'flex', gap: 6 }}>
              {['all', 'malicious', 'suspicious', 'safe'].map(f => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  style={{
                    padding: '4px 10px', fontSize: 10, borderRadius: 12, border: 'none', cursor: 'pointer',
                    fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5,
                    background: filter === f
                      ? (f === 'malicious' ? '#FF3B5C' : f === 'suspicious' ? '#F97316' : f === 'safe' ? '#22C55E' : '#378ADD')
                      : 'rgba(15,20,32,0.8)',
                    color: filter === f ? '#fff' : '#64748B',
                    backdropFilter: 'blur(4px)',
                  }}
                >
                  {f}
                </button>
              ))}
            </div>
          )}

          {/* ── Open Ports pill ── */}
          {viewMode === 'machine' && scanData?.open_ports?.length > 0 && (
            <div style={{
              position: 'absolute', bottom: 12, left: 12, zIndex: 1000,
              background: 'rgba(10,13,20,0.9)', backdropFilter: 'blur(8px)',
              border: '1px solid rgba(55,138,221,0.2)', borderRadius: 8, padding: '8px 12px',
            }}>
              <div style={{ color: '#8892B0', fontSize: 10, textTransform: 'uppercase', marginBottom: 4 }}>Open Ports</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {scanData.open_ports.slice(0, 12).map(p => (
                  <span key={p.port} style={{
                    fontSize: 10, padding: '1px 6px', borderRadius: 4,
                    background: 'rgba(55,138,221,0.15)', color: '#378ADD',
                    fontFamily: 'monospace',
                  }}>{p.port}</span>
                ))}
                {scanData.open_ports.length > 12 && (
                  <span style={{ fontSize: 10, color: '#64748B' }}>+{scanData.open_ports.length - 12}</span>
                )}
              </div>
            </div>
          )}

          {/* ── Stats Overlay ── */}
          <div style={{
            position: 'absolute', top: 12, right: 12, width: 200, zIndex: 1000,
            background: 'rgba(10,13,20,0.88)', backdropFilter: 'blur(10px)',
            border: '1px solid rgba(55,138,221,0.2)', borderRadius: 10, padding: 14,
          }}>
            <div style={{ color: '#8892B0', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10, display: 'flex', gap: 6, alignItems: 'center' }}>
              <Activity size={12}/> Live Analysis
            </div>
            {[
              { label: 'Active Threat Sources', value: threatCount, color: '#FF3B5C' },
              { label: 'Confirmed Critical', value: criticalCount, color: '#FF3B5C' },
              { label: 'Top Origin', value: topThreatCountry, color: '#F0EFE9' },
            ].map(({ label, value, color }) => (
              <div key={label} style={{ marginBottom: 10 }}>
                <div style={{ color, fontSize: 20, fontWeight: 800, lineHeight: 1 }}>{value}</div>
                <div style={{ color: '#64748B', fontSize: 10 }}>{label}</div>
              </div>
            ))}

            {/* Legend */}
            <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 8, marginTop: 4 }}>
              {[
                { color: '#FF3B5C', label: 'Malicious' },
                { color: '#F97316', label: 'Suspicious' },
                { color: '#22C55E', label: 'Safe' },
                { color: '#378ADD', label: 'Your Host' },
              ].map(({ color, label }) => (
                <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block' }} />
                  <span style={{ fontSize: 10, color: '#8892B0' }}>{label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* ── The Leaflet Map ── */}
          <div style={{ height: 520, width: '100%', position: 'relative' }}>
            {loading && (
              <div style={{
                position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
                alignItems: 'center', justifyContent: 'center', zIndex: 2000,
                background: 'rgba(7,10,16,0.85)', backdropFilter: 'blur(4px)',
              }}>
                <div style={{ width: 40, height: 40, borderRadius: '50%', border: '3px solid #378ADD', borderTopColor: 'transparent', animation: 'spin 1s linear infinite', marginBottom: 12 }} />
                <div style={{ color: '#8892B0', fontSize: 13 }}>Scanning machine…</div>
              </div>
            )}

            <MapContainer 
              center={initialCenter} 
              zoom={2} 
              style={{ width: '100%', height: '100%', zIndex: 1 }}
              zoomControl={true}
              scrollWheelZoom={true}
            >
              <MapUpdater center={initialCenter} zoom={viewMode === 'machine' ? 3 : 2} />
              
              {/* CartoDB Dark Matter Base Map (No API Key Required) */}
              <TileLayer
                url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
                maxZoom={19}
              />

              {/* ── Attack Lines ── */}
              {viewMode === 'machine' && machineConns
                .filter(c => c.classification !== 'SAFE' && c.lat && c.lon && hostLat && hostLon)
                .map((c, i) => {
                  const color = CLS_COLOR[c.classification] || '#F97316';
                  return (
                    <Polyline
                      key={`line-${i}`}
                      positions={[[c.lat, c.lon], [hostLat, hostLon]]}
                      pathOptions={{
                        color,
                        weight: c.classification === 'MALICIOUS' ? 2 : 1.5,
                        opacity: c.classification === 'MALICIOUS' ? 0.7 : 0.4,
                        dashArray: '5, 8'
                      }}
                    />
                  );
                })}

              {viewMode === 'global' && globalThreats
                .filter(t => t.lat && t.lon && hostLat && hostLon)
                .map((t, i) => (
                  <Polyline
                    key={`gline-${i}`}
                    positions={[[t.lat, t.lon], [hostLat, hostLon]]}
                    pathOptions={{ color: '#FF3B5C', weight: 1.5, opacity: 0.5, dashArray: '5, 8' }}
                  />
                ))}

              {/* ── Connection Markers (Machine Mode) ── */}
              {viewMode === 'machine' && machineConns
                .filter(c => c.lat && c.lon)
                .map((c, i) => {
                  const color = CLS_COLOR[c.classification] || '#22C55E';
                  return (
                    <Marker
                      key={`mc-${i}`}
                      position={[c.lat, c.lon]}
                      icon={createDotIcon(color, c.classification === 'MALICIOUS')}
                    >
                      <Popup closeButton={false}>
                        <div style={{ minWidth: 200 }}>
                          <div style={{ color, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', marginBottom: 4 }}>
                            {c.classification}
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 8 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                              <span style={{ color: '#64748B', fontSize: 11 }}>IP</span>
                              <span style={{ color: '#F0EFE9', fontFamily: 'monospace', fontSize: 11 }}>{c.remote_ip}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                              <span style={{ color: '#64748B', fontSize: 11 }}>Port</span>
                              <span style={{ color: '#F0EFE9', fontFamily: 'monospace', fontSize: 11 }}>{c.remote_port}/{c.protocol}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                              <span style={{ color: '#64748B', fontSize: 11 }}>Process</span>
                              <span style={{ color: '#F0EFE9', fontFamily: 'monospace', fontSize: 11 }}>{c.process}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                              <span style={{ color: '#64748B', fontSize: 11 }}>Org</span>
                              <span style={{ color: '#F0EFE9', fontSize: 11, maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.org}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                              <span style={{ color: '#64748B', fontSize: 11 }}>Location</span>
                              <span style={{ color: '#F0EFE9', fontSize: 11 }}>{c.city}, {c.country_code}</span>
                            </div>
                          </div>
                        </div>
                      </Popup>
                    </Marker>
                  );
                })}

              {/* ── Global KEV Markers ── */}
              {viewMode === 'global' && globalThreats
                .filter(t => t.lat && t.lon)
                .map((t, i) => (
                  <Marker
                    key={`gt-${i}`}
                    position={[t.lat, t.lon]}
                    icon={createDotIcon('#FF3B5C', true)}
                  >
                    <Popup closeButton={false}>
                      <div style={{ minWidth: 200 }}>
                        <div style={{ color: '#FF3B5C', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', marginBottom: 4 }}>
                          CRITICAL CVE
                        </div>
                        <div style={{ color: '#F0EFE9', fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
                          {t.title}
                        </div>
                        <div style={{ color: '#8892B0', fontSize: 11, marginBottom: 8 }}>
                          {t.desc}
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ color: '#64748B', fontSize: 11 }}>Origin</span>
                          <span style={{ color: '#F0EFE9', fontSize: 11 }}>{t.country}</span>
                        </div>
                      </div>
                    </Popup>
                  </Marker>
                ))}

              {/* ── HOST MACHINE Marker ── */}
              {hostLat && hostLon && (
                <Marker position={[hostLat, hostLon]} icon={createHostIcon()}>
                  <Popup closeButton={false}>
                    <div style={{ minWidth: 150 }}>
                      <div style={{ color: '#378ADD', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', marginBottom: 4 }}>
                        YOUR HOST
                      </div>
                      <div style={{ color: '#F0EFE9', fontFamily: 'monospace', fontSize: 12 }}>
                        {hostIP}
                      </div>
                      <div style={{ color: '#8892B0', fontSize: 11, marginTop: 4 }}>
                        {hostCity}
                      </div>
                    </div>
                  </Popup>
                </Marker>
              )}
            </MapContainer>
          </div>
        </div>
      </div>

      {/* ── Connection Details Table ── */}
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">
            <Wifi size={16} />
            {viewMode === 'machine' ? 'Active Network Connections — Threat Intelligence' : 'CISA KEV Global Active Exploits'}
          </div>
          <div style={{ fontSize: 11, color: '#64748B' }}>
            {viewMode === 'machine'
              ? `${machineConns.length} connections shown · ${scanData?.total_connections || 0} total mapped`
              : `${globalThreats.length} active KEV entries`}
          </div>
        </div>
        <div className="panel-body no-pad">
          <div style={{ overflowX: 'auto' }}>
            <table className="threat-table">
              <thead>
                <tr>
                  {viewMode === 'machine' ? (
                    <>
                      <th>Classification</th>
                      <th>Remote IP</th>
                      <th>Location</th>
                      <th>Port</th>
                      <th>Process</th>
                      <th>Organisation</th>
                      <th>Coordinates</th>
                    </>
                  ) : (
                    <>
                      <th>Severity</th>
                      <th>CVE ID</th>
                      <th>Vulnerability</th>
                      <th>Origin Country</th>
                      <th>Coordinates</th>
                    </>
                  )}
                </tr>
              </thead>
              <tbody>
                {viewMode === 'machine' && machineConns.length === 0 && !loading && (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', color: '#64748B', padding: 24 }}>
                      {loading ? 'Scanning active connections…' : 'No connections match the current filter.'}
                    </td>
                  </tr>
                )}
                {viewMode === 'machine' && machineConns.map((c, i) => (
                  <tr key={i} style={{
                    borderLeft: `3px solid ${CLS_COLOR[c.classification] || '#22C55E'}`,
                    background: c.classification === 'MALICIOUS' ? 'rgba(255,59,92,0.04)' : c.classification === 'SUSPICIOUS' ? 'rgba(249,115,22,0.04)' : 'transparent',
                  }}>
                    <td><Badge label={c.classification} color={CLS_COLOR[c.classification]} /></td>
                    <td style={{ fontFamily: 'monospace', fontSize: 12, color: '#CBD5E1' }}>{c.remote_ip}</td>
                    <td style={{ color: '#F0EFE9' }}>
                      📍 {c.city}
                      <span style={{ color: '#64748B', fontSize: 11, display: 'block' }}>{c.region}, {c.country}</span>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#378ADD' }}>{c.remote_port}</span>
                      <span style={{ color: '#4A5568', fontSize: 10 }}>/{c.protocol}</span>
                    </td>
                    <td style={{ color: '#94A3B8', fontSize: 12, fontFamily: 'monospace' }}>{c.process || '—'}</td>
                    <td style={{ color: '#64748B', fontSize: 11, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.org}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: 11, color: '#4A5568' }}>{c.lat?.toFixed(3)}, {c.lon?.toFixed(3)}</td>
                  </tr>
                ))}

                {viewMode === 'global' && globalThreats.map((t, i) => (
                  <tr key={i} style={{ borderLeft: '3px solid #FF3B5C', background: 'rgba(255,59,92,0.03)' }}>
                    <td><Badge label="CRITICAL" color="#FF3B5C" /></td>
                    <td style={{ fontFamily: 'monospace', fontSize: 12, color: '#FF3B5C', fontWeight: 700 }}>{t.title}</td>
                    <td style={{ color: '#8892B0', fontSize: 11, maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.desc}</td>
                    <td style={{ color: '#F0EFE9' }}>📍 {t.country}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: 11, color: '#4A5568' }}>{t.lat?.toFixed(3)}, {t.lon?.toFixed(3)}</td>
                  </tr>
                ))}
                {viewMode === 'global' && globalThreats.length === 0 && (
                  <tr><td colSpan={5} style={{ textAlign: 'center', color: '#64748B', padding: 24 }}>Loading CISA KEV feed…</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* ── OS Info Footer ── */}
      {scanData?.os_info && (
        <div style={{
          display: 'flex', gap: 20, flexWrap: 'wrap', padding: '10px 16px',
          background: 'rgba(15,20,32,0.5)', borderRadius: 8,
          border: '1px solid rgba(255,255,255,0.04)', fontSize: 11,
        }}>
          <span style={{ color: '#4A5568' }}>OS FINGERPRINT</span>
          {[
            ['System', `${scanData.os_info.system} ${scanData.os_info.release}`],
            ['Hostname', scanData.os_info.hostname],
            ['CPU Cores', scanData.os_info.cpu_count],
            ['Org', scanData.host?.org],
            ['Timezone', scanData.host?.timezone],
            ['Scan Time', scanData.scan_time ? new Date(scanData.scan_time + 'Z').toLocaleTimeString() : '—'],
          ].map(([k, v]) => v && (
            <span key={k} style={{ color: '#64748B' }}>
              {k}: <span style={{ color: '#8892B0', fontFamily: 'monospace' }}>{v}</span>
            </span>
          ))}
        </div>
      )}

      {/* Inline animation keyframes */}
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes map-pulse {
          0% { transform: scale(0.8); opacity: 0.8; }
          100% { transform: scale(2.5); opacity: 0; }
        }
        .threat-table tbody tr:hover { background: rgba(55,138,221,0.05) !important; }
        .threat-table td { padding: 10px 14px; vertical-align: middle; }
      `}</style>
    </div>
  );
}

// ── Style helpers ────────────────────────────────────────────────────────────
function cardStyle(accentColor) {
  return {
    background: 'rgba(15,20,32,0.8)',
    border: `1px solid ${accentColor}22`,
    borderRadius: 10,
    padding: '14px 16px',
    backdropFilter: 'blur(8px)',
  };
}

function btnStyle(color) {
  return {
    display: 'inline-flex', alignItems: 'center', gap: 5,
    padding: '5px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600,
    border: `1px solid ${color}44`, background: `${color}18`,
    color, cursor: 'pointer', letterSpacing: 0.3,
    transition: 'all 0.2s',
  };
}
