import { useState, useEffect } from 'react';
import { Map, Activity, ShieldAlert, Crosshair } from 'lucide-react';
import { api } from '../api';

// Miller Cylindrical projection approximation
function project(lat, lon, w, h) {
  const x = (lon + 180) * (w / 360);
  const latRad = lat * Math.PI / 180;
  const y = (h / 2) - (w / (2 * Math.PI)) * Math.log(Math.tan((Math.PI / 4) + (latRad / 2)));
  return { x: Math.max(0, Math.min(w, x)), y: Math.max(0, Math.min(h, y)) };
}

const SEVERITY_COLORS = { critical: '#FF3B5C', high: '#F97316', medium: '#F59E0B', low: '#22C55E' };
const SERVER_LAT = 38.9072;
const SERVER_LON = -77.0369;

export default function GeoMapView({ stats }) {
  const [globalThreats, setGlobalThreats] = useState(null);

  useEffect(() => {
    // If no direct local threats with coordinates, fetch global threats for the map
    if (!stats?.threats_by_country?.length) {
      api.getGlobalThreats().then(setGlobalThreats).catch(console.error);
    }
  }, [stats]);

  let displayThreats = stats?.threats_by_country || [];
  let isGlobalMode = false;
  
  if (displayThreats.length === 0 && globalThreats?.cisa_kev) {
    displayThreats = globalThreats.cisa_kev.map(k => ({
      country: k.estimated_origin,
      lat: k.lat,
      lon: k.lon,
      severity: 'critical',
      title: k.cveID,
      desc: k.vulnerabilityName
    }));
    isGlobalMode = true;
  }

  const W = 1000, H = 500;
  const serverPos = project(SERVER_LAT, SERVER_LON, W, H);

  const totalThreats = displayThreats.length;
  const criticalCount = displayThreats.filter(t => t.severity === 'critical').length;
  const topCountry = displayThreats.reduce((acc, t) => {
    acc[t.country] = (acc[t.country] || 0) + 1;
    return acc;
  }, {});
  const mostTargeted = Object.keys(topCountry).sort((a,b) => topCountry[b] - topCountry[a])[0] || 'Unknown';

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title"><Map size={16} /> {isGlobalMode ? 'Global CISA KEV Threat Map' : 'Local Attack Geolocation Map'}</div>
          <span style={{ fontSize: 12, color: isGlobalMode ? '#F59E0B' : '#22C55E' }}>● {isGlobalMode ? 'GLOBAL FEED' : 'LIVE TELEMETRY'}</span>
        </div>
        
        <div className="panel-body" style={{ position: 'relative', padding: 0, overflow: 'hidden', background: '#0a0d14' }}>
          
          <div style={{ position: 'absolute', top: 20, right: 20, width: 220, background: 'rgba(21,27,43,0.85)', backdropFilter: 'blur(8px)', border: '1px solid rgba(55,138,221,0.2)', borderRadius: 8, padding: 15, zIndex: 20 }}>
             <h4 style={{ color: '#8892B0', fontSize: 11, textTransform: 'uppercase', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}><Activity size={14} /> Analysis</h4>
             
             <div style={{ marginBottom: 12 }}>
               <div style={{ color: '#F0EFE9', fontSize: 24, fontWeight: 700, lineHeight: 1 }}>{totalThreats}</div>
               <div style={{ color: '#64748B', fontSize: 11 }}>Active Threat Sources</div>
             </div>
             
             <div style={{ marginBottom: 12 }}>
               <div style={{ color: '#FF3B5C', fontSize: 24, fontWeight: 700, lineHeight: 1 }}>{criticalCount}</div>
               <div style={{ color: '#64748B', fontSize: 11 }}>Critical Severity</div>
             </div>
             
             <div>
               <div style={{ color: '#F0EFE9', fontSize: 14, fontWeight: 600 }}>{mostTargeted}</div>
               <div style={{ color: '#64748B', fontSize: 11 }}>Top Origin Country</div>
             </div>
          </div>

          <div className="threat-map" style={{ height: 500, width: '100%', position: 'relative' }}>
            <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: '100%', position: 'absolute' }}>
              
              <image href="https://raw.githubusercontent.com/d3/d3-geo/master/img/equirectangular.png" width={W} height={H} opacity="0.15" style={{ filter: 'invert(1) sepia(1) hue-rotate(180deg) brightness(0.8)' }} preserveAspectRatio="none" />
              
              <g opacity="0.05" stroke="#378ADD" strokeWidth="1">
                {Array.from({length: 20}).map((_, i) => <line key={`h${i}`} x1="0" y1={i*(H/20)} x2={W} y2={i*(H/20)} />)}
                {Array.from({length: 40}).map((_, i) => <line key={`v${i}`} x1={i*(W/40)} y1="0" x2={i*(W/40)} y2={H} />)}
              </g>

              {displayThreats.map((t, i) => {
                const pos = project(t.lat, t.lon, W, H);
                const color = SEVERITY_COLORS[t.severity] || '#F59E0B';
                if (['critical', 'high'].includes(t.severity)) {
                  const cx = (pos.x + serverPos.x) / 2;
                  const cy = (pos.y + serverPos.y) / 2 - 100;
                  return (
                    <path key={`line-${i}`}
                      d={`M${pos.x},${pos.y} Q${cx},${cy} ${serverPos.x},${serverPos.y}`}
                      fill="none"
                      stroke={color}
                      strokeWidth="1.5"
                      opacity="0.6"
                      className="attack-line"
                    />
                  );
                }
                return null;
              })}
            </svg>

            <div className="map-dot" style={{ left: `${(serverPos.x/W)*100}%`, top: `${(serverPos.y/H)*100}%`, color: '#378ADD', zIndex: 5 }}>
              <div style={{ position: 'absolute', top: -20, left: -40, width: 80, textAlign: 'center', fontSize: 10, color: '#378ADD', fontWeight: 'bold' }}>TARGET</div>
              <Crosshair size={24} color="#378ADD" style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', opacity: 0.8 }} />
            </div>

            {displayThreats.map((t, i) => {
              const pos = project(t.lat, t.lon, W, H);
              const color = SEVERITY_COLORS[t.severity] || '#F59E0B';
              return (
                <div key={`dot-${i}`} className={`map-dot ${t.severity}`}
                  style={{ left: `${(pos.x / W) * 100}%`, top: `${(pos.y / H) * 100}%`, background: color, color: color }}>
                  
                  <div className="map-tooltip" style={{ position: 'absolute', bottom: 15, left: '50%', transform: 'translateX(-50%)', background: 'rgba(15,20,32,0.95)', border: `1px solid ${color}`, borderRadius: 6, padding: '8px 12px', minWidth: 150, pointerEvents: 'none', opacity: 0, transition: 'opacity 0.2s', zIndex: 100, backdropFilter: 'blur(4px)', whiteSpace: 'nowrap' }}>
                    <div style={{ color: '#F0EFE9', fontWeight: 600, fontSize: 12, marginBottom: 4 }}>{t.country}</div>
                    <div style={{ color: '#8892B0', fontSize: 10 }}>{t.title}</div>
                    <div style={{ marginTop: 6, display: 'inline-block', padding: '2px 6px', background: color, color: '#000', borderRadius: 4, fontSize: 9, fontWeight: 'bold', textTransform: 'uppercase' }}>
                      {t.severity}
                    </div>
                  </div>
                </div>
              );
            })}
            
            <style>{`.map-dot:hover .map-tooltip { opacity: 1 !important; pointer-events: auto; }`}</style>
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 20 }}>
        <div className="panel-header"><div className="panel-title"><ShieldAlert size={16}/> Active Threat Sources Detail</div></div>
        <div className="panel-body no-pad">
          <table className="threat-table">
            <thead><tr><th>Country</th><th>Threat Detected</th><th>Severity</th><th>Coordinates</th></tr></thead>
            <tbody>
              {displayThreats.map((t, i) => (
                <tr key={i}>
                  <td style={{ fontWeight: 500, color: '#F0EFE9' }}>📍 {t.country}</td>
                  <td>{t.title} <span style={{fontSize: 10, color: '#64748B', display: 'block'}}>{t.desc}</span></td>
                  <td><span className={`severity-badge ${t.severity}`}>{t.severity}</span></td>
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 11 }}>{t.lat?.toFixed(2)}, {t.lon?.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {displayThreats.length === 0 && <div style={{ padding: 20, textAlign: 'center', color: '#64748B' }}>No geolocation data available.</div>}
        </div>
      </div>
    </div>
  );
}
