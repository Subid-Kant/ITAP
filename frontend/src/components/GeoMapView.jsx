import { useState, useEffect } from 'react';
import { Map, Activity, ShieldAlert, Crosshair } from 'lucide-react';
import { ComposableMap, Geographies, Geography, Marker, Line } from "react-simple-maps";
import { api } from '../api';

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

const SEVERITY_COLORS = { critical: '#FF3B5C', high: '#F97316', medium: '#F59E0B', low: '#22C55E' };
const SERVER_LAT = 38.9072;
const SERVER_LON = -77.0369;

export default function GeoMapView({ stats }) {
  const [globalThreats, setGlobalThreats] = useState(null);
  const [tooltipContent, setTooltipContent] = useState("");

  useEffect(() => {
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

          <div style={{ height: 500, width: '100%', position: 'relative' }}>
            <ComposableMap projectionConfig={{ scale: 140 }} style={{ width: "100%", height: "100%" }}>
              <Geographies geography={geoUrl}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill="#1e293b"
                      stroke="#334155"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: "none" },
                        hover: { fill: "#334155", outline: "none" },
                        pressed: { outline: "none" },
                      }}
                    />
                  ))
                }
              </Geographies>

              {/* Server Marker */}
              <Marker coordinates={[SERVER_LON, SERVER_LAT]}>
                <g transform="translate(-12, -12)">
                  <Crosshair size={24} color="#378ADD" opacity={0.8} />
                </g>
                <text textAnchor="middle" y={-20} style={{ fontFamily: "system-ui", fill: "#378ADD", fontSize: 10, fontWeight: "bold" }}>
                  TARGET
                </text>
              </Marker>

              {/* Attack Lines and Markers */}
              {displayThreats.map((t, i) => {
                const color = SEVERITY_COLORS[t.severity] || '#F59E0B';
                return (
                  <g key={`threat-${i}`}>
                    {['critical', 'high'].includes(t.severity) && (
                      <Line
                        from={[t.lon, t.lat]}
                        to={[SERVER_LON, SERVER_LAT]}
                        stroke={color}
                        strokeWidth={1.5}
                        strokeLinecap="round"
                        className="attack-line"
                        style={{ strokeDasharray: "4, 4", opacity: 0.6 }}
                      />
                    )}
                    <Marker 
                      coordinates={[t.lon, t.lat]}
                      onMouseEnter={() => setTooltipContent(`${t.country}: ${t.title} (${t.severity.toUpperCase()})`)}
                      onMouseLeave={() => setTooltipContent("")}
                    >
                      <circle r={4} fill={color} stroke="#0a0d14" strokeWidth={1} />
                    </Marker>
                  </g>
                );
              })}
            </ComposableMap>

            {tooltipContent && (
              <div style={{
                position: 'absolute',
                bottom: 20,
                left: '50%',
                transform: 'translateX(-50%)',
                background: 'rgba(15,20,32,0.95)',
                border: `1px solid #378ADD`,
                borderRadius: 6,
                padding: '8px 12px',
                color: '#F0EFE9',
                fontSize: 12,
                fontWeight: 600,
                pointerEvents: 'none',
                zIndex: 100,
                backdropFilter: 'blur(4px)'
              }}>
                {tooltipContent}
              </div>
            )}
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
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: '#8892B0' }}>{t.lat.toFixed(4)}, {t.lon.toFixed(4)}</td>
                </tr>
              ))}
              {displayThreats.length === 0 && <tr><td colSpan="4" style={{ textAlign: 'center', color: '#64748B', padding: 20 }}>No active mapped threats.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
