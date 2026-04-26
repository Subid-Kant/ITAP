import { Map } from 'lucide-react';

// Simple mercator projection for world map
function project(lat, lon, w, h) {
  const x = ((lon + 180) / 360) * w;
  const latRad = (lat * Math.PI) / 180;
  const y = h / 2 - (h * Math.log(Math.tan(Math.PI / 4 + latRad / 2))) / (2 * Math.PI) * 0.85;
  return { x: Math.max(10, Math.min(w - 10, x)), y: Math.max(10, Math.min(h - 10, y)) };
}

const SEVERITY_COLORS = { critical: '#FF3B5C', high: '#F97316', medium: '#F59E0B', low: '#22C55E' };

export default function GeoMapView({ stats }) {
  const threats = stats?.threats_by_country || [];
  const W = 800, H = 400;

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title"><Map size={16} /> Global Threat Geolocation Map</div>
          <span style={{ fontSize: 12, color: '#6B7280' }}>{threats.length} threat sources</span>
        </div>
        <div className="panel-body">
          <div className="threat-map" style={{ height: 420 }}>
            {/* SVG World Map Outline */}
            <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: '100%', position: 'absolute' }}>
              {/* Simplified continent outlines */}
              <g opacity="0.15" stroke="#378ADD" fill="none" strokeWidth="0.8">
                {/* North America */}
                <path d="M120,80 L180,70 L220,90 L230,120 L200,160 L180,180 L160,200 L140,190 L100,160 L90,130 L100,100Z" />
                {/* South America */}
                <path d="M180,210 L200,200 L220,220 L230,260 L220,300 L200,330 L180,340 L170,310 L160,270 L170,230Z" />
                {/* Europe */}
                <path d="M360,70 L400,60 L430,70 L440,90 L420,110 L400,120 L380,115 L360,100Z" />
                {/* Africa */}
                <path d="M370,140 L420,130 L440,160 L450,200 L430,250 L400,280 L380,270 L360,240 L350,200 L360,160Z" />
                {/* Asia */}
                <path d="M440,60 L520,50 L600,60 L640,80 L650,120 L620,150 L580,160 L520,150 L480,130 L450,110 L440,80Z" />
                {/* Australia */}
                <path d="M600,250 L650,240 L680,260 L670,290 L640,300 L610,290 L600,270Z" />
              </g>
              {/* Grid lines */}
              <g opacity="0.05" stroke="#378ADD" strokeWidth="0.5">
                {[0,1,2,3,4,5,6,7].map(i => <line key={`h${i}`} x1="0" y1={i*50} x2={W} y2={i*50} />)}
                {[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15].map(i => <line key={`v${i}`} x1={i*50} y1="0" x2={i*50} y2={H} />)}
              </g>
            </svg>

            {/* Threat dots */}
            {threats.map((t, i) => {
              const pos = project(t.lat, t.lon, W, H);
              const color = SEVERITY_COLORS[t.severity] || '#F59E0B';
              return (
                <div key={i} className={`map-dot ${t.severity}`}
                  style={{ left: `${(pos.x / W) * 100}%`, top: `${(pos.y / H) * 100}%`, background: color, color: color }}
                  title={`${t.title} — ${t.country}`} />
              );
            })}
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 20 }}>
        <div className="panel-header"><div className="panel-title">Threat Sources by Country</div></div>
        <div className="panel-body no-pad">
          <table className="threat-table">
            <thead><tr><th>Country</th><th>Threat</th><th>Severity</th><th>Coordinates</th></tr></thead>
            <tbody>
              {threats.map((t, i) => (
                <tr key={i}>
                  <td style={{ fontWeight: 500, color: '#F0EFE9' }}>📍 {t.country}</td>
                  <td>{t.title}</td>
                  <td><span className={`severity-badge ${t.severity}`}>{t.severity}</span></td>
                  <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 11 }}>{t.lat?.toFixed(2)}, {t.lon?.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
