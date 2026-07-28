import { useState, useEffect } from 'react';
import { Shield, Lock, User, Eye, EyeOff, AlertCircle, Activity } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

const DEMO_CREDS = [
  { role: 'admin', username: 'admin', description: 'Full access' },
  { role: 'analyst', username: 'analyst', description: 'SOC analyst' },
  { role: 'viewer', username: 'viewer', description: 'Read-only' },
];

export default function LoginView() {
  const { login, loading, error } = useAuth();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('ITAP@Admin2025!');
  const [showPass, setShowPass] = useState(false);
  const [particles, setParticles] = useState([]);

  // Generate background particles once
  useEffect(() => {
    setParticles(Array.from({ length: 40 }, (_, i) => ({
      id: i,
      left: `${Math.random() * 100}%`,
      top: `${Math.random() * 100}%`,
      size: Math.random() * 3 + 1,
      duration: Math.random() * 8 + 4,
      delay: Math.random() * 4,
    })));
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    await login(username, password);
  };

  const handleDemoClick = (cred) => {
    setUsername(cred.username);
    setPassword(`ITAP@${cred.username.charAt(0).toUpperCase() + cred.username.slice(1)}2025!`);
  };

  return (
    <div className="login-root">
      {/* Animated background particles */}
      <div className="login-particles">
        {particles.map(p => (
          <div key={p.id} className="login-particle" style={{
            left: p.left, top: p.top,
            width: p.size, height: p.size,
            animationDuration: `${p.duration}s`,
            animationDelay: `${p.delay}s`,
          }} />
        ))}
      </div>

      {/* Scan line effect */}
      <div className="login-scanline" />

      <div className="login-container">
        {/* Brand */}
        <div className="login-brand">
          <div className="login-logo">
            <Shield size={36} strokeWidth={1.5} />
          </div>
          <h1 className="login-title">ITAP</h1>
          <p className="login-subtitle">INTEGRATED THREAT ASSESSMENT PLATFORM</p>
          <div className="login-version">v2.0 — Advanced Intelligence, Integrated Defence</div>
        </div>

        {/* Live indicator */}
        <div className="login-status-bar">
          <span className="status-dot" />
          <span style={{ fontSize: 11, color: 'var(--accent-green)', letterSpacing: 1.5 }}>ALL SYSTEMS OPERATIONAL</span>
          <Activity size={12} color="var(--accent-green)" />
        </div>

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="login-form">
          <div className="login-field">
            <label className="login-label">USERNAME</label>
            <div className="login-input-wrap">
              <User size={16} className="login-icon" />
              <input
                id="login-username"
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                className="login-input"
                placeholder="Enter username"
                autoComplete="username"
                required
              />
            </div>
          </div>

          <div className="login-field">
            <label className="login-label">PASSWORD</label>
            <div className="login-input-wrap">
              <Lock size={16} className="login-icon" />
              <input
                id="login-password"
                type={showPass ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="login-input"
                placeholder="Enter password"
                autoComplete="current-password"
                required
              />
              <button type="button" className="login-eye" onClick={() => setShowPass(s => !s)}>
                {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>

          {error && (
            <div className="login-error">
              <AlertCircle size={14} />
              {error}
            </div>
          )}

          <button
            id="login-submit"
            type="submit"
            className="login-btn"
            disabled={loading}
          >
            {loading ? (
              <><div className="login-spinner" /> Authenticating...</>
            ) : (
              <><Shield size={16} /> Authenticate</>
            )}
          </button>
        </form>

        {/* Demo credential quick-fill */}
        <div className="login-demo">
          <div className="login-demo-title">DEMO ACCESS</div>
          <div className="login-demo-creds">
            {DEMO_CREDS.map(c => (
              <button key={c.role} className={`login-demo-btn role-${c.role}`}
                onClick={() => handleDemoClick(c)} type="button">
                <span className="role-badge">{c.role}</span>
                <span className="role-desc">{c.description}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="login-footer">
          <span>🔒 Protected by ITAP v2.0</span>
          <span>© 2025 SRMCEM Lucknow</span>
        </div>
      </div>
    </div>
  );
}
