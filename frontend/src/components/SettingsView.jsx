import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Palette, Key, Crosshair, Shield, CheckCircle2, Save, User, Laptop } from 'lucide-react';
import { useSettings } from '../hooks/useSettings';
import AnimatedButton from './ui/AnimatedButton';
import HoverCard from './ui/HoverCard';

export default function SettingsView() {
  const { settings, updateSettings } = useSettings();
  const [activeTab, setActiveTab] = useState('appearance');
  const [saveSuccess, setSaveSuccess] = useState(false);

  const [localScanner, setLocalScanner] = useState({
    scanDepth: settings.scanDepth,
    autoArchiveDays: settings.autoArchiveDays,
  });

  // NOTE: a `localKeys` state + `handleSaveKeys` lived here, writing the OSINT API
  // keys into localStorage via updateSettings. They are gone: the backend owns the
  // keys (backend/.env -> settings), and a browser-side copy was readable by any
  // script on the page.

  const handleSaveScanner = () => {
    updateSettings(localScanner);
    showSaveSuccess();
  };

  const showSaveSuccess = () => {
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 2000);
  };

  const TABS = [
    { id: 'appearance', label: 'Appearance', icon: Palette, desc: 'Themes, density, animations' },
    { id: 'integrations', label: 'API & Integrations', icon: Key, desc: 'OSINT API keys' },
    { id: 'scanner', label: 'Scanner & AI Config', icon: Crosshair, desc: 'Depth & automation' },
    { id: 'account', label: 'Account & Security', icon: Shield, desc: 'Profile & 2FA' },
  ];

  return (
    <div style={{ padding: 24, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ margin: 0, marginBottom: 4 }}>Settings</h2>
          <p style={{ color: 'var(--text-muted)', margin: 0, fontSize: 13 }}>
            Manage platform preferences, OSINT integrations, and security policies.
          </p>
        </div>
        <AnimatePresence>
          {saveSuccess && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--success)', fontSize: 13, background: 'rgba(34,197,94,0.1)', padding: '6px 12px', borderRadius: 20 }}
            >
              <CheckCircle2 size={14} /> Settings Saved
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <div style={{ display: 'flex', gap: 24, flex: 1, minHeight: 0 }}>
        {/* Sidebar Tabs */}
        <div style={{ width: 260, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
          {TABS.map(tab => {
            const isActive = activeTab === tab.id;
            return (
              <AnimatedButton
                key={tab.id}
                variant="none"
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px',
                  background: isActive ? 'rgba(55,138,221,0.1)' : 'transparent',
                  border: `1px solid ${isActive ? 'rgba(55,138,221,0.2)' : 'transparent'}`,
                  borderRadius: 'var(--radius-md)', cursor: 'pointer', textAlign: 'left',
                  color: isActive ? 'var(--accent-blue)' : 'var(--text-main)',
                  position: 'relative', overflow: 'hidden'
                }}
              >
                {isActive && (
                  <motion.div
                    layoutId="settings-tab-active"
                    style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 3, background: 'var(--accent-blue)' }}
                  />
                )}
                <tab.icon size={18} style={{ color: isActive ? 'var(--accent-blue)' : 'var(--text-muted)' }} />
                <div>
                  <div style={{ fontWeight: isActive ? 600 : 500, fontSize: 14 }}>{tab.label}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{tab.desc}</div>
                </div>
              </AnimatedButton>
            );
          })}
        </div>

        {/* Content Area */}
        <HoverCard className="panel" style={{ flex: 1, overflowY: 'auto', margin: 0 }}>
          <div className="panel-body" style={{ padding: 32 }}>
            <AnimatePresence mode="wait">
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, x: 10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -10 }}
                transition={{ duration: 0.15 }}
              >
                {/* ─── APPEARANCE ────────────────────────────────────────────────────────── */}
                {activeTab === 'appearance' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
                    <div>
                      <h3 style={{ margin: '0 0 16px', fontSize: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Palette size={16} /> Visual Theme
                      </h3>
                      <div style={{ display: 'flex', gap: 16 }}>
                        {['dark', 'light', 'black'].map(theme => (
                          <div
                            key={theme}
                            onClick={() => updateSettings({ theme })}
                            style={{
                              flex: 1, padding: 16, borderRadius: 'var(--radius-md)', cursor: 'pointer',
                              border: `2px solid ${settings.theme === theme ? 'var(--accent-blue)' : 'var(--border-subtle)'}`,
                              background: theme === 'light' ? '#F8FAFC' : theme === 'black' ? '#000000' : '#0F172A',
                              color: theme === 'light' ? '#0F172A' : '#FFFFFF',
                              textAlign: 'center', textTransform: 'capitalize', fontWeight: 500
                            }}
                          >
                            {theme} Mode
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h3 style={{ margin: '0 0 16px', fontSize: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Laptop size={16} /> UI Density
                      </h3>
                      <div style={{ display: 'flex', gap: 16 }}>
                        {[
                          { id: 'comfortable', label: 'Comfortable', desc: 'Standard padding and typography' },
                          { id: 'compact', label: 'Compact', desc: 'Dense data display for power users' }
                        ].map(d => (
                          <div
                            key={d.id}
                            onClick={() => updateSettings({ density: d.id })}
                            style={{
                              flex: 1, padding: 16, borderRadius: 'var(--radius-md)', cursor: 'pointer',
                              border: `2px solid ${settings.density === d.id ? 'var(--accent-blue)' : 'var(--border-subtle)'}`,
                              background: 'var(--bg-card)'
                            }}
                          >
                            <div style={{ fontWeight: 500, marginBottom: 4 }}>{d.label}</div>
                            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{d.desc}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h3 style={{ margin: '0 0 16px', fontSize: 16 }}>Motion & Animations</h3>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer' }}>
                        <input
                          type="checkbox"
                          checked={settings.animations}
                          onChange={(e) => updateSettings({ animations: e.target.checked })}
                          style={{ width: 18, height: 18, accentColor: 'var(--accent-blue)' }}
                        />
                        <div>
                          <div style={{ fontWeight: 500 }}>Enable UI Animations</div>
                          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Includes HoverCards, staggered lists, and spring physics.</div>
                        </div>
                      </label>
                    </div>
                  </div>
                )}

                {/* ─── INTEGRATIONS ──────────────────────────────────────────────────────── */}
                {activeTab === 'integrations' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
                    <div>
                      <h3 style={{ margin: '0 0 8px', fontSize: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Key size={16} /> OSINT API Keys
                      </h3>
                      <p style={{ color: 'var(--text-muted)', fontSize: 13, marginBottom: 24 }}>
                        OSINT keys are configured on the <strong>backend</strong>, in <code>backend/.env</code>.
                        The browser never holds them.
                      </p>

                      <div style={{
                        padding: '16px 18px',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-md)',
                        background: 'var(--bg-app)',
                        fontSize: 13,
                        lineHeight: 1.7,
                        color: 'var(--text-muted)',
                      }}>
                        {/* These fields used to write the keys into localStorage, where any
                            XSS — or anyone with access to the browser profile — could read
                            them. The backend already reads them from settings, so the
                            duplicate, less-protected copy was removed instead of secured. */}
                        <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 12, color: 'var(--text-main)' }}>
                          SHODAN_API_KEY=<br />
                          VIRUSTOTAL_API_KEY=<br />
                          ALIENVAULT_OTX_KEY=<br />
                          CENSYS_API_ID / CENSYS_API_SECRET=<br />
                          NVD_API_KEY=
                        </div>
                        <div style={{ marginTop: 12 }}>
                          They are read once at startup, so a changed key needs a backend
                          restart to take effect.
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* ─── SCANNER CONFIG ────────────────────────────────────────────────────── */}
                {activeTab === 'scanner' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
                    <div>
                      <h3 style={{ margin: '0 0 16px', fontSize: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Crosshair size={16} /> Default Scan Depth
                      </h3>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                        {[
                          { id: 'fast', label: 'Fast Scan', desc: 'Basic port scan and rapid DNS recon. Fast but shallow.' },
                          { id: 'normal', label: 'Normal Scan (Recommended)', desc: 'Standard Nmap SYN scan + CVE lookups + Shodan queries.' },
                          { id: 'deep', label: 'Deep Aggressive Scan', desc: 'Full OSINT extraction, intense vulnerability probing. May trigger alerts.' }
                        ].map(depth => (
                          <label key={depth.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 16, border: `1px solid ${localScanner.scanDepth === depth.id ? 'var(--accent-blue)' : 'var(--border-subtle)'}`, borderRadius: 'var(--radius-md)', cursor: 'pointer', background: localScanner.scanDepth === depth.id ? 'rgba(55,138,221,0.05)' : 'transparent' }}>
                            <input
                              type="radio"
                              name="scanDepth"
                              value={depth.id}
                              checked={localScanner.scanDepth === depth.id}
                              onChange={() => setLocalScanner(prev => ({ ...prev, scanDepth: depth.id }))}
                              style={{ width: 18, height: 18, accentColor: 'var(--accent-blue)' }}
                            />
                            <div>
                              <div style={{ fontWeight: 500, color: localScanner.scanDepth === depth.id ? 'var(--accent-blue)' : 'var(--text-main)' }}>{depth.label}</div>
                              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{depth.desc}</div>
                            </div>
                          </label>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h3 style={{ margin: '0 0 16px', fontSize: 16 }}>Data Retention Policy</h3>
                      <div className="input-group">
                        <label style={{ display: 'block', marginBottom: 8, fontSize: 13, fontWeight: 500, color: 'var(--text-main)' }}>Auto-Archive History (Days)</label>
                        <input
                          type="number"
                          min="1"
                          max="365"
                          value={localScanner.autoArchiveDays}
                          onChange={e => setLocalScanner(prev => ({ ...prev, autoArchiveDays: parseInt(e.target.value) || 30 }))}
                          style={{ width: 120, padding: '10px 14px', background: 'var(--bg-app)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)', color: 'var(--text-main)' }}
                        />
                        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>Scans older than this will be automatically archived to save database space.</div>
                      </div>
                    </div>

                    <div style={{ marginTop: 8 }}>
                      <AnimatedButton onClick={handleSaveScanner} className="primary" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 20px', background: 'var(--accent-blue)', color: '#fff', border: 'none', borderRadius: 'var(--radius-md)', fontWeight: 600 }}>
                        <Save size={16} /> Save Configuration
                      </AnimatedButton>
                    </div>
                  </div>
                )}

                {/* ─── ACCOUNT & SECURITY ────────────────────────────────────────────────── */}
                {activeTab === 'account' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
                    <div>
                      <h3 style={{ margin: '0 0 16px', fontSize: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <User size={16} /> Profile Information
                      </h3>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 24, marginBottom: 24 }}>
                        <div style={{ width: 80, height: 80, borderRadius: '50%', background: 'rgba(55,138,221,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid var(--accent-blue)' }}>
                          <User size={32} color="var(--accent-blue)" />
                        </div>
                        <div>
                          <AnimatedButton style={{ padding: '8px 16px', background: 'var(--bg-app)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)', color: 'var(--text-main)', fontSize: 13 }}>
                            Upload New Avatar
                          </AnimatedButton>
                        </div>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
                        <div className="input-group">
                          <label style={{ display: 'block', marginBottom: 8, fontSize: 13, fontWeight: 500, color: 'var(--text-main)' }}>Full Name</label>
                          <input type="text" defaultValue="Admin User" style={{ width: '100%', padding: '10px 14px', background: 'var(--bg-app)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)', color: 'var(--text-main)' }} />
                        </div>
                        <div className="input-group">
                          <label style={{ display: 'block', marginBottom: 8, fontSize: 13, fontWeight: 500, color: 'var(--text-main)' }}>Role</label>
                          <input type="text" disabled value="Administrator" style={{ width: '100%', padding: '10px 14px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)', color: 'var(--text-muted)', cursor: 'not-allowed' }} />
                        </div>
                      </div>
                    </div>

                    <div>
                      <h3 style={{ margin: '0 0 16px', fontSize: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Shield size={16} /> Security
                      </h3>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: 16, border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', background: 'var(--bg-card)' }}>
                        <div>
                          <div style={{ fontWeight: 500, marginBottom: 4 }}>Two-Factor Authentication (2FA)</div>
                          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Add an extra layer of security to your account.</div>
                        </div>
                        <AnimatedButton style={{ padding: '8px 16px', background: 'var(--accent-blue)', color: '#fff', border: 'none', borderRadius: 'var(--radius-sm)', fontWeight: 600, fontSize: 13 }}>
                          Enable 2FA
                        </AnimatedButton>
                      </div>
                    </div>

                    <div>
                       <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                         Note: Account changes require backend API integration which is currently mocked.
                       </div>
                    </div>
                  </div>
                )}
              </motion.div>
            </AnimatePresence>
          </div>
        </HoverCard>
      </div>
    </div>
  );
}
