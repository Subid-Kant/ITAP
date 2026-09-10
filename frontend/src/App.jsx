import { useState, useCallback, useEffect, useRef } from 'react';
import './index.css';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import DashboardView from './components/DashboardView';
import ThreatsView from './components/ThreatsView';
import IncidentsView from './components/IncidentsView';
import ScannerView from './components/ScannerView';
import PredictionsView, { AnomaliesView } from './components/PredictionsView';
import MitreView from './components/MitreView';
import KillChainView from './components/KillChainView';
import GeoMapView from './components/GeoMapView';
import PlaybookView from './components/PlaybookView';
import SecurityPostureView from './components/SecurityPostureView';
import IOCWorkbench from './components/IOCWorkbench';
import ReportsView from './components/ReportsView';
import LoginView from './components/LoginView';
import HistoryView from './components/HistoryView';
import CommandPalette from './components/CommandPalette';
import ToastProvider, { useToast } from './components/ToastNotification';
import { AuthProvider, useAuth } from './hooks/useAuth';
import { WebSocketProvider } from './hooks/useWebSocket';
import { useDashboard } from './hooks/useDashboard';
import { api } from './services/api';

function AppContent() {
  const [activeView, setActiveView] = useState('dashboard');
  const { isAuthenticated, user, logout } = useAuth();
  const { stats, loading, refresh, isLive } = useDashboard(isAuthenticated);
  const { addToast } = useToast();
  const [paletteOpen, setPaletteOpen] = useState(false);

  // ─── Scheduler State ──────────────────────────────────────────
  const [scheduler, setScheduler] = useState({
    active: false,
    domain: '',
    intervalMs: 60000,
    scanHistory: [],
    startedAt: null,
    totalScans: 0,
    scanning: false,
    stoppedAt: null,
  });
  const schedulerIntervalRef = useRef(null);
  const schedulerTargetIdRef = useRef(null);

  // Run a single scheduled scan cycle
  const runScheduledScan = useCallback(async (domain) => {
    setScheduler(s => ({ ...s, scanning: true }));
    try {
      // Create or reuse target
      let targetId = schedulerTargetIdRef.current;
      if (!targetId) {
        try {
          const target = await api.createTarget({ domain });
          targetId = target.id;
        } catch (createErr) {
          // If target already exists (409), fetch it from the targets list
          if (createErr.status === 409) {
            const targets = await api.getTargets();
            const existing = targets.find(t => t.domain === domain);
            if (existing) targetId = existing.id;
            else throw createErr;
          } else {
            throw createErr;
          }
        }
        schedulerTargetIdRef.current = targetId;
      }
      // Run scan
      const scan = await api.runScan({ target_id: targetId, scan_types: ['shodan', 'virustotal', 'cve'] });
      // Record success
      const entry = {
        timestamp: Date.now(),
        riskScore: scan.risk_score || 0,
        threatsCreated: scan.threats_created?.length || 0,
        error: null,
      };
      setScheduler(s => ({
        ...s,
        scanning: false,
        totalScans: s.totalScans + 1,
        scanHistory: [entry, ...s.scanHistory].slice(0, 100),
      }));
      // Refresh dashboard to propagate data to all tabs
      refresh();
      addToast(`Scheduler scan #${scheduler.totalScans + 1} complete — Risk: ${scan.risk_score || 0}`, 'info', 4000);
    } catch (err) {
      const entry = {
        timestamp: Date.now(),
        riskScore: 0,
        threatsCreated: 0,
        error: err.message || 'Scan failed',
      };
      setScheduler(s => ({
        ...s,
        scanning: false,
        totalScans: s.totalScans + 1,
        scanHistory: [entry, ...s.scanHistory].slice(0, 100),
      }));
      addToast(`Scheduler scan failed: ${err.message}`, 'error', 5000);
    }
  }, [refresh, addToast, scheduler.totalScans]);

  const startScheduler = useCallback((domain, intervalMs) => {
    // Clear any existing interval
    if (schedulerIntervalRef.current) {
      clearInterval(schedulerIntervalRef.current);
    }
    schedulerTargetIdRef.current = null;

    setScheduler({
      active: true,
      domain,
      intervalMs,
      scanHistory: [],
      startedAt: Date.now(),
      totalScans: 0,
      scanning: false,
      stoppedAt: null,
    });

    addToast(`Scheduler started: scanning ${domain} every ${intervalMs / 1000}s`, 'success', 5000);

    // Run first scan immediately
    runScheduledScan(domain);

    // Set up interval for subsequent scans
    schedulerIntervalRef.current = setInterval(() => {
      runScheduledScan(domain);
    }, intervalMs);
  }, [addToast, runScheduledScan]);

  const stopScheduler = useCallback(() => {
    if (schedulerIntervalRef.current) {
      clearInterval(schedulerIntervalRef.current);
      schedulerIntervalRef.current = null;
    }
    schedulerTargetIdRef.current = null;
    setScheduler(s => ({
      ...s,
      active: false,
      scanning: false,
      stoppedAt: Date.now(),
    }));
    addToast('Scheduler stopped', 'warning', 3000);
  }, [addToast]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (schedulerIntervalRef.current) {
        clearInterval(schedulerIntervalRef.current);
      }
    };
  }, []);

  // Global Cmd/Ctrl+K listener for Command Palette
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setPaletteOpen(p => !p);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Lifted scanner state — persists across view switches
  const [scannerState, setScannerState] = useState({
    domain: '',
    results: null,
    error: '',
  });

  const handleScanComplete = useCallback(() => {
    // Refresh dashboard so new target/threats appear immediately
    refresh();
  }, [refresh]);

  const handleWSEvent = useCallback((event) => {
    if (event.type === 'threat_detected') {
      const sev = event.data?.severity || 'medium';
      addToast(
        `${event.data?.title || 'New threat detected'} — ${event.data?.target || ''}`,
        sev === 'critical' ? 'critical' : sev === 'high' ? 'threat' : 'warning',
        7000,
      );
    } else if (event.type === 'incident_created') {
      addToast(`Incident created: ${event.data?.title}`, 'warning', 5000);
    } else if (event.type === 'scan_complete') {
      addToast(`Scan complete: ${event.data?.target} — Risk ${event.data?.risk_level}`, 'info', 4000);
    }
  }, [addToast]);

  if (!isAuthenticated) {
    return <LoginView />;
  }

  const handleNewSession = async () => {
    if (!window.confirm('Are you sure you want to archive current data and start a new session?')) return;
    // Stop scheduler if active
    if (scheduler.active) {
      stopScheduler();
    }
    try {
      await api.newSession();
      addToast('New session started. Old data archived to History.', 'success', 5000);
      refresh();
      setActiveView('dashboard');
    } catch (err) {
      console.error(err);
      addToast('Failed to start new session', 'danger', 5000);
    }
  };

  const renderView = () => {
    switch (activeView) {
      case 'dashboard':   return <DashboardView stats={stats} isLive={isLive} />;
      case 'threats':     return <ThreatsView stats={stats} />;
      case 'incidents':   return <IncidentsView stats={stats} />;
      case 'scanner':     return <ScannerView
                            onScanComplete={handleScanComplete}
                            scannerState={scannerState}
                            setScannerState={setScannerState}
                          />;

      case 'predictions': return <PredictionsView />;
      case 'anomalies':   return <AnomaliesView />;
      case 'mitre':       return <MitreView stats={stats} />;
      case 'killchain':   return <KillChainView stats={stats} />;
      case 'geomap':      return <GeoMapView stats={stats} />;
      case 'posture':     return <SecurityPostureView stats={stats} scheduler={scheduler} />;
      case 'playbooks':   return <PlaybookView />;
      case 'ioc':         return <IOCWorkbench />;
      case 'reports':     return <ReportsView scheduler={scheduler} />;
      case 'history':     return <HistoryView />;
      default:            return <SecurityPostureView stats={stats} scheduler={scheduler} />;
    }
  };

  return (
    <WebSocketProvider onEvent={handleWSEvent}>
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onNavigate={(view) => { setActiveView(view); setPaletteOpen(false); }}
      />
      <div className="app-layout">
        <Sidebar
          activeView={activeView}
          setActiveView={setActiveView}
          stats={stats}
          user={user}
          onLogout={logout}
        />
        <div className="main-content">
          <Header
            activeView={activeView}
            onRefresh={refresh}
            onScan={() => setActiveView('scanner')}
            onNewSession={handleNewSession}
            isLive={isLive}
            user={user}
            onOpenPalette={() => setPaletteOpen(true)}
            scheduler={scheduler}
            onSchedulerStart={startScheduler}
            onSchedulerStop={stopScheduler}
          />
          <div className="dashboard">
            {loading && !stats ? (
              <div className="scanning">
                <div className="scanning-ring" />
                <div className="scanning-text">Connecting to ITAP backend...</div>
              </div>
            ) : renderView()}
          </div>
        </div>
      </div>
    </WebSocketProvider>
  );
}

function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <AppContent />
      </ToastProvider>
    </AuthProvider>
  );
}

export default App;
