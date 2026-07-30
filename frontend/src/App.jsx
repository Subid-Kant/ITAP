import { useState, useCallback } from 'react';
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
import ToastProvider, { useToast } from './components/ToastNotification';
import { AuthProvider, useAuth } from './hooks/useAuth';
import { WebSocketProvider } from './hooks/useWebSocket';
import { useDashboard } from './hooks/useDashboard';

function AppContent() {
  const [activeView, setActiveView] = useState('dashboard');
  const { isAuthenticated, user, logout } = useAuth();
  const { stats, loading, refresh, isLive } = useDashboard(isAuthenticated);
  const { addToast } = useToast();

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

  const renderView = () => {
    switch (activeView) {
      case 'dashboard':   return <DashboardView stats={stats} isLive={isLive} />;
      case 'threats':     return <ThreatsView stats={stats} />;
      case 'incidents':   return <IncidentsView stats={stats} />;
      case 'scanner':     return <ScannerView onScanComplete={refresh} />;
      case 'predictions': return <PredictionsView />;
      case 'anomalies':   return <AnomaliesView />;
      case 'mitre':       return <MitreView stats={stats} />;
      case 'killchain':   return <KillChainView stats={stats} />;
      case 'geomap':      return <GeoMapView stats={stats} />;
      case 'posture':     return <SecurityPostureView stats={stats} />;
      case 'playbooks':   return <PlaybookView />;
      case 'ioc':         return <IOCWorkbench />;
      case 'reports':     return <ReportsView />;
      default:            return <SecurityPostureView stats={stats} />;
    }
  };

  return (
    <WebSocketProvider onEvent={handleWSEvent}>
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
            isLive={isLive}
            user={user}
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
