import { useState } from 'react';
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
import { useDashboard } from './hooks/useDashboard';

function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const { stats, loading, refresh, isLive } = useDashboard();

  const renderView = () => {
    switch (activeView) {
      case 'dashboard': return <DashboardView stats={stats} isLive={isLive} />;
      case 'threats': return <ThreatsView stats={stats} />;
      case 'incidents': return <IncidentsView stats={stats} />;
      case 'scanner': return <ScannerView onScanComplete={refresh} />;
      case 'predictions': return <PredictionsView />;
      case 'anomalies': return <AnomaliesView />;
      case 'mitre': return <MitreView stats={stats} />;
      case 'killchain': return <KillChainView stats={stats} />;
      case 'geomap': return <GeoMapView stats={stats} />;
      case 'posture': return <SecurityPostureView stats={stats} />;
      case 'playbooks': return <PlaybookView />;
      default: return <SecurityPostureView stats={stats} />;
    }
  };

  return (
    <div className="app-layout">
      <Sidebar activeView={activeView} setActiveView={setActiveView} stats={stats} />
      <div className="main-content">
        <Header activeView={activeView} onRefresh={refresh} onScan={() => setActiveView('scanner')} isLive={isLive} />
        <div className="dashboard">
          {loading && !stats ? (
            <div className="scanning"><div className="scanning-ring" /><div className="scanning-text">Connecting to ITAP backend...</div></div>
          ) : renderView()}
        </div>
      </div>
    </div>
  );
}

export default App;
