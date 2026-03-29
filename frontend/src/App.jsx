import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  LayoutDashboard, GitBranch, Crosshair, Users,
  Fingerprint, SlidersHorizontal, FileText, Database,
  ShieldCheck, Activity, Wifi, WifiOff, RefreshCw
} from 'lucide-react';

import ThreatOverview from './tabs/ThreatOverview';
import DetectionPipeline from './tabs/DetectionPipeline';
import TTPAnalysis from './tabs/TTPAnalysis';
import APTIntelligence from './tabs/APTIntelligence';
import ControlPlaneTab from './tabs/ControlPlaneTab';
import AuditTrailTab from './tabs/AuditTrailTab';
import RawData from './tabs/RawData';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const CONTROL_KEY = import.meta.env.VITE_CONTROL_API_KEY || (typeof window !== 'undefined' ? window.localStorage.getItem('AEGIS_CONTROL_API_KEY') || '' : '');

if (CONTROL_KEY) {
  axios.defaults.headers.common['X-Control-Key'] = CONTROL_KEY;
}

const TABS = [
  { id: 'overview',   label: 'Threat Overview',     icon: LayoutDashboard, color: '#00e0ff' },
  { id: 'pipeline',   label: 'Detection Pipeline',  icon: GitBranch,       color: '#a78bfa' },
  { id: 'ttp',        label: 'TTP Analysis',         icon: Crosshair,      color: '#f97316' },
  { id: 'apt',        label: 'APT Intelligence',     icon: Users,          color: '#ef4444' },
  { id: 'ja4',        label: 'JA4 Fingerprinting',   icon: Fingerprint,    color: '#22d3ee' },
  { id: 'control',    label: 'Control Plane',         icon: SlidersHorizontal, color: '#10b981' },
  { id: 'audit',      label: 'Audit Trail',           icon: FileText,       color: '#8b5cf6' },
  { id: 'data',       label: 'Flow Inspector',        icon: Database,       color: '#6b7280' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [apiStatus, setApiStatus] = useState('connecting');
  const [pipelineStatus, setPipelineStatus] = useState({});
  const [lastCheck, setLastCheck] = useState(null);

  const checkHealth = useCallback(async () => {
    try {
      const res = await axios.get(`${API}/api/health`, { timeout: 4000 });
      setApiStatus('online');
      setPipelineStatus(res.data.pipeline || {});
      setLastCheck(new Date());
    } catch {
      setApiStatus('offline');
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const id = setInterval(checkHealth, 15000);
    return () => clearInterval(id);
  }, [checkHealth]);

  const activeTabData = TABS.find(t => t.id === activeTab);

  return (
    <div className="app-container">
      {/* ── Top Header ── */}
      <header className="app-header">
        <div className="header-left">
          <div className="logo-mark">
            <ShieldCheck size={28} strokeWidth={2} />
          </div>
          <div>
            <h1 className="app-title">AEGISNET</h1>
            <p className="app-subtitle">Threat Intelligence & Detection Platform</p>
          </div>
        </div>

        <div className="header-right">
          <div className={`status-badge ${apiStatus}`}>
            {apiStatus === 'online' ? <Wifi size={14} /> : apiStatus === 'offline' ? <WifiOff size={14} /> : <Activity size={14} />}
            <span>{apiStatus === 'online' ? 'Cloud Connected' : apiStatus === 'offline' ? 'Cloud Offline' : 'Connecting…'}</span>
          </div>
          {pipelineStatus.ttp_model && (
            <div className="pipeline-indicator active">
              <Crosshair size={13} />
              <span>TTP Model</span>
            </div>
          )}
          {pipelineStatus.apt_stix && (
            <div className="pipeline-indicator active">
              <Users size={13} />
              <span>APT STIX</span>
            </div>
          )}
          <button className="refresh-btn" onClick={checkHealth} title="Refresh status">
            <RefreshCw size={16} />
          </button>
        </div>
      </header>

      {/* ── Navigation ── */}
      <nav className="tab-nav">
        {TABS.map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              id={`tab-${tab.id}`}
              className={`tab-btn ${isActive ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
              style={isActive ? { '--tab-color': tab.color } : {}}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
              {isActive && <div className="tab-indicator" />}
            </button>
          );
        })}
      </nav>

      {/* ── Content ── */}
      <main className="main-content">
        {activeTab === 'overview'  && <ThreatOverview api={API} />}
        {activeTab === 'pipeline'  && <DetectionPipeline api={API} />}
        {activeTab === 'ttp'       && <TTPAnalysis api={API} />}
        {activeTab === 'apt'       && <APTIntelligence api={API} />}
        {activeTab === 'ja4'       && <RawData api={API} view="ja4" />}
        {activeTab === 'control'   && <ControlPlaneTab api={API} />}
        {activeTab === 'audit'     && <AuditTrailTab api={API} />}
        {activeTab === 'data'      && <RawData api={API} view="flows" />}
      </main>
    </div>
  );
}
