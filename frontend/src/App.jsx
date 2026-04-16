import { useState, useEffect, useMemo, useCallback } from 'react';
import axios from 'axios';
import {
  Shield,
  LayoutDashboard,
  Database,
  Crosshair,
  Users,
  SlidersHorizontal,
  FileText,
  Siren,
  Activity,
  Network,
  Wifi,
  WifiOff,
  RefreshCw,
} from 'lucide-react';

import ThreatOverview from './tabs/ThreatOverview';
import InvestigatorTab from './tabs/InvestigatorTab';
import ControlPlaneTab from './tabs/ControlPlaneTab';
import AuditTrailTab from './tabs/AuditTrailTab';
import BehavioralAnalyticsTab from './tabs/BehavioralAnalyticsTab';
import TtpMitreTab from './tabs/TtpMitreTab';
import AnomalyTrafficTab from './tabs/AnomalyTrafficTab';
import TrafficTypeTab from './tabs/TrafficTypeTab';

const API = import.meta.env.VITE_API_URL || '';
const CONTROL_KEY = import.meta.env.VITE_CONTROL_API_KEY || (typeof window !== 'undefined' ? window.localStorage.getItem('AEGIS_CONTROL_API_KEY') || '' : '');

if (CONTROL_KEY) {
  axios.defaults.headers.common['X-Control-Key'] = CONTROL_KEY;
}

const TABS = [
  { id: 'overview', label: 'Command Center', icon: LayoutDashboard },
  { id: 'behavioral', label: 'Behavioral Engines', icon: Activity },
  { id: 'anomaly', label: 'Anomaly Canvas', icon: Siren },
  { id: 'traffic-type', label: 'Traffic Types', icon: Network },
  { id: 'ttp', label: 'MITRE ATT&CK', icon: Users }, // Using Users icon since lucide-react doesn't have Target imported easily without another replace
  { id: 'investigator', label: 'Investigator', icon: Database },
  { id: 'control', label: 'Active Defense', icon: SlidersHorizontal },
  { id: 'audit', label: 'System Audit', icon: FileText },
];

const TIME_RANGES = [
  { value: '30m', label: 'Pulse 30m', seconds: 1800 },
  { value: '1h', label: 'Pulse 1h', seconds: 3600 },
  { value: '6h', label: 'Shift 6h', seconds: 21600 },
  { value: '24h', label: 'Day 24h', seconds: 86400 },
];

const REFRESH_OPTIONS = [
  { value: 0, label: 'On-demand' },
  { value: 5, label: '5s' },
  { value: 10, label: '10s' },
  { value: 20, label: '20s' },
  { value: 30, label: '30s' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [apiStatus, setApiStatus] = useState('connecting');
  const [pipelineStatus, setPipelineStatus] = useState({});
  const [selectedFlowId, setSelectedFlowId] = useState(null);
  const [timeRange, setTimeRange] = useState('6h');
  const [refreshSeconds, setRefreshSeconds] = useState(10);
  const [globalSearch, setGlobalSearch] = useState('');
  const [pivot, setPivot] = useState(null);

  const checkHealth = useCallback(async () => {
    try {
      const statsRes = await axios.get(`${API}/api/stats`, { timeout: 4000 });
      const ts = statsRes?.data?.last_flow_timestamp;

      if (ts) {
        const lastSeen = new Date(ts).getTime();
        setApiStatus(Date.now() - lastSeen < 15000 ? 'online' : 'offline');
      } else {
        setApiStatus('online');
      }

      const healthRes = await axios.get(`${API}/api/health`, { timeout: 4000 });
      setPipelineStatus(healthRes?.data?.pipeline || {});
    } catch {
      setApiStatus('offline');
      setPipelineStatus({});
    }
  }, []);

  const timeRangeSeconds = useMemo(
    () => TIME_RANGES.find((r) => r.value === timeRange)?.seconds ?? 21600,
    [timeRange],
  );

  const handlePivot = useCallback((payload = {}) => {
    setPivot({ ...payload, ts: Date.now() });

    if (payload.search) {
      setGlobalSearch(String(payload.search));
    }
    if (payload.targetTab) {
      setActiveTab(payload.targetTab);
    }
    if (payload.flowId) {
      setSelectedFlowId(payload.flowId);
    }
  }, []);

  useEffect(() => {
    checkHealth();
    if (refreshSeconds <= 0) {
      return undefined;
    }

    const id = setInterval(checkHealth, refreshSeconds * 1000);
    return () => clearInterval(id);
  }, [checkHealth, refreshSeconds]);

  const sharedProps = {
    api: API,
    onPivot: handlePivot,
    pivot,
    globalSearch,
    setGlobalSearch,
    timeRangeSeconds,
    autoRefreshSeconds: refreshSeconds,
  };

  return (
    <div className="app-shell min-h-screen bg-background text-gray-300 font-sans selection:bg-primary selection:text-black">
      <header className="bg-black/30 backdrop-blur-md border-b border-white/10 sticky top-0 z-50 transition-all duration-300">
        <div className="shell-frame p-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-4 self-start md:self-auto">
            <div className={`z-10 relative transition-all duration-500`}>
              <Shield className={`w-11 h-11 transition-colors duration-500 text-cyan-400`} style={{ filter: 'drop-shadow(0 0 10px rgba(0,224,255,0.8))' }} />
            </div>
            <h1
              className={`text-[2rem] md:text-[2.1rem] font-bold tracking-wider transition-all duration-500 bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 via-blue-400 to-cyan-400`}
              style={{ textShadow: '0 0 15px rgba(0,224,255,0.7), 0 0 25px rgba(0,224,255,0.5)', fontFamily: "'Orbitron', sans-serif" }}
            >
              AEGISNET
            </h1>
          </div>

          <nav className="flex items-center gap-2 flex-wrap self-end md:self-auto overflow-x-auto">
            {TABS.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`
                    flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-all duration-300 whitespace-nowrap border
                    ${isActive
                      ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.2)]'
                      : 'bg-transparent text-gray-400 border-transparent hover:bg-white/5 hover:text-gray-200 hover:border-white/10'
                    }
                  `}
                >
                  <Icon size={16} className={isActive ? 'animate-pulse' : ''} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      <main className="shell-frame py-8">
        {activeTab === 'overview'  && (
          <ThreatOverview
            {...sharedProps}
            apiStatus={apiStatus}
            pipelineStatus={pipelineStatus}
          />
        )}
        {activeTab === 'behavioral'  && <BehavioralAnalyticsTab />}
        {activeTab === 'anomaly'     && (
          <AnomalyTrafficTab
            api={API}
            autoRefreshSeconds={refreshSeconds}
            timeRangeSeconds={timeRangeSeconds}
          />
        )}
        {activeTab === 'traffic-type' && (
          <TrafficTypeTab
            api={API}
            autoRefreshSeconds={refreshSeconds}
          />
        )}
        {activeTab === 'ttp'         && <TtpMitreTab />}
        {activeTab === 'investigator'  && (
          <InvestigatorTab
            api={API}
            selectedFlowId={selectedFlowId ?? (pivot?.targetTab === 'investigator' ? pivot?.flowId : undefined)}
            globalSearch={globalSearch}
            onPivot={handlePivot}
            autoRefreshSeconds={refreshSeconds}
            pipelineStatus={pipelineStatus}
          />
        )}
        {activeTab === 'control'   && <ControlPlaneTab api={API} globalSearch={globalSearch} autoRefreshSeconds={refreshSeconds} />}
        {activeTab === 'audit'     && <AuditTrailTab api={API} globalSearch={globalSearch} autoRefreshSeconds={refreshSeconds} />}
      </main>
    </div>
  );
}
