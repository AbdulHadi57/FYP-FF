import { useState, useMemo, useEffect } from 'react';
import axios from 'axios';
import {
  Activity,
  Monitor,
  Radar,
  Server,
  ShieldAlert,
  TimerReset,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

export default function ThreatOverview({
  api,
  onPivot,
  timeRangeSeconds = 21600,
  autoRefreshSeconds = 15,
  apiStatus = 'connecting',
  pipelineStatus = {},
  lastHealthCheck = null,
}) {
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [moduleStats, setModuleStats] = useState(null);
  const [health, setHealth] = useState(null);
  const [dcs, setDcs] = useState([]);
  const [agents, setAgents] = useState([]);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  const timelineLimit = useMemo(() => {
    const minutes = Math.round(timeRangeSeconds / 60);
    return Math.max(45, Math.min(360, minutes));
  }, [timeRangeSeconds]);

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [
          statsRes,
          timelineRes,
          modulesRes,
          healthRes,
          eventsRes,
          dcsRes,
          agentsRes,
        ] = await Promise.all([
          axios.get(`${api}/api/stats`),
          axios.get(`${api}/api/timeline?limit=${timelineLimit}`),
          axios.get(`${api}/api/modules?limit=600`),
          axios.get(`${api}/api/health`),
          axios.get(`${api}/api/events?status=open&limit=120&min_confidence=0.2`).catch(() => ({ data: [] })),
          axios.get(`${api}/api/control/dcs?limit=200`).catch(() => ({ data: [] })),
          axios.get(`${api}/api/control/agents?limit=500`).catch(() => ({ data: [] })),
        ]);

        setStats(statsRes.data);
        setTimeline(timelineRes.data || []);
        setModuleStats(modulesRes.data);
        setHealth(healthRes.data);
        setEvents(eventsRes.data || []);
        setDcs(dcsRes.data || []);
        setAgents(agentsRes.data || []);
      } catch (err) {
        console.error('Overview fetch error:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchAll();
    if (!autoRefreshSeconds || autoRefreshSeconds <= 0) {
      return undefined;
    }

    const id = setInterval(fetchAll, autoRefreshSeconds * 1000);
    return () => clearInterval(id);
  }, [api, autoRefreshSeconds, timelineLimit]);

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  const totalFlows = stats?.total_flows || 0;
  const maliciousFlows = stats?.malicious_flows || 0;
  const benignFlows = Math.max(totalFlows - maliciousFlows, 0);
  const maliciousPct = totalFlows > 0 ? ((maliciousFlows / totalFlows) * 100).toFixed(1) : '0.0';

  const agentsOnline = agents.filter((agent) => agent.status === 'online').length;
  const dcsApproved = dcs.filter((dc) => dc.approval_status === 'approved').length;

  const threatStatus = moduleStats?.threat_status_distribution || {};
  const openIncidents = Math.max(events.length, Number(threatStatus.open || 0));
  const resolvedIncidents = Number(threatStatus.resolved || 0);
  const moduleActivity = moduleStats?.module_activity || {};
  const topAttackers = (stats?.top_attackers || []).slice(0, 4);
  const topAttackerIp = topAttackers[0]?.ip || '';
  const highConfidenceEvents = events.filter((event) => Number(event.confidence || 0) >= 0.75).length;

  const compositionData = totalFlows > 0
    ? [
      { name: 'Malicious', value: maliciousFlows, color: '#ff0055' },
      { name: 'Benign', value: benignFlows, color: '#14d9d1' },
    ]
    : [{ name: 'No Data', value: 1, color: '#5d6f88' }];

  const signalMixData = [
    { name: 'JA4 Hits', value: Number(moduleActivity.ja4 || 0), color: '#00e0ff' },
    { name: 'TTP Mapped', value: Number(moduleActivity.ttp || 0), color: '#ff9a3d' },
    { name: 'APT Attributed', value: Number(moduleActivity.apt || 0), color: '#9f8fff' },
    { name: 'Open Incidents', value: Number(openIncidents || 0), color: '#ff4b5c' },
  ];

  const displaySignalMix = signalMixData.some((entry) => entry.value > 0)
    ? signalMixData
    : [{ name: 'No Signals', value: 1, color: '#5d6f88' }];

  const lastSync = lastHealthCheck ? new Date(lastHealthCheck).toLocaleTimeString() : 'N/A';
  const latestFlow = stats?.last_flow_timestamp ? new Date(stats.last_flow_timestamp).toLocaleString() : 'No flow yet';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Radar size={16} style={{ color: '#00e0ff' }} />
            Mission System Overview
          </div>
          <div className="card-subtitle" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <TimerReset size={12} />
            Last sync: {lastSync}
          </div>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 12 }}>
          <span className={apiStatus === 'online' ? 'badge badge-success' : apiStatus === 'offline' ? 'badge badge-danger' : 'badge badge-warning'}>
            Cloud {apiStatus}
          </span>
          <span className="badge badge-cyan">Last flow: {latestFlow}</span>
          <span className="badge badge-orange">Window: {Math.round(timeRangeSeconds / 60)}m</span>
          {topAttackerIp && <span className="badge badge-danger">Top source: {topAttackerIp}</span>}
        </div>

        <div style={{ color: '#a7b4c8', fontSize: 14, lineHeight: 1.5 }}>
          This overview focuses on real-time platform posture: controller trust, endpoint availability,
          pipeline readiness, and containment pressure, without investigative logs.
        </div>
      </div>

      <div className="grid-4">
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(0,224,255,0.12)', color: '#00e0ff' }}>
            <Monitor size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#00e0ff' }}>{agentsOnline}/{agents.length}</div>
            <div className="kpi-label">Connected Agents (online/total)</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(84,166,255,0.14)', color: '#54a6ff' }}>
            <Server size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#54a6ff' }}>{dcsApproved}/{dcs.length}</div>
            <div className="kpi-label">Trusted Domain Controllers</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(255,75,92,0.14)', color: '#ff4b5c' }}>
            <ShieldAlert size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ff4b5c' }}>{openIncidents}</div>
            <div className="kpi-label">Open Threat Incidents</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(255,154,61,0.14)', color: '#ff9a3d' }}>
            <Activity size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ff9a3d' }}>{maliciousPct}%</div>
            <div className="kpi-label">Malicious Flow Ratio</div>
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Activity size={16} style={{ color: '#54a6ff' }} />
              Traffic Composition
            </div>
          </div>

          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={[{ value: 1 }]}
                cx="50%"
                cy="50%"
                innerRadius={79}
                outerRadius={80}
                dataKey="value"
                stroke="none"
                fill="rgba(255,255,255,0.1)"
                isAnimationActive={false}
              />

              <Pie
                data={compositionData}
                cx="50%"
                cy="50%"
                innerRadius={75}
                outerRadius={85}
                paddingAngle={5}
                cornerRadius={2}
                dataKey="value"
                stroke="none"
              >
                {compositionData.map((entry, index) => (
                  <Cell
                    key={`${entry.name}-${entry.color}`}
                    fill={entry.color}
                    style={{ filter: `drop-shadow(0 0 2px ${index === 0 ? '#ff0055' : '#14d9d1'})` }}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #333', color: '#fff', borderRadius: 8 }}
                formatter={(value, name) => [value, name]}
              />
              <text x="50%" y="50%" dy={8} textAnchor="middle" className="fill-white text-3xl font-mono tracking-widest" style={{ filter: 'drop-shadow(0 0 3px white)' }}>
                {maliciousFlows}
              </text>
              <text x="50%" y="65%" dy={5} textAnchor="middle" className="fill-cyan-400 text-[10px] uppercase tracking-[0.2em] font-mono">
                THREATS
              </text>
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Activity size={16} style={{ color: '#00e0ff' }} />
              Traffic Volume & Spikes
            </div>
          </div>

          {timeline.length > 0 ? (
            <ResponsiveContainer width="100%" height={270}>
              <AreaChart data={timeline} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
                <defs>
                  <linearGradient id="trafficVolumeFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00e0ff" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="#00e0ff" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                <XAxis
                  dataKey="bucket"
                  stroke="#666"
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                  tickFormatter={(value) => value?.split('T')?.[1] || value?.slice(-5) || value}
                />
                <YAxis stroke="#666" tick={{ fill: '#94a3b8', fontSize: 11 }} width={44} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #333', color: '#fff', borderRadius: 8 }}
                />
                <Area type="monotone" dataKey="flow_count" stroke="#00e0ff" fill="url(#trafficVolumeFill)" strokeWidth={2} name="Flows" />
                <Area type="monotone" dataKey="malicious_count" stroke="#ff4b4b" fill="none" strokeWidth={2} name="Malicious" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state"><Activity size={36} /><p>No timeline data available yet.</p></div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Monitor size={16} style={{ color: '#9f8fff' }} />
            Threat Signal Breakdown
          </div>
          <span className="badge badge-info">Realtime counters</span>
        </div>

        <div className="overview-health-grid" style={{ gridTemplateColumns: '1.35fr 1fr' }}>
          <div style={{ minHeight: 240 }}>
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={displaySignalMix} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                <XAxis dataKey="name" stroke="#666" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis stroke="#666" tick={{ fill: '#94a3b8', fontSize: 11 }} width={42} />
                <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #333', color: '#fff', borderRadius: 8 }} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {displaySignalMix.map((entry) => (
                    <Cell key={`${entry.name}-${entry.color}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div className="stat-line"><span className="stat-label">Total flows</span><span className="stat-value">{totalFlows}</span></div>
            <div className="stat-line"><span className="stat-label">Malicious flows</span><span className="stat-value" style={{ color: '#ff4b5c' }}>{maliciousFlows}</span></div>
            <div className="stat-line"><span className="stat-label">Open incidents</span><span className="stat-value" style={{ color: '#ff9a3d' }}>{openIncidents}</span></div>
            <div className="stat-line"><span className="stat-label">Resolved incidents</span><span className="stat-value" style={{ color: '#20c997' }}>{resolvedIncidents}</span></div>
            <div className="stat-line"><span className="stat-label">High-confidence alerts</span><span className="stat-value" style={{ color: '#54a6ff' }}>{highConfidenceEvents}</span></div>
            <div className="stat-line"><span className="stat-label">Top source</span><span className="stat-value mono" style={{ color: '#00e0ff' }}>{topAttackerIp || 'N/A'}</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}
