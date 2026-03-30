import { useState, useMemo, useEffect } from 'react';
import axios from 'axios';
import {
  Workflow,
  Fingerprint,
  Crosshair,
  Users,
  CheckCircle2,
  AlertTriangle,
  Search,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  TimerReset,
  Flame,
  Target,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

export default function DetectionPipeline({
  api,
  onPivot,
  timeRangeSeconds = 21600,
  autoRefreshSeconds = 15,
}) {
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [moduleStats, setModuleStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  const eventLimit = useMemo(() => {
    const minutes = Math.round(timeRangeSeconds / 60);
    return Math.max(20, Math.min(150, Math.round(minutes / 2)));
  }, [timeRangeSeconds]);

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [healthRes, statsRes, modulesRes, eventsRes] = await Promise.all([
          axios.get(`${api}/api/health`),
          axios.get(`${api}/api/stats`),
          axios.get(`${api}/api/modules?limit=200`),
          axios.get(`${api}/api/events?status=open&limit=${eventLimit}&min_confidence=0.2`).catch(() => ({ data: [] })),
        ]);
        setHealth(healthRes.data);
        setStats(statsRes.data);
        setModuleStats(modulesRes.data);
        setEvents(eventsRes.data || []);
      } catch (err) {
        console.error('Pipeline fetch error:', err);
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
  }, [api, autoRefreshSeconds, eventLimit]);

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  const pipeline = health?.pipeline || {};
  const activity = moduleStats?.module_activity || {};
  const totalFlows = stats?.total_flows || 0;

  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const triageQueue = [...events]
    .sort((a, b) => {
      const sevDiff = (severityOrder[b.severity] ?? -1) - (severityOrder[a.severity] ?? -1);
      if (sevDiff !== 0) return sevDiff;
      return (b.confidence || 0) - (a.confidence || 0);
    })
    .slice(0, 14);

  const escalatedCount = events.filter((event) => ['critical', 'high'].includes(event.severity)).length;
  const avgConfidence = events.length
    ? events.reduce((acc, event) => acc + (event.confidence || 0), 0) / events.length
    : 0;

  const stageCards = [
    {
      id: 'ja4',
      label: 'Stage 1: JA4 Detection',
      icon: Fingerprint,
      ready: Boolean(pipeline.ja4_model),
      input: totalFlows,
      output: activity.ja4 || 0,
      accent: '#00e0ff',
      detail: 'Flow fingerprinting and first-pass malicious classification',
      actionLabel: 'Inspect flow evidence',
      action: () => onPivot?.({ targetTab: 'explorer' }),
    },
    {
      id: 'ttp',
      label: 'Stage 2: TTP Mapping',
      icon: Crosshair,
      ready: Boolean(pipeline.ttp_model),
      input: activity.ja4 || 0,
      output: moduleStats?.ttp_total_predictions || 0,
      accent: '#ff9a3d',
      detail: 'MITRE ATT&CK technique prediction on suspicious traffic',
      actionLabel: 'Open TTP intelligence',
      action: () => onPivot?.({ targetTab: 'ttp' }),
    },
    {
      id: 'apt',
      label: 'Stage 3: APT Attribution',
      icon: Users,
      ready: Boolean(pipeline.apt_stix),
      input: moduleStats?.ttp_total_predictions || 0,
      output: activity.apt || 0,
      accent: '#9f8fff',
      detail: 'Campaign-level actor matching against STIX corpus',
      actionLabel: 'View actor attribution',
      action: () => onPivot?.({ targetTab: 'apt' }),
    },
    {
      id: 'response',
      label: 'Stage 4: Response Handoff',
      icon: ShieldCheck,
      ready: true,
      input: activity.apt || 0,
      output: escalatedCount,
      accent: '#20c997',
      detail: 'Escalated queue sent to policy and containment actions',
      actionLabel: 'Open response control',
      action: () => onPivot?.({ targetTab: 'control' }),
    },
  ];

  const stageYield = (input, output) => {
    if (!input) return 0;
    return Number(((output / input) * 100).toFixed(1));
  };

  const severityClass = (severity) => {
    if (severity === 'critical') return 'badge badge-danger';
    if (severity === 'high') return 'badge badge-orange';
    if (severity === 'medium') return 'badge badge-warning';
    return 'badge badge-info';
  };

  const severityCounters = events.reduce((acc, event) => {
    const key = String(event.severity || 'low').toLowerCase();
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  const severityData = [
    { label: 'Critical', value: severityCounters.critical || 0, color: '#ff4b5c' },
    { label: 'High', value: severityCounters.high || 0, color: '#ff9a3d' },
    { label: 'Medium', value: severityCounters.medium || 0, color: '#f0c24d' },
    { label: 'Low', value: (severityCounters.low || 0) + (severityCounters.info || 0), color: '#54a6ff' },
  ];

  const stageOutputData = stageCards.map((stage) => ({
    label: stage.label.replace('Stage ', 'S').replace(':', ''),
    value: stage.output,
    color: stage.accent,
  }));

  const priorityIncidents = triageQueue.slice(0, 4);
  const topAttackers = (stats?.top_attackers || []).slice(0, 5);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="card" style={{ overflow: 'hidden' }}>
        <div className="card-header">
          <div className="card-title">
            <Workflow size={16} style={{ color: '#9f8fff' }} />
            Detection Operations Board
          </div>
          <div className="card-subtitle" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <TimerReset size={12} />
            Window: {Math.round(timeRangeSeconds / 60)}m
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
          <div style={{ color: '#a7b4c8', fontSize: 13 }}>
            Baseline anomaly filtering runs in the background and feeds this operational queue.
          </div>
          <span className="badge badge-info">Prefilter Active</span>
        </div>
      </div>

      <div className="grid-4">
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(255,75,92,0.12)', color: '#ff4b5c' }}>
            <ShieldAlert size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ff4b5c' }}>{events.length}</div>
            <div className="kpi-label">Queue Depth</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(255,154,61,0.12)', color: '#ff9a3d' }}>
            <AlertTriangle size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ff9a3d' }}>{escalatedCount}</div>
            <div className="kpi-label">Escalated Incidents</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(0,224,255,0.12)', color: '#00e0ff' }}>
            <Search size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#00e0ff' }}>{avgConfidence.toFixed(2)}</div>
            <div className="kpi-label">Average Confidence</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(159,143,255,0.12)', color: '#9f8fff' }}>
            <Workflow size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#9f8fff' }}>{totalFlows.toLocaleString()}</div>
            <div className="kpi-label">Flows Processed</div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Workflow size={16} style={{ color: '#00e0ff' }} />
            Stage Throughput and Analyst Handoff
          </div>
          <span className="badge badge-cyan">Single-row pipeline view</span>
        </div>

        <div className="stage-rail">
          <div className="stage-grid">
            {stageCards.map((stage) => {
              const StageIcon = stage.icon;
              return (
                <div
                  key={stage.id}
                  className="stage-card"
                  style={{
                    borderColor: stage.ready ? `${stage.accent}6e` : 'rgba(255,255,255,0.14)',
                    background: stage.ready ? `${stage.accent}14` : 'rgba(255,255,255,0.03)',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                      <StageIcon size={17} style={{ color: stage.accent }} />
                      <span style={{ fontSize: 13, fontWeight: 700, color: '#e7edf7' }}>{stage.label}</span>
                    </div>
                    <span className={stage.ready ? 'badge badge-success' : 'badge badge-warning'}>
                      {stage.ready ? <CheckCircle2 size={10} /> : <AlertTriangle size={10} />}
                      {stage.ready ? 'Ready' : 'Limited'}
                    </span>
                  </div>

                  <div style={{ fontSize: 12, color: '#a7b4c8', marginBottom: 12 }}>{stage.detail}</div>

                  <div className="stage-meta">
                    <div className="stat-line"><span className="stat-label">Input</span><span className="stat-value">{stage.input}</span></div>
                    <div className="stat-line"><span className="stat-label">Output</span><span className="stat-value" style={{ color: stage.accent }}>{stage.output}</span></div>
                    <div className="stat-line"><span className="stat-label">Yield</span><span className="badge badge-info">{stageYield(stage.input, stage.output)}%</span></div>
                  </div>

                  <div className="score-bar" style={{ marginBottom: 10 }}>
                    <div
                      className="score-bar-fill"
                      style={{
                        width: `${Math.min(100, Number(stageYield(stage.input, stage.output)) || 0)}%`,
                        background: stage.accent,
                      }}
                    />
                  </div>

                  <button className="btn btn-outline btn-sm" onClick={stage.action}>
                    {stage.actionLabel} <ArrowRight size={12} />
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Flame size={16} style={{ color: '#ff9a3d' }} />
              Escalation Heat and Stage Output
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div style={{ minHeight: 220 }}>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={severityData} margin={{ left: 0, right: 10, top: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                  <XAxis dataKey="label" stroke="#666" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <YAxis width={34} stroke="#666" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #333', color: '#fff', borderRadius: 8 }} />
                  <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                    {severityData.map((row) => (
                      <Cell key={row.label} fill={row.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div style={{ minHeight: 220 }}>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={stageOutputData} margin={{ left: 0, right: 10, top: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                  <XAxis dataKey="label" stroke="#666" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                  <YAxis width={34} stroke="#666" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <Tooltip contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #333', color: '#fff', borderRadius: 8 }} />
                  <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                    {stageOutputData.map((row) => (
                      <Cell key={row.label} fill={row.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Target size={16} style={{ color: '#54a6ff' }} />
              Analyst Jumpboard
            </div>
            <span className="badge badge-danger">{priorityIncidents.length} critical picks</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {priorityIncidents.map((event) => (
              <div key={event.id} className="insight-card" style={{ borderColor: 'rgba(255,255,255,0.1)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginBottom: 8 }}>
                  <span className={severityClass(event.severity)}>{event.severity || 'unknown'}</span>
                  <span className="badge badge-cyan">{event.module_source || 'ja4'}</span>
                </div>
                <div style={{ color: '#d8e3f4', fontWeight: 600, marginBottom: 6 }}>{event.title}</div>
                <div className="mono" style={{ color: '#8fa4bf', marginBottom: 8 }}>{event.source_ip || 'unknown source'}</div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-outline btn-sm"
                    onClick={() => onPivot?.({ targetTab: 'explorer', flowId: event.flow_id, search: event.source_ip })}
                  >
                    Investigate
                  </button>
                  <button
                    className="btn btn-danger btn-sm"
                    onClick={() => onPivot?.({ targetTab: 'control', sourceIp: event.source_ip, search: event.source_ip })}
                  >
                    Contain
                  </button>
                </div>
              </div>
            ))}

            {priorityIncidents.length === 0 && (
              <div className="empty-state" style={{ minHeight: 120 }}>
                <ShieldCheck size={34} />
                <p>No open incidents in the current detection window.</p>
              </div>
            )}

            {topAttackers.length > 0 && (
              <div style={{ borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: 10 }}>
                <div className="card-subtitle" style={{ marginBottom: 8 }}>Highest-frequency suspicious sources</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {topAttackers.map((attacker) => (
                    <button
                      key={attacker.ip}
                      className="badge badge-orange"
                      style={{ border: 'none', cursor: 'pointer' }}
                      onClick={() => onPivot?.({ targetTab: 'explorer', search: attacker.ip })}
                    >
                      {attacker.ip} ({attacker.count})
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
