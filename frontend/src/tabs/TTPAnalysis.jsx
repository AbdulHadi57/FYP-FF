import { useState, useMemo, useEffect } from 'react';
import axios from 'axios';
import {
  Crosshair,
  TrendingUp,
  AlertTriangle,
  BarChart3,
  Layers,
  Search,
  ArrowRight,
  TimerReset,
  Target,
  ShieldCheck,
  Activity,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts';

const asText = (value) => String(value ?? '');
const asLower = (value) => asText(value).toLowerCase();

export default function TTPAnalysis({
  api,
  onPivot,
  globalSearch = '',
  timeRangeSeconds = 21600,
  autoRefreshSeconds = 15,
}) {
  const [data, setData] = useState(null);
  const [openEvents, setOpenEvents] = useState([]);
  const [fallbackNotice, setFallbackNotice] = useState('');
  const [loading, setLoading] = useState(true);

  const ttpLimit = useMemo(() => {
    return Math.max(250, Math.min(2000, Math.round(timeRangeSeconds / 25)));
  }, [timeRangeSeconds]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, eventsRes] = await Promise.all([
          axios.get(`${api}/api/ttp-stats?limit=${ttpLimit}`),
          axios.get(`${api}/api/events?status=open&module=ttp&limit=80&min_confidence=0.2`).catch(() => ({ data: [] })),
        ]);
        let ttpPayload = statsRes.data || {};
        setFallbackNotice('');

        if (Number(ttpPayload.total_predictions || 0) === 0) {
          try {
            const modulesRes = await axios.get(`${api}/api/modules?limit=${Math.max(ttpLimit, 1200)}`);
            const topTechniques = Array.isArray(modulesRes?.data?.ttp_top_techniques)
              ? modulesRes.data.ttp_top_techniques
              : [];
            const recentFlowsFromModules = Array.isArray(modulesRes?.data?.ttp_recent_flows)
              ? modulesRes.data.ttp_recent_flows
              : [];

            if (topTechniques.length > 0 || recentFlowsFromModules.length > 0) {
              ttpPayload = {
                ...ttpPayload,
                total_predictions: Number(modulesRes?.data?.ttp_total_predictions || 0),
                unique_techniques: topTechniques.length,
                technique_distribution: topTechniques,
                recent_ttp_flows: recentFlowsFromModules,
                model_loaded: ttpPayload.model_loaded,
              };
              setFallbackNotice('Loaded extended TTP history');
            }
          } catch {
            // Keep default payload when module fallback fails.
          }
        }

        setData(ttpPayload);
        setOpenEvents(eventsRes.data || []);
      } catch (err) {
        console.error('TTP stats error:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();

    if (!autoRefreshSeconds || autoRefreshSeconds <= 0) {
      return undefined;
    }

    const id = setInterval(fetchData, autoRefreshSeconds * 1000);
    return () => clearInterval(id);
  }, [api, autoRefreshSeconds, ttpLimit]);

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  const techniques = useMemo(
    () => (data?.technique_distribution || []).map((technique, index) => ({
      id: asText(technique?.id || `T000${index}`),
      name: asText(technique?.name || 'Unknown Technique'),
      count: Number(technique?.count || 0),
      pct: Number(technique?.pct || 0),
    })),
    [data],
  );

  const recentFlows = useMemo(
    () => (data?.recent_ttp_flows || []).map((flow) => ({
      flow_id: flow?.flow_id,
      src_ip: asText(flow?.src_ip || 'unknown'),
      dst_ip: asText(flow?.dst_ip || 'unknown'),
      captured_at: asText(flow?.captured_at || '-'),
      techniques: Array.isArray(flow?.techniques)
        ? flow.techniques.filter((technique) => technique != null).map((technique) => asText(technique))
        : [],
    })),
    [data],
  );

  const modelLoaded = data?.model_loaded || false;
  const normalizedSearch = asLower(globalSearch).trim();

  const filteredTechniques = normalizedSearch
    ? techniques.filter(
      (technique) =>
        asLower(technique.id).includes(normalizedSearch)
        || asLower(technique.name).includes(normalizedSearch),
    )
    : techniques;

  const filteredRecentFlows = normalizedSearch
    ? recentFlows.filter((flow) => {
      const techniqueList = (flow.techniques || []).join(' ').toLowerCase();
      return asText(flow.flow_id).includes(normalizedSearch)
        || asLower(flow.src_ip).includes(normalizedSearch)
        || asLower(flow.dst_ip).includes(normalizedSearch)
        || techniqueList.includes(normalizedSearch);
    })
    : recentFlows;

  const displayTechniques = normalizedSearch && filteredTechniques.length === 0 && techniques.length > 0
    ? techniques
    : filteredTechniques;

  const displayRecentFlows = normalizedSearch && filteredRecentFlows.length === 0 && recentFlows.length > 0
    ? recentFlows
    : filteredRecentFlows;

  const searchFallbackActive = Boolean(
    normalizedSearch
    && (displayTechniques !== filteredTechniques || displayRecentFlows !== filteredRecentFlows),
  );

  const topTechnique = displayTechniques[0];
  const topTechniqueShare = topTechnique?.pct || 0;

  const hotspotTechniques = useMemo(() => {
    const counter = {};
    const matcher = /(T\d{4}(?:\.\d{3})?)/g;

    openEvents.forEach((event) => {
      const text = `${event.title || ''} ${event.message || ''}`;
      const matches = text.match(matcher) || [];
      matches.forEach((technique) => {
        counter[technique] = (counter[technique] || 0) + 1;
      });
    });

    return Object.entries(counter)
      .map(([id, count]) => ({ id, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [openEvents]);

  const getHeatColor = (pct) => {
    if (pct > 20) return '#ef4444';
    if (pct > 10) return '#f97316';
    if (pct > 5) return '#eab308';
    return '#3b82f6';
  };

  const barColors = ['#ef4444', '#f97316', '#eab308', '#22d3ee', '#3b82f6', '#a78bfa', '#10b981'];
  const shownFlows = displayRecentFlows.slice(0, 12);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Target size={16} style={{ color: '#00e0ff' }} />
            MITRE ATT&CK Correlation Workspace
          </div>
          <div className="card-subtitle" style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
            <TimerReset size={12} />
            Window: {Math.round(timeRangeSeconds / 60)}m
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
          <div style={{ color: '#a9b7cb', fontSize: 13 }}>
            Technique trends are aggregated for analyst triage and immediate handoff to attribution and containment.
          </div>
          <div style={{ display: 'inline-flex', gap: 6, flexWrap: 'wrap' }}>
            <span className={modelLoaded ? 'badge badge-success' : 'badge badge-danger'}>
              Model {modelLoaded ? 'Active' : 'Offline'}
            </span>
            {fallbackNotice && <span className="badge badge-info">{fallbackNotice}</span>}
            {searchFallbackActive && <span className="badge badge-warning">Search kept context-wide</span>}
          </div>
        </div>
      </div>

      <div className="grid-4">
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(249,115,22,0.12)', color: '#f97316' }}>
            <Crosshair size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#f97316' }}>{data?.total_predictions || 0}</div>
            <div className="kpi-label">Mapped Flows</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>
            <Layers size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ef4444' }}>{displayTechniques.length}</div>
            <div className="kpi-label">Visible Techniques</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(16,185,129,0.12)', color: '#10b981' }}>
            <TrendingUp size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#10b981', fontSize: 20 }}>{topTechnique?.id || 'N/A'}</div>
            <div className="kpi-label">Top Technique ({topTechniqueShare}%)</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div
            className="kpi-icon"
            style={{ background: modelLoaded ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.12)', color: modelLoaded ? '#10b981' : '#ef4444' }}
          >
            <BarChart3 size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: modelLoaded ? '#10b981' : '#ef4444', fontSize: 18 }}>{modelLoaded ? 'Active' : 'Offline'}</div>
            <div className="kpi-label">TTP Model Status</div>
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <BarChart3 size={16} style={{ color: '#f97316' }} />
              MITRE ATT&CK Distribution
            </div>
          </div>
          {displayTechniques.length > 0 ? (
            <ResponsiveContainer width="100%" height={350}>
              <BarChart data={displayTechniques.slice(0, 12)} layout="vertical" margin={{ left: 80, right: 20, top: 5, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" horizontal={false} />
                <XAxis type="number" stroke="#666" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis dataKey="id" type="category" stroke="#666" tick={{ fill: '#94a3b8', fontSize: 11 }} width={75} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #333', color: '#fff', borderRadius: 8 }}
                  formatter={(value, _name, props) => [`${value} flows (${props.payload.pct}%)`, props.payload.name]}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={18}>
                  {displayTechniques.slice(0, 12).map((entry, index) => (
                    <Cell key={entry.id} fill={barColors[index % barColors.length]} fillOpacity={0.8} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">
              <Crosshair size={40} />
              <p>No TTP predictions yet. Malicious flows will be analyzed for MITRE techniques.</p>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Layers size={16} style={{ color: '#ef4444' }} />
              Technique Hotspot Grid
            </div>
            <span className="card-subtitle">{displayTechniques.length} techniques detected</span>
          </div>

          {displayTechniques.length > 0 ? (
            <>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12 }}>
                {displayTechniques.map((technique) => (
                  <button
                    key={technique.id}
                    className="heatmap-cell"
                    style={{
                      background: `${getHeatColor(technique.pct)}20`,
                      color: getHeatColor(technique.pct),
                      border: `1px solid ${getHeatColor(technique.pct)}40`,
                    }}
                    title={`${technique.name} - ${technique.count} flows (${technique.pct}%)`}
                    onClick={() => onPivot?.({ targetTab: 'explorer', search: technique.id })}
                  >
                    {technique.id}
                  </button>
                ))}
              </div>

              <div style={{ borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: 10 }}>
                <div
                  style={{
                    fontSize: 12,
                    color: '#90a0b8',
                    marginBottom: 8,
                    fontWeight: 600,
                    display: 'inline-flex',
                    gap: 6,
                    alignItems: 'center',
                  }}
                >
                  <Target size={12} />
                  Incident Hotspots
                </div>
                {hotspotTechniques.length > 0 ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {hotspotTechniques.map((hotspot) => (
                      <button
                        key={hotspot.id}
                        className="badge badge-danger"
                        style={{ border: 'none', cursor: 'pointer' }}
                        onClick={() => onPivot?.({ targetTab: 'detection', search: hotspot.id })}
                      >
                        {hotspot.id} ({hotspot.count})
                      </button>
                    ))}
                  </div>
                ) : (
                  <span className="badge badge-info">No hotspot tags extracted</span>
                )}
              </div>

              <div style={{ borderTop: '1px solid rgba(255,255,255,0.08)', marginTop: 12, paddingTop: 12 }}>
                <div className="card-subtitle" style={{ marginBottom: 8 }}>Top search pivots</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {displayTechniques.slice(0, 6).map((technique) => (
                    <button
                      key={`pivot-${technique.id}`}
                      className="badge badge-cyan"
                      style={{ border: 'none', cursor: 'pointer' }}
                      onClick={() => onPivot?.({ targetTab: 'explorer', search: technique.id })}
                    >
                      {technique.id} ({technique.count})
                    </button>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="empty-state">
              <AlertTriangle size={40} />
              <p>Awaiting malicious flow data for technique heatmap.</p>
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Crosshair size={16} style={{ color: '#22d3ee' }} />
            Predicted Flow Chains
          </div>
          <span className="badge badge-orange">{shownFlows.length} flows</span>
        </div>

        {shownFlows.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 10 }}>
            {shownFlows.map((flow) => (
              <div key={`flow-${flow.flow_id}-${flow.src_ip}`} className="insight-card" style={{ borderColor: 'rgba(255,255,255,0.1)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
                  <span className="mono" style={{ color: '#00e0ff', fontWeight: 700 }}>#{flow.flow_id}</span>
                  <span className="badge badge-info">{flow.techniques.length} techniques</span>
                </div>

                <div className="mono" style={{ color: '#d4e0f4', marginBottom: 4 }}>{flow.src_ip}</div>
                <div className="mono" style={{ color: '#8ea2be', marginBottom: 8 }}>{flow.dst_ip}</div>
                <div className="card-subtitle" style={{ marginBottom: 8 }}>{flow.captured_at}</div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 10 }}>
                  {flow.techniques.slice(0, 5).map((techniqueId) => (
                    <span key={`${flow.flow_id}-${techniqueId}`} className="badge badge-orange">{techniqueId}</span>
                  ))}
                  {flow.techniques.length > 5 && <span className="badge badge-info">+{flow.techniques.length - 5}</span>}
                </div>

                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-outline btn-sm"
                    onClick={() => onPivot?.({ targetTab: 'explorer', flowId: flow.flow_id, search: flow.src_ip })}
                  >
                    <Search size={12} /> Inspect
                  </button>
                  <button
                    className="btn btn-danger btn-sm"
                    onClick={() => onPivot?.({ targetTab: 'apt', search: flow.src_ip, sourceIp: flow.src_ip })}
                  >
                    Attribute <ArrowRight size={11} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <ShieldCheck size={40} />
            <p>No TTP predictions recorded for the selected scope.</p>
          </div>
        )}

        <div style={{ borderTop: '1px solid rgba(255,255,255,0.08)', marginTop: 12, paddingTop: 10 }}>
          <span className="badge badge-cyan" style={{ marginRight: 6 }}>{openEvents.length} open TTP incidents</span>
          <span className="badge badge-orange">{displayRecentFlows.length} scoped predictions</span>
          <span className="badge badge-info" style={{ marginLeft: 6 }}><Activity size={10} /> Counter-first view</span>
        </div>
      </div>
    </div>
  );
}
