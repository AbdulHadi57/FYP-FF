import { useState, useEffect } from 'react';
import axios from 'axios';
import { Users, Shield, Target, Globe, Clock, ChevronDown, ChevronUp, AlertTriangle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, RadarChart, PolarGrid, PolarAngleAxis, Radar } from 'recharts';

const WINDOW_OPTIONS = [
  { value: 900, label: '15 min' },
  { value: 3600, label: '1 hour' },
  { value: 21600, label: '6 hours' },
  { value: 86400, label: '24 hours' },
  { value: 604800, label: '7 days' },
];

export default function APTIntelligence({ api }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [window, setWindow] = useState(3600);
  const [expandedActor, setExpandedActor] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await axios.get(`${api}/api/apt-stats?window=${window}&top_n=5`);
        setData(res.data);
      } catch (err) {
        console.error('APT stats error:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
    const id = setInterval(fetchData, 30000);
    return () => clearInterval(id);
  }, [api, window]);

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  const topGroups = data?.top_apt_groups || [];
  const actors = data?.actor_profiles || [];
  const stix = data?.stix_stats || {};

  const getScoreColor = (score) => {
    if (score >= 0.7) return '#ef4444';
    if (score >= 0.45) return '#f97316';
    if (score >= 0.2) return '#eab308';
    return '#3b82f6';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header row with controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="section-title" style={{ margin: 0 }}>
          <Users size={20} style={{ color: '#ef4444' }} />
          APT Group Attribution
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <Clock size={14} style={{ color: 'var(--text-muted)' }} />
          <select className="form-select" value={window} onChange={e => { setWindow(Number(e.target.value)); setLoading(true); }}>
            {WINDOW_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* KPIs */}
      <div className="grid-4">
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>
            <Target size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ef4444' }}>{data?.actor_count || 0}</div>
            <div className="kpi-label">Active Threat Actors</div>
          </div>
        </div>
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(167,139,250,0.12)', color: '#a78bfa' }}>
            <Users size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#a78bfa' }}>{topGroups.length}</div>
            <div className="kpi-label">Matched APT Groups</div>
          </div>
        </div>
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(16,185,129,0.12)', color: '#10b981' }}>
            <Globe size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#10b981' }}>{stix.apt_groups || 0}</div>
            <div className="kpi-label">STIX APT Groups</div>
          </div>
        </div>
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(59,130,246,0.12)', color: '#3b82f6' }}>
            <Shield size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#3b82f6' }}>{stix.total_techniques || 0}</div>
            <div className="kpi-label">Known Techniques</div>
          </div>
        </div>
      </div>

      <div className="grid-2">
        {/* Top APT Groups Bar Chart */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Users size={16} style={{ color: '#ef4444' }} />
              Top Attributed APT Groups
            </div>
          </div>
          {topGroups.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={topGroups.slice(0, 10)} layout="vertical" margin={{ left: 90, right: 20, top: 5, bottom: 5 }}>
                <XAxis type="number" domain={[0, 1]} tick={{ fill: '#64748b', fontSize: 11 }} />
                <YAxis dataKey="apt_name" type="category" tick={{ fill: '#94a3b8', fontSize: 12 }} width={85} />
                <Tooltip
                  contentStyle={{ background: '#141820', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6 }}
                  formatter={(value) => [value.toFixed(4), 'Avg Score']}
                />
                <Bar dataKey="avg_score" radius={[0, 4, 4, 0]} maxBarSize={16}>
                  {topGroups.slice(0, 10).map((entry, index) => (
                    <Cell key={entry.apt_name} fill={getScoreColor(entry.avg_score)} fillOpacity={0.8} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">
              <Users size={40} />
              <p>No APT attributions yet. Malicious flows with TTP predictions are needed.</p>
            </div>
          )}
        </div>

        {/* STIX Matrix Health */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Globe size={16} style={{ color: '#10b981' }} />
              MITRE ATT&CK STIX Matrix
            </div>
            <span className={`badge ${stix.loaded ? 'badge-success' : 'badge-danger'}`}>
              {stix.loaded ? 'Loaded' : 'Not Loaded'}
            </span>
          </div>
          {stix.loaded && stix.top_groups ? (
            <div>
              <div style={{ marginBottom: 16 }}>
                <div className="stat-line">
                  <span className="stat-label">Total APT Groups</span>
                  <span className="stat-value" style={{ color: '#10b981' }}>{stix.apt_groups}</span>
                </div>
                <div className="stat-line">
                  <span className="stat-label">Total Techniques</span>
                  <span className="stat-value" style={{ color: '#3b82f6' }}>{stix.total_techniques}</span>
                </div>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600 }}>Top Groups by TTP Coverage</div>
              <div style={{ maxHeight: 200, overflowY: 'auto' }}>
                {stix.top_groups.slice(0, 10).map((g, i) => (
                  <div key={g.name} className="stat-line">
                    <span className="stat-label" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <span style={{ color: 'var(--text-muted)', fontSize: 11, width: 20 }}>#{i+1}</span>
                      {g.name}
                    </span>
                    <span className="badge badge-info">{g.technique_count} TTPs</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="empty-state">
              <Globe size={40} />
              <p>STIX matrix not loaded. The system will download it automatically on first attribution.</p>
            </div>
          )}
        </div>
      </div>

      {/* Actor Profiles */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Target size={16} style={{ color: '#f97316' }} />
            Threat Actor Profiles
          </div>
          <span className="badge badge-danger">{actors.length} actors</span>
        </div>
        {actors.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {actors.map(actor => (
              <div key={actor.actor_id} style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', overflow: 'hidden' }}>
                <button
                  onClick={() => setExpandedActor(expandedActor === actor.actor_id ? null : actor.actor_id)}
                  style={{
                    width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '12px 16px', background: 'var(--bg-elevated)', border: 'none', cursor: 'pointer',
                    color: 'var(--text-primary)', fontFamily: 'inherit',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                    <span className="mono" style={{ color: 'var(--cyan)', fontWeight: 600 }}>{actor.actor_id}</span>
                    <span className="badge badge-orange">{actor.ttp_count} TTPs</span>
                    <span className="badge badge-info">{actor.flow_count} flows</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Best match:</span>
                      <span style={{ fontWeight: 700, color: getScoreColor(actor.top_score) }}>{actor.top_match}</span>
                      <span style={{ fontSize: 12, color: getScoreColor(actor.top_score) }}>({(actor.top_score * 100).toFixed(1)}%)</span>
                    </div>
                    {expandedActor === actor.actor_id ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                  </div>
                </button>
                {expandedActor === actor.actor_id && (
                  <div style={{ padding: 16, background: 'var(--bg-card)' }}>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600 }}>Observed TTPs</div>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 16 }}>
                      {(actor.ttps || []).map(t => (
                        <span key={t} className="badge badge-orange">{t}</span>
                      ))}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>
                      Window: {WINDOW_OPTIONS.find(w => w.value === data?.window_seconds)?.label || `${data?.window_seconds}s`}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <AlertTriangle size={40} />
            <p>No threat actors detected in the current time window. Adjust the window or wait for malicious traffic.</p>
          </div>
        )}
      </div>
    </div>
  );
}
