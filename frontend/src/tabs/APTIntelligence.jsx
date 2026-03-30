import { useState, useMemo, useEffect } from 'react';
import axios from 'axios';
import {
  Users,
  Shield,
  Target,
  Globe,
  Clock,
  AlertTriangle,
  ArrowRight,
  ShieldAlert,
  Radar,
  ShieldCheck,
  Activity,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts';

const WINDOW_OPTIONS = [
  { value: 900, label: '15 min' },
  { value: 3600, label: '1 hour' },
  { value: 21600, label: '6 hours' },
  { value: 86400, label: '24 hours' },
  { value: 604800, label: '7 days' },
  { value: 2592000, label: '30 days' },
  { value: 7776000, label: '90 days' },
  { value: 15552000, label: '180 days' },
  { value: 31536000, label: '1 year' },
];

export default function APTIntelligence({
  api,
  onPivot,
  globalSearch = '',
  timeRangeSeconds = 21600,
  autoRefreshSeconds = 15,
}) {
  const [data, setData] = useState(null);
  const [openEvents, setOpenEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [windowSeconds, setWindowSeconds] = useState(Math.max(timeRangeSeconds, 15552000));
  const [windowPinned, setWindowPinned] = useState(false);
  const [windowHint, setWindowHint] = useState('');

  useEffect(() => {
    if (!windowPinned) {
      setWindowSeconds(Math.max(timeRangeSeconds, 15552000));
    }
  }, [timeRangeSeconds, windowPinned]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [eventsRes] = await Promise.all([
          axios.get(`${api}/api/events?status=open&module=ttp&limit=80&min_confidence=0.2`).catch(() => ({ data: [] })),
        ]);

        const fallbackWindows = [];
        [windowSeconds, 86400, 604800, 2592000, 7776000, 15552000, 31536000].forEach((value) => {
          if (!fallbackWindows.includes(value)) {
            fallbackWindows.push(value);
          }
        });

        let resolvedWindow = windowSeconds;
        let aptPayload = null;

        for (const candidateWindow of fallbackWindows) {
          const aptRes = await axios.get(`${api}/api/apt-stats?window=${candidateWindow}&top_n=8`);
          aptPayload = aptRes.data;
          resolvedWindow = candidateWindow;

          const actorCount = Number(aptRes?.data?.actor_count || 0);
          const topGroupCount = Array.isArray(aptRes?.data?.top_apt_groups) ? aptRes.data.top_apt_groups.length : 0;
          if (actorCount > 0 || topGroupCount > 0 || candidateWindow === fallbackWindows[fallbackWindows.length - 1]) {
            break;
          }
        }

        setData(aptPayload || {});
        if (resolvedWindow !== windowSeconds) {
          const resolvedLabel = WINDOW_OPTIONS.find((option) => option.value === resolvedWindow)?.label || `${resolvedWindow}s`;
          setWindowHint(`Auto-expanded scope to ${resolvedLabel}`);
        } else {
          setWindowHint('');
        }
        setOpenEvents(eventsRes.data || []);
      } catch (err) {
        console.error('APT stats error:', err);
        setWindowHint('');
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
  }, [api, autoRefreshSeconds, windowSeconds]);

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  const topGroups = useMemo(
    () => (data?.top_apt_groups || []).map((group) => ({
      apt_name: String(group?.apt_name || 'Unknown'),
      match_count: Number(group?.match_count || 0),
      avg_score: Number(group?.avg_score || 0),
      max_score: Number(group?.max_score || 0),
    })),
    [data],
  );

  const actors = useMemo(
    () => (data?.actor_profiles || []).map((actor) => ({
      actor_id: String(actor?.actor_id || 'unknown'),
      ttp_count: Number(actor?.ttp_count || 0),
      flow_count: Number(actor?.flow_count || 0),
      top_match: String(actor?.top_match || 'None'),
      top_score: Number(actor?.top_score || 0),
      ttps: Array.isArray(actor?.ttps)
        ? actor.ttps.filter((ttp) => ttp != null).map((ttp) => String(ttp))
        : [],
    })),
    [data],
  );

  const stix = data?.stix_stats || {};
  const normalizedSearch = String(globalSearch || '').trim().toLowerCase();

  const getScoreColor = (score) => {
    if (score >= 0.7) return '#ef4444';
    if (score >= 0.45) return '#f97316';
    if (score >= 0.2) return '#eab308';
    return '#3b82f6';
  };

  const filteredTopGroups = normalizedSearch
    ? topGroups.filter((group) => String(group.apt_name).toLowerCase().includes(normalizedSearch))
    : topGroups;

  const filteredActors = normalizedSearch
    ? actors.filter((actor) => {
      const ttps = (actor.ttps || []).join(' ').toLowerCase();
      return String(actor.actor_id).toLowerCase().includes(normalizedSearch)
        || String(actor.top_match).toLowerCase().includes(normalizedSearch)
        || ttps.includes(normalizedSearch);
    })
    : actors;

  const displayTopGroups = normalizedSearch && filteredTopGroups.length === 0 && topGroups.length > 0
    ? topGroups
    : filteredTopGroups;

  const displayActors = normalizedSearch && filteredActors.length === 0 && actors.length > 0
    ? actors
    : filteredActors;

  const searchFallbackActive = Boolean(
    normalizedSearch
    && displayTopGroups === topGroups
    && displayActors === actors
    && (topGroups.length > 0 || actors.length > 0),
  );

  const aptEscalations = openEvents.filter((event) => {
    if (!event.source_ip) return false;
    return displayActors.some((actor) => actor.actor_id === event.source_ip);
  });

  const topScore = displayTopGroups.length ? Math.max(...displayTopGroups.map((group) => group.max_score || 0)) : 0;
  const topGroup = displayTopGroups[0];

  const selectedWindowLabel = WINDOW_OPTIONS.find((option) => option.value === windowSeconds)?.label || `${windowSeconds}s`;
  const stixTopGroups = Array.isArray(stix.top_groups) ? stix.top_groups.slice(0, 8) : [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Radar size={16} style={{ color: '#9f8fff' }} />
            Actor Attribution Workspace
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <Clock size={14} style={{ color: 'var(--text-muted)' }} />
            <select className="form-select" value={windowSeconds} onChange={(e) => { setWindowPinned(true); setWindowSeconds(Number(e.target.value)); setLoading(true); setWindowHint(''); }}>
              {WINDOW_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </div>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <div style={{ color: '#a5b3c8', fontSize: 13 }}>
            Attribution aggregates observed techniques per source actor and maps them against known APT behavior.
          </div>
          <div style={{ display: 'inline-flex', gap: 6, flexWrap: 'wrap' }}>
            <span className="badge badge-purple">Window: {selectedWindowLabel}</span>
            {windowHint && <span className="badge badge-info">{windowHint}</span>}
            {searchFallbackActive && <span className="badge badge-warning">Search kept context-wide</span>}
          </div>
        </div>
      </div>

      <div className="grid-4">
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>
            <Target size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ef4444' }}>{displayActors.length}</div>
            <div className="kpi-label">Tracked Actors</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(167,139,250,0.12)', color: '#a78bfa' }}>
            <Users size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#a78bfa', fontSize: 20 }}>{topGroup?.apt_name || 'N/A'}</div>
            <div className="kpi-label">Top Attributed Group</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(16,185,129,0.12)', color: '#10b981' }}>
            <Shield size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: getScoreColor(topScore) }}>{(topScore * 100).toFixed(1)}%</div>
            <div className="kpi-label">Peak Match Confidence</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(255,75,92,0.12)', color: '#ff4b5c' }}>
            <ShieldAlert size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ff4b5c' }}>{aptEscalations.length}</div>
            <div className="kpi-label">Linked Open Incidents</div>
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Users size={16} style={{ color: '#ef4444' }} />
              Top Attributed APT Groups
            </div>
          </div>
          {displayTopGroups.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={displayTopGroups.slice(0, 10)} layout="vertical" margin={{ left: 90, right: 20, top: 5, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" horizontal={false} />
                <XAxis type="number" domain={[0, 1]} stroke="#666" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis dataKey="apt_name" type="category" stroke="#666" tick={{ fill: '#94a3b8', fontSize: 12 }} width={85} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #333', color: '#fff', borderRadius: 8 }}
                  formatter={(value) => [Number(value || 0).toFixed(4), 'Average Score']}
                />
                <Bar dataKey="avg_score" radius={[0, 4, 4, 0]} maxBarSize={16}>
                  {displayTopGroups.slice(0, 10).map((entry) => (
                    <Cell key={entry.apt_name} fill={getScoreColor(entry.avg_score)} fillOpacity={0.85} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">
              <Users size={40} />
              <p>No APT group matches in this scope.</p>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Globe size={16} style={{ color: '#10b981' }} />
              STIX Matrix and Corpus Health
            </div>
            <span className={`badge ${stix.loaded ? 'badge-success' : 'badge-danger'}`}>
              {stix.loaded ? 'Loaded' : 'Not Loaded'}
            </span>
          </div>

          {stix.loaded && stix.top_groups ? (
            <div>
              <div style={{ marginBottom: 14 }}>
                <div className="stat-line">
                  <span className="stat-label">Total APT Groups</span>
                  <span className="stat-value" style={{ color: '#10b981' }}>{stix.apt_groups}</span>
                </div>
                <div className="stat-line">
                  <span className="stat-label">Total Techniques</span>
                  <span className="stat-value" style={{ color: '#3b82f6' }}>{stix.total_techniques}</span>
                </div>
              </div>

              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600 }}>Top groups by TTP coverage</div>
              <div style={{ maxHeight: 210, overflowY: 'auto' }}>
                {stixTopGroups.map((group, index) => (
                  <button
                    key={group.name}
                    className="stat-line"
                    style={{ width: '100%', textAlign: 'left', background: 'transparent', borderLeft: 'none', borderRight: 'none', borderTop: 'none', cursor: 'pointer' }}
                    onClick={() => onPivot?.({ targetTab: 'ttp', search: group.name })}
                  >
                    <span className="stat-label" style={{ display: 'inline-flex', gap: 8, alignItems: 'center' }}>
                      <span style={{ color: 'var(--text-muted)', fontSize: 11, width: 20 }}>#{index + 1}</span>
                      {group.name}
                    </span>
                    <span className="badge badge-info">{group.technique_count} TTPs</span>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="empty-state">
              <Globe size={40} />
              <p>STIX matrix not loaded yet. Attribution improves once corpus download completes.</p>
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Target size={16} style={{ color: '#f97316' }} />
            Threat Actor Profiles
          </div>
          <span className="badge badge-danger">{displayActors.length} actors</span>
        </div>

        {displayActors.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(270px, 1fr))', gap: 10 }}>
            {displayActors.map((actor) => (
              <div key={actor.actor_id} className="insight-card" style={{ borderColor: 'rgba(255,255,255,0.12)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
                  <span className="mono" style={{ color: '#00e0ff', fontWeight: 700 }}>{actor.actor_id}</span>
                  <span className="badge badge-info">{actor.flow_count} flows</span>
                </div>

                <div style={{ marginBottom: 8 }}>
                  <div style={{ fontSize: 12, color: '#8ea2bd', marginBottom: 4 }}>Top Match</div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                    <span style={{ fontWeight: 700, color: getScoreColor(actor.top_score) }}>{actor.top_match}</span>
                    <span className="badge badge-orange">{(actor.top_score * 100).toFixed(1)}%</span>
                  </div>
                </div>

                <div className="score-bar" style={{ marginBottom: 10 }}>
                  <div
                    className="score-bar-fill"
                    style={{
                      width: `${Math.max(2, Math.min(100, actor.top_score * 100))}%`,
                      background: getScoreColor(actor.top_score),
                    }}
                  />
                </div>

                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 10 }}>
                  {actor.ttps.slice(0, 6).map((technique) => (
                    <span key={`${actor.actor_id}-${technique}`} className="badge badge-purple">{technique}</span>
                  ))}
                  {actor.ttps.length > 6 && <span className="badge badge-info">+{actor.ttps.length - 6}</span>}
                </div>

                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-outline btn-sm"
                    onClick={() => onPivot?.({ targetTab: 'explorer', search: actor.actor_id })}
                  >
                    Investigate Actor
                  </button>
                  <button
                    className="btn btn-danger btn-sm"
                    onClick={() => onPivot?.({ targetTab: 'control', sourceIp: actor.actor_id, search: actor.actor_id })}
                  >
                    Contain Actor <ArrowRight size={11} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <AlertTriangle size={40} />
            <p>No threat actors detected for this attribution scope.</p>
          </div>
        )}

        <div style={{ borderTop: '1px solid rgba(255,255,255,0.08)', marginTop: 12, paddingTop: 10 }}>
          <span className="badge badge-cyan"><ShieldCheck size={10} /> STIX {stix.loaded ? 'online' : 'offline'}</span>
          <span className="badge badge-danger" style={{ marginLeft: 6 }}>{aptEscalations.length} linked open incidents</span>
          <span className="badge badge-info" style={{ marginLeft: 6 }}><Activity size={10} /> Counter-first attribution</span>
        </div>
      </div>
    </div>
  );
}
