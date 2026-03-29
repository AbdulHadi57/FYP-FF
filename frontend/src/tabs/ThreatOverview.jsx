import { useState, useEffect } from 'react';
import axios from 'axios';
import {
  ShieldAlert, Activity, TrendingUp, Users, AlertTriangle, Crosshair,
  ArrowUpRight, ArrowDownRight, Eye, Clock
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar
} from 'recharts';

export default function ThreatOverview({ api }) {
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [moduleStats, setModuleStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [statsRes, timelineRes, modulesRes] = await Promise.all([
          axios.get(`${api}/api/stats`),
          axios.get(`${api}/api/timeline?limit=60`),
          axios.get(`${api}/api/modules?limit=500`),
        ]);
        setStats(statsRes.data);
        setTimeline(timelineRes.data);
        setModuleStats(modulesRes.data);
      } catch (err) {
        console.error('Stats error:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchAll();
    const id = setInterval(fetchAll, 15000);
    return () => clearInterval(id);
  }, [api]);

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  const malPct = stats?.total_flows > 0
    ? ((stats.malicious_flows / stats.total_flows) * 100).toFixed(1)
    : '0.0';

  // Module activity data
  const moduleActivity = moduleStats?.module_activity || {};
  const moduleChartData = [
    { name: 'JA4', value: moduleActivity.ja4 || 0, color: '#22d3ee' },
    { name: 'TTP', value: moduleActivity.ttp || 0, color: '#f97316' },
    { name: 'APT', value: moduleActivity.apt || 0, color: '#ef4444' },
  ].filter(d => d.value > 0);

  // Threat status
  const threatDist = moduleStats?.threat_status_distribution || {};
  const threatChartData = [
    { name: 'Open', value: threatDist.open || 0, color: '#ef4444' },
    { name: 'Resolved', value: threatDist.resolved || 0, color: '#10b981' },
  ].filter(d => d.value > 0);

  // Top attackers
  const topAttackers = stats?.top_attackers || [];

  // TTP quick stats
  const ttpTop = moduleStats?.ttp_top_techniques || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ── KPI Row ── */}
      <div className="grid-4">
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(0,224,255,0.12)', color: 'var(--cyan)' }}>
            <Activity size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: 'var(--cyan)' }}>
              {(stats?.total_flows || 0).toLocaleString()}
            </div>
            <div className="kpi-label">Total Flows Analyzed</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>
            <ShieldAlert size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ef4444' }}>
              {(stats?.malicious_flows || 0).toLocaleString()}
            </div>
            <div className="kpi-label">Malicious Flows ({malPct}%)</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(249,115,22,0.12)', color: '#f97316' }}>
            <Crosshair size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#f97316' }}>
              {moduleStats?.ttp_total_predictions || 0}
            </div>
            <div className="kpi-label">TTP Detections</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(167,139,250,0.12)', color: '#a78bfa' }}>
            <TrendingUp size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#a78bfa' }}>
              {stats?.avg_severity?.toFixed(2) || '0.00'}
            </div>
            <div className="kpi-label">Avg Severity Score</div>
          </div>
        </div>
      </div>

      {/* ── Traffic Timeline ── */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Activity size={16} style={{ color: 'var(--cyan)' }} />
            Traffic Volume & Threat Timeline
          </div>
          <div className="card-subtitle">
            <Clock size={12} style={{ display: 'inline', marginRight: 4 }} />
            Last updated: {stats?.last_flow_timestamp || 'N/A'}
          </div>
        </div>
        {timeline.length > 0 ? (
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={timeline} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="gradientTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradientMalicious" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="bucket" tick={{ fill: '#64748b', fontSize: 10 }} tickFormatter={v => v?.split('T')?.[1] || v?.slice(-5) || v} />
              <YAxis tick={{ fill: '#64748b', fontSize: 10 }} width={40} />
              <Tooltip contentStyle={{ background: '#141820', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, fontSize: 12 }} />
              <Area type="monotone" dataKey="flow_count" stroke="#22d3ee" fill="url(#gradientTotal)" strokeWidth={2} name="Total Flows" />
              <Area type="monotone" dataKey="malicious_count" stroke="#ef4444" fill="url(#gradientMalicious)" strokeWidth={2} name="Malicious" />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty-state"><Activity size={40} /><p>No timeline data available yet.</p></div>
        )}
      </div>

      {/* ── Middle Row: Module Activity + Threat Status + Top Attackers ── */}
      <div className="grid-3">
        {/* Module Activity */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Eye size={16} style={{ color: '#22d3ee' }} />
              Module Detection Activity
            </div>
          </div>
          {moduleChartData.length > 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <ResponsiveContainer width="50%" height={160}>
                <PieChart>
                  <Pie data={moduleChartData} dataKey="value" cx="50%" cy="50%" innerRadius={35} outerRadius={60} paddingAngle={3}>
                    {moduleChartData.map((entry, i) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#141820', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ flex: 1 }}>
                {moduleChartData.map(d => (
                  <div key={d.name} className="stat-line">
                    <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: d.color }} />
                      {d.name}
                    </span>
                    <span className="stat-value" style={{ color: d.color }}>{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="empty-state"><Eye size={32} /><p>No module detections yet.</p></div>
          )}
        </div>

        {/* Threat Status */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <ShieldAlert size={16} style={{ color: '#ef4444' }} />
              Threat Status
            </div>
          </div>
          {threatChartData.length > 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <ResponsiveContainer width="50%" height={160}>
                <PieChart>
                  <Pie data={threatChartData} dataKey="value" cx="50%" cy="50%" innerRadius={35} outerRadius={60} paddingAngle={3}>
                    {threatChartData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#141820', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ flex: 1 }}>
                {threatChartData.map(d => (
                  <div key={d.name} className="stat-line">
                    <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: d.color }} />
                      {d.name}
                    </span>
                    <span className="stat-value" style={{ color: d.color }}>{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="empty-state"><ShieldAlert size={32} /><p>No threats recorded.</p></div>
          )}
        </div>

        {/* Top Attackers */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <AlertTriangle size={16} style={{ color: '#f97316' }} />
              Top Attackers
            </div>
          </div>
          {topAttackers.length > 0 ? (
            <div>
              {topAttackers.map((a, i) => (
                <div key={a.ip} className="stat-line">
                  <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: 11, width: 20 }}>#{i+1}</span>
                    <span className="mono" style={{ color: '#f97316' }}>{a.ip}</span>
                  </span>
                  <span className="badge badge-danger">{a.count} flows</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state"><AlertTriangle size={32} /><p>No attackers detected.</p></div>
          )}
        </div>
      </div>

      {/* ── Bottom: Top TTP Techniques Quick View ── */}
      {ttpTop.length > 0 && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Crosshair size={16} style={{ color: '#f97316' }} />
              Top MITRE ATT&CK Techniques
            </div>
            <span className="badge badge-orange">{moduleStats?.ttp_total_predictions || 0} detections</span>
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={ttpTop.slice(0, 8)} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
              <XAxis dataKey="id" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <YAxis tick={{ fill: '#64748b', fontSize: 10 }} width={40} />
              <Tooltip
                contentStyle={{ background: '#141820', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, fontSize: 12 }}
                formatter={(value, name, props) => [`${value} flows`, props.payload.name]}
              />
              <Bar dataKey="count" fill="#f97316" radius={[4, 4, 0, 0]} maxBarSize={30} fillOpacity={0.8} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
