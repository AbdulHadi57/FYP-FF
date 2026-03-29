import { useState, useEffect } from 'react';
import axios from 'axios';
import { Crosshair, TrendingUp, AlertTriangle, BarChart3, ChevronRight, Layers } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie } from 'recharts';

export default function TTPAnalysis({ api }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await axios.get(`${api}/api/ttp-stats?limit=1000`);
        setData(res.data);
      } catch (err) {
        console.error('TTP stats error:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
    const id = setInterval(fetchData, 20000);
    return () => clearInterval(id);
  }, [api]);

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  const techniques = data?.technique_distribution || [];
  const recentFlows = data?.recent_ttp_flows || [];
  const modelLoaded = data?.model_loaded || false;

  // Color scale for heatmap
  const getHeatColor = (pct) => {
    if (pct > 20) return '#ef4444';
    if (pct > 10) return '#f97316';
    if (pct > 5) return '#eab308';
    return '#3b82f6';
  };

  const barColors = ['#ef4444', '#f97316', '#eab308', '#22d3ee', '#3b82f6', '#a78bfa', '#10b981'];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* KPIs */}
      <div className="grid-4">
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(249,115,22,0.12)', color: '#f97316' }}>
            <Crosshair size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#f97316' }}>{data?.total_predictions || 0}</div>
            <div className="kpi-label">Flows with TTPs</div>
          </div>
        </div>
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444' }}>
            <Layers size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ef4444' }}>{data?.unique_techniques || 0}</div>
            <div className="kpi-label">Unique Techniques</div>
          </div>
        </div>
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(16,185,129,0.12)', color: '#10b981' }}>
            <TrendingUp size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#10b981' }}>{techniques[0]?.name || 'N/A'}</div>
            <div className="kpi-label">Top Technique</div>
          </div>
        </div>
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: modelLoaded ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.12)', color: modelLoaded ? '#10b981' : '#ef4444' }}>
            <BarChart3 size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: modelLoaded ? '#10b981' : '#ef4444', fontSize: 18 }}>{modelLoaded ? 'Active' : 'Offline'}</div>
            <div className="kpi-label">TTP Model Status</div>
          </div>
        </div>
      </div>

      <div className="grid-2">
        {/* Technique Distribution Bar Chart */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <BarChart3 size={16} style={{ color: '#f97316' }} />
              MITRE ATT&CK Technique Distribution
            </div>
          </div>
          {techniques.length > 0 ? (
            <ResponsiveContainer width="100%" height={350}>
              <BarChart data={techniques.slice(0, 12)} layout="vertical" margin={{ left: 80, right: 20, top: 5, bottom: 5 }}>
                <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} />
                <YAxis dataKey="id" type="category" tick={{ fill: '#94a3b8', fontSize: 11 }} width={75} />
                <Tooltip
                  contentStyle={{ background: '#141820', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6 }}
                  formatter={(value, name, props) => [`${value} flows (${props.payload.pct}%)`, props.payload.name]}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={18}>
                  {techniques.slice(0, 12).map((entry, index) => (
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

        {/* Technique Heatmap Grid */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Layers size={16} style={{ color: '#ef4444' }} />
              Technique Heatmap
            </div>
            <span className="card-subtitle">{techniques.length} techniques detected</span>
          </div>
          {techniques.length > 0 ? (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {techniques.map(t => (
                <div
                  key={t.id}
                  className="heatmap-cell"
                  style={{ background: `${getHeatColor(t.pct)}20`, color: getHeatColor(t.pct), border: `1px solid ${getHeatColor(t.pct)}40` }}
                  title={`${t.name} — ${t.count} flows (${t.pct}%)`}
                >
                  {t.id}
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <AlertTriangle size={40} />
              <p>Awaiting malicious flow data for technique heatmap.</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent TTP Flows Table */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Crosshair size={16} style={{ color: '#22d3ee' }} />
            Recent Flows with TTP Predictions
          </div>
          <span className="badge badge-orange">{recentFlows.length} flows</span>
        </div>
        {recentFlows.length > 0 ? (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Flow ID</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Detected At</th>
                  <th>Techniques</th>
                  <th>Count</th>
                </tr>
              </thead>
              <tbody>
                {recentFlows.map(f => (
                  <tr key={f.flow_id}>
                    <td className="mono" style={{ color: 'var(--cyan)' }}>#{f.flow_id}</td>
                    <td className="mono">{f.src_ip}</td>
                    <td className="mono">{f.dst_ip}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{f.captured_at}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {(f.techniques || []).slice(0, 5).map(tid => (
                          <span key={tid} className="badge badge-orange">{tid}</span>
                        ))}
                        {(f.techniques || []).length > 5 && (
                          <span className="badge badge-info">+{f.techniques.length - 5}</span>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className="badge badge-danger">{f.technique_count || f.techniques?.length || 0}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <Crosshair size={40} />
            <p>No TTP predictions recorded yet. The pipeline will analyze malicious flows automatically.</p>
          </div>
        )}
      </div>
    </div>
  );
}
