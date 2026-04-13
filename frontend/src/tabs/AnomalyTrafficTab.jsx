import { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import {
  Activity,
  AlertTriangle,
  ShieldCheck,
  Waves,
  Binary,
  Sparkles,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

export default function AnomalyTrafficTab({ api, autoRefreshSeconds = 10 }) {
  const [payload, setPayload] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const res = await axios.get(`${api}/api/behavioral/overview?limit=240`);
        if (!active) return;
        setPayload(res.data || null);
      } catch (err) {
        console.error('Failed to load behavioral overview', err);
      } finally {
        if (active) setLoading(false);
      }
    };

    load();
    if (!autoRefreshSeconds || autoRefreshSeconds <= 0) {
      return () => {
        active = false;
      };
    }

    const id = setInterval(load, autoRefreshSeconds * 1000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [api, autoRefreshSeconds]);

  const timeline = payload?.timeline || [];
  const anomalies = payload?.anomalies || [];
  const normals = payload?.normals || [];

  const ringData = useMemo(() => {
    return [
      { label: 'Anomalies', value: payload?.anomaly_count || 0, color: '#ff5470' },
      { label: 'Normals', value: payload?.normal_count || 0, color: '#00d8ff' },
    ];
  }, [payload]);

  const topAnomalies = useMemo(() => {
    return [...anomalies]
      .sort((a, b) => (b.score || 0) - (a.score || 0))
      .slice(0, 20);
  }, [anomalies]);

  if (loading) {
    return <div className="loading-spinner"><div className="spinner" /></div>;
  }

  if (!payload) {
    return (
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Activity size={16} style={{ color: '#00e0ff' }} />
            Behavioral Anomaly Canvas
          </div>
        </div>
        <div style={{ color: '#9aa6bc' }}>No behavioral telemetry available yet.</div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="card" style={{ overflow: 'hidden' }}>
        <div className="card-header">
          <div className="card-title">
            <Sparkles size={16} style={{ color: '#9f8fff' }} />
            Behavioral Anomaly Canvas
          </div>
          <span className={payload.model_loaded ? 'badge badge-success' : 'badge badge-warning'}>
            {payload.model_loaded ? 'Baseline Model Loaded' : 'Baseline Model Missing'}
          </span>
        </div>
        <div style={{ color: '#a7b4c8', fontSize: 13 }}>
          Stage-0 behavioral detection runs before JA4 and drives this anomaly versus normal traffic board.
        </div>
      </div>

      <div className="grid-4">
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(0,216,255,0.14)', color: '#00d8ff' }}>
            <Binary size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#00d8ff' }}>{(payload.total_flows || 0).toLocaleString()}</div>
            <div className="kpi-label">Total Behavioral Evaluations</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(255,84,112,0.14)', color: '#ff5470' }}>
            <AlertTriangle size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ff5470' }}>{(payload.anomaly_count || 0).toLocaleString()}</div>
            <div className="kpi-label">Anomalies Flagged</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(0,216,255,0.14)', color: '#00d8ff' }}>
            <ShieldCheck size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#00d8ff' }}>{(payload.normal_count || 0).toLocaleString()}</div>
            <div className="kpi-label">Normal Traffic</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(159,143,255,0.14)', color: '#9f8fff' }}>
            <Waves size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#9f8fff' }}>
              {payload.total_flows ? ((payload.anomaly_count || 0) * 100 / payload.total_flows).toFixed(2) : '0.00'}%
            </div>
            <div className="kpi-label">Anomaly Rate</div>
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Waves size={16} style={{ color: '#00d8ff' }} />
              Normal vs Anomaly Stream
            </div>
          </div>
          <div style={{ minHeight: 300 }}>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={timeline} margin={{ left: -20, right: 10, top: 8, bottom: 0 }}>
                <defs>
                  <linearGradient id="normFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00d8ff" stopOpacity={0.45} />
                    <stop offset="95%" stopColor="#00d8ff" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="anomFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff5470" stopOpacity={0.45} />
                    <stop offset="95%" stopColor="#ff5470" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                <XAxis
                  dataKey="bucket"
                  tick={{ fill: '#8d97aa', fontSize: 10 }}
                  tickFormatter={(v) => v?.split('T')[1]?.slice(0, 5) || v}
                />
                <YAxis tick={{ fill: '#8d97aa', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ background: 'rgba(5,8,15,0.95)', border: '1px solid rgba(0,216,255,0.35)', borderRadius: 8 }}
                  labelStyle={{ color: '#fff' }}
                />
                <Area type="monotone" dataKey="normals" name="Normals" stroke="#00d8ff" fill="url(#normFill)" strokeWidth={2} />
                <Area type="monotone" dataKey="anomalies" name="Anomalies" stroke="#ff5470" fill="url(#anomFill)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Activity size={16} style={{ color: '#9f8fff' }} />
              Distribution Snapshot
            </div>
          </div>
          <div style={{ minHeight: 300 }}>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={ringData} margin={{ left: 0, right: 8, top: 8, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: '#8d97aa', fontSize: 12 }} />
                <YAxis tick={{ fill: '#8d97aa', fontSize: 12 }} />
                <Tooltip contentStyle={{ background: 'rgba(5,8,15,0.95)', border: '1px solid rgba(159,143,255,0.35)', borderRadius: 8 }} />
                <Bar dataKey="value" radius={[8, 8, 0, 0]}>
                  {ringData.map((row) => (
                    <Cell key={row.label} fill={row.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="card" style={{ overflow: 'hidden' }}>
        <div className="card-header">
          <div className="card-title">
            <AlertTriangle size={16} style={{ color: '#ff5470' }} />
            Top Behavioral Anomalies
          </div>
          <span className="badge badge-danger">{topAnomalies.length} surfaced</span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table" style={{ minWidth: 900 }}>
            <thead>
              <tr>
                <th>ID</th>
                <th>Captured</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Score</th>
                <th>Confidence</th>
                <th>Rationale</th>
              </tr>
            </thead>
            <tbody>
              {topAnomalies.map((row) => (
                <tr key={row.id} style={{ background: 'rgba(255,84,112,0.06)' }}>
                  <td>{row.id}</td>
                  <td>{row.captured_at}</td>
                  <td className="mono">{row.src_ip}</td>
                  <td className="mono">{row.dst_ip}</td>
                  <td>{row.dst_port}</td>
                  <td>{row.protocol}</td>
                  <td style={{ color: '#ff9a3d' }}>{Number(row.score || 0).toFixed(4)}</td>
                  <td style={{ color: '#ff5470' }}>{Number(row.confidence || 0).toFixed(3)}</td>
                  <td style={{ maxWidth: 300, color: '#9aa6bc' }}>{row.rationale}</td>
                </tr>
              ))}
              {topAnomalies.length === 0 && (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', color: '#8d97aa', padding: 24 }}>
                    No anomalies recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card" style={{ overflow: 'hidden' }}>
        <div className="card-header">
          <div className="card-title">
            <ShieldCheck size={16} style={{ color: '#00d8ff' }} />
            Recent Normal Traffic Samples
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12 }}>
          {normals.slice(0, 12).map((row) => (
            <div key={`normal-${row.id}`} className="insight-card" style={{ borderColor: 'rgba(0,216,255,0.25)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <div style={{ color: '#00d8ff', fontWeight: 700 }}>Flow #{row.id}</div>
                <span className="badge badge-success">Normal</span>
              </div>
              <div style={{ color: '#8d97aa', fontSize: 12, marginTop: 6 }}>{row.captured_at}</div>
              <div className="mono" style={{ marginTop: 8, fontSize: 12 }}>{row.src_ip} → {row.dst_ip}</div>
              <div style={{ marginTop: 8, color: '#9aa6bc', fontSize: 12 }}>
                score {Number(row.score || 0).toFixed(4)} | confidence {Number(row.confidence || 0).toFixed(3)}
              </div>
            </div>
          ))}
          {normals.length === 0 && (
            <div style={{ color: '#8d97aa', padding: 10 }}>No normal samples available yet.</div>
          )}
        </div>
      </div>
    </div>
  );
}
