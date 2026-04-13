import { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import {
  Network,
  ShieldCheck,
  AlertCircle,
  ScanLine,
  Radio,
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

const LABEL_ORDER = ['DNS', 'FTP', 'SSH', 'VPN', 'HTTPS', 'other'];

const LABEL_COLORS = {
  DNS: '#00d8ff',
  FTP: '#ff9a3d',
  SSH: '#ff5470',
  VPN: '#9f8fff',
  HTTPS: '#54a6ff',
  other: '#8d97aa',
};

function formatLabel(label) {
  return label === 'other' ? 'Others' : label;
}

export default function TrafficTypeTab({ api, autoRefreshSeconds = 10 }) {
  const [payload, setPayload] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const res = await axios.get(`${api}/api/traffic-types/overview?limit=240`);
        if (!active) return;
        setPayload(res.data || null);
      } catch (err) {
        console.error('Failed to load traffic type overview', err);
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

  const distribution = payload?.distribution || [];
  const timeline = payload?.timeline || [];
  const recent = payload?.recent || [];

  const normalizedDistribution = useMemo(() => {
    const byLabel = Object.fromEntries(distribution.map((d) => [d.label, d]));
    return LABEL_ORDER.map((label) => {
      const row = byLabel[label] || { count: 0, pct: 0 };
      return {
        label,
        labelDisplay: formatLabel(label),
        count: Number(row.count || 0),
        pct: Number(row.pct || 0),
        color: LABEL_COLORS[label],
      };
    });
  }, [distribution]);

  const topType = useMemo(() => {
    return normalizedDistribution.reduce((best, row) => {
      if (!best || row.count > best.count) return row;
      return best;
    }, null);
  }, [normalizedDistribution]);

  const avgConfidence = useMemo(() => {
    if (!recent.length) return 0;
    const total = recent.reduce((acc, row) => acc + Number(row.traffic_type_confidence || 0), 0);
    return total / recent.length;
  }, [recent]);

  if (loading) {
    return <div className="loading-spinner"><div className="spinner" /></div>;
  }

  if (!payload) {
    return (
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Network size={16} style={{ color: '#54a6ff' }} />
            Traffic Type Intelligence
          </div>
        </div>
        <div style={{ color: '#9aa6bc' }}>No traffic-type telemetry available yet.</div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="card" style={{ overflow: 'hidden' }}>
        <div className="card-header">
          <div className="card-title">
            <ScanLine size={16} style={{ color: '#54a6ff' }} />
            Traffic Type Intelligence
          </div>
          <span className={payload.model_loaded ? 'badge badge-success' : 'badge badge-warning'}>
            {payload.model_loaded ? 'Model Inference Active' : 'Heuristic Fallback Active'}
          </span>
        </div>
        <div style={{ color: '#a7b4c8', fontSize: 13 }}>
          Stage-0.5 classifies each flow as DNS, FTP, SSH, VPN, HTTPS, or Others before downstream threat context.
        </div>
      </div>

      <div className="grid-4">
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(84,166,255,0.15)', color: '#54a6ff' }}>
            <Radio size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#54a6ff' }}>{Number(payload.total_predictions || 0).toLocaleString()}</div>
            <div className="kpi-label">Classified Flows</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(0,216,255,0.14)', color: '#00d8ff' }}>
            <Network size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#00d8ff' }}>{topType ? topType.labelDisplay : 'N/A'}</div>
            <div className="kpi-label">Most Observed Type</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(159,143,255,0.14)', color: '#9f8fff' }}>
            <ShieldCheck size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#9f8fff' }}>{(avgConfidence * 100).toFixed(1)}%</div>
            <div className="kpi-label">Recent Confidence</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(255,154,61,0.14)', color: '#ff9a3d' }}>
            <AlertCircle size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ff9a3d' }}>{normalizedDistribution.filter((d) => d.count > 0).length}</div>
            <div className="kpi-label">Active Types</div>
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Network size={16} style={{ color: '#00d8ff' }} />
              Traffic Mix Timeline
            </div>
          </div>
          <div style={{ minHeight: 300 }}>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={timeline} margin={{ left: -20, right: 10, top: 8, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                <XAxis
                  dataKey="bucket"
                  tick={{ fill: '#8d97aa', fontSize: 10 }}
                  tickFormatter={(v) => v?.split('T')[1]?.slice(0, 5) || v}
                />
                <YAxis tick={{ fill: '#8d97aa', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ background: 'rgba(5,8,15,0.95)', border: '1px solid rgba(84,166,255,0.35)', borderRadius: 8 }}
                  labelStyle={{ color: '#fff' }}
                />
                {LABEL_ORDER.map((label) => (
                  <Area
                    key={label}
                    type="monotone"
                    dataKey={label}
                    name={formatLabel(label)}
                    stroke={LABEL_COLORS[label]}
                    fill={LABEL_COLORS[label]}
                    fillOpacity={0.2}
                    stackId="traffic-type"
                    strokeWidth={1.8}
                  />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <ScanLine size={16} style={{ color: '#9f8fff' }} />
              Type Distribution
            </div>
          </div>
          <div style={{ minHeight: 300 }}>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={normalizedDistribution} margin={{ left: 0, right: 8, top: 8, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                <XAxis dataKey="labelDisplay" tick={{ fill: '#8d97aa', fontSize: 11 }} />
                <YAxis tick={{ fill: '#8d97aa', fontSize: 11 }} />
                <Tooltip contentStyle={{ background: 'rgba(5,8,15,0.95)', border: '1px solid rgba(159,143,255,0.35)', borderRadius: 8 }} />
                <Bar dataKey="count" radius={[8, 8, 0, 0]}>
                  {normalizedDistribution.map((row) => (
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
            <ShieldCheck size={16} style={{ color: '#00d8ff' }} />
            Recent Classified Traffic
          </div>
          <span className="badge badge-success">{recent.length} recent flows</span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table" style={{ minWidth: 980 }}>
            <thead>
              <tr>
                <th>ID</th>
                <th>Captured</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Traffic Type</th>
                <th>Type Confidence</th>
                <th>Verdict</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((row) => {
                const label = LABEL_ORDER.includes(row.traffic_type) ? row.traffic_type : 'other';
                return (
                  <tr key={row.id}>
                    <td>{row.id}</td>
                    <td>{row.captured_at}</td>
                    <td className="mono">{row.src_ip}:{row.src_port}</td>
                    <td className="mono">{row.dst_ip}:{row.dst_port}</td>
                    <td>{row.dst_port}</td>
                    <td>{row.protocol}</td>
                    <td>
                      <span
                        className="badge"
                        style={{
                          color: LABEL_COLORS[label],
                          borderColor: `${LABEL_COLORS[label]}66`,
                          background: `${LABEL_COLORS[label]}1f`,
                        }}
                      >
                        {formatLabel(label)}
                      </span>
                    </td>
                    <td style={{ color: '#b6c3d7' }}>{(Number(row.traffic_type_confidence || 0) * 100).toFixed(1)}%</td>
                    <td>
                      <span className={row.verdict === 'malicious' ? 'badge badge-danger' : 'badge badge-success'}>
                        {row.verdict}
                      </span>
                    </td>
                  </tr>
                );
              })}
              {recent.length === 0 && (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', color: '#8d97aa', padding: 24 }}>
                    No classified flows available yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
