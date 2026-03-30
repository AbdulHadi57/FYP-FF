import { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import axios from 'axios';
import {
  Search,
  Download,
  Filter,
  RefreshCw,
  Database,
  Siren,
  ShieldCheck,
  ArrowRight,
  SlidersHorizontal,
  Activity,
  Flame,
} from 'lucide-react';
import FlowDetailPanel from '../components/FlowDetailPanel';

const PROTOCOL_OPTIONS = [
  { value: 'all', label: 'All Protocols' },
  { value: '6', label: 'TCP' },
  { value: '17', label: 'UDP' },
  { value: '1', label: 'ICMP' },
];

const VERDICT_OPTIONS = [
  { value: 'all', label: 'All Verdicts' },
  { value: 'malicious', label: 'Malicious' },
  { value: 'benign', label: 'Benign' },
  { value: 'none', label: 'Unknown' },
];

const SORT_OPTIONS = [
  { value: 'captured_at_desc', label: 'Newest first' },
  { value: 'captured_at_asc', label: 'Oldest first' },
  { value: 'confidence_desc', label: 'Highest confidence' },
  { value: 'severity_desc', label: 'Highest severity' },
  { value: 'total_packets_desc', label: 'Most packets' },
];

export default function RawData({
  selectedFlowId,
  api = '',
  globalSearch = '',
  onPivot,
  autoRefreshSeconds = 15,
}) {
  const [flows, setFlows] = useState([]);
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [verdict, setVerdict] = useState('all');
  const [protocol, setProtocol] = useState('all');
  const [sortBy, setSortBy] = useState('captured_at_desc');
  const [minConfidence, setMinConfidence] = useState(0);
  const [riskOnly, setRiskOnly] = useState(false);
  const [loading, setLoading] = useState(false);
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [lastSync, setLastSync] = useState(null);
  const fetchInFlight = useRef(false);

  useEffect(() => {
    setSearchInput(globalSearch || '');
  }, [globalSearch]);

  useEffect(() => {
    const id = setTimeout(() => {
      setSearch(searchInput.trim());
    }, 320);
    return () => clearTimeout(id);
  }, [searchInput]);

  const buildFilters = useMemo(() => {
    const next = {};
    if (verdict !== 'all') next.verdict = verdict;
    if (protocol !== 'all') next.protocol = Number(protocol);
    return next;
  }, [verdict, protocol]);

  const fetchFlows = useCallback(async () => {
    if (fetchInFlight.current) return;
    fetchInFlight.current = true;
    setLoading(true);

    try {
      const params = new URLSearchParams();
      params.append('limit', '300');
      if (search.trim()) params.append('search', search.trim());
      if (Object.keys(buildFilters).length > 0) {
        params.append('filters', JSON.stringify(buildFilters));
      }

      const res = await axios.get(`${api}/api/flows?${params.toString()}`);
      setFlows(res.data || []);
      setLastSync(new Date());
    } catch (error) {
      console.error('Error fetching flows:', error);
    } finally {
      setLoading(false);
      fetchInFlight.current = false;
    }
  }, [api, search, buildFilters]);

  useEffect(() => {
    fetchFlows();
  }, [fetchFlows]);

  useEffect(() => {
    if (!autoRefreshSeconds || autoRefreshSeconds <= 0) return undefined;
    const interval = setInterval(fetchFlows, autoRefreshSeconds * 1000);
    return () => clearInterval(interval);
  }, [fetchFlows, autoRefreshSeconds]);

  useEffect(() => {
    if (selectedFlowId) {
      handleRowClick(selectedFlowId);
    }
  }, [selectedFlowId]);

  const handleRowClick = async (id) => {
    setDetailLoading(true);
    setSelectedFlow(null);
    try {
      const res = await axios.get(`${api}/api/flows/${id}`);
      setSelectedFlow(res.data);
    } catch (error) {
      console.error('Error fetching flow details:', error);
    } finally {
      setDetailLoading(false);
    }
  };

  const closePanel = () => setSelectedFlow(null);

  const downloadCSV = () => {
    if (!visibleFlows.length) return;
    const headers = Object.keys(visibleFlows[0]).join(',');
    const rows = visibleFlows.map((flow) => Object.values(flow).join(','));
    const csvContent = `data:text/csv;charset=utf-8,${[headers, ...rows].join('\n')}`;
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', 'aegisnet_flows.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const visibleFlows = useMemo(() => {
    let scoped = [...flows];

    if (minConfidence > 0) {
      const threshold = minConfidence / 100;
      scoped = scoped.filter((flow) => (flow.confidence || 0) >= threshold);
    }

    if (riskOnly) {
      scoped = scoped.filter((flow) => {
        const hasTtp = Boolean(flow.ttp_predictions && flow.ttp_predictions !== '[]' && flow.ttp_predictions !== 'null');
        return flow.verdict === 'malicious' || (flow.confidence || 0) >= 0.75 || hasTtp;
      });
    }

    const [sortField, sortDirection] = sortBy.split('_');
    scoped.sort((a, b) => {
      let left = a?.[sortField];
      let right = b?.[sortField];

      if (sortField === 'captured_at') {
        left = new Date(left || 0).getTime();
        right = new Date(right || 0).getTime();
      }

      if (sortField === 'confidence' || sortField === 'severity' || sortField === 'total_packets') {
        left = Number(left || 0);
        right = Number(right || 0);
      }

      if (left === right) return 0;
      const ascending = sortDirection === 'asc';
      if (ascending) return left > right ? 1 : -1;
      return left < right ? 1 : -1;
    });

    return scoped;
  }, [flows, minConfidence, riskOnly, sortBy]);

  const maliciousCount = visibleFlows.filter((flow) => flow.verdict === 'malicious').length;
  const highRiskCount = visibleFlows.filter((flow) => (flow.confidence || 0) >= 0.8).length;
  const avgConfidence = visibleFlows.length
    ? visibleFlows.reduce((acc, flow) => acc + (flow.confidence || 0), 0) / visibleFlows.length
    : 0;

  const getProtoName = (protocolValue) => {
    if (protocolValue === 6) return 'TCP';
    if (protocolValue === 17) return 'UDP';
    if (protocolValue === 1) return 'ICMP';
    return String(protocolValue);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, position: 'relative' }}>
      <div className="grid-4">
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(84,166,255,0.12)', color: '#54a6ff' }}>
            <Database size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#54a6ff' }}>{visibleFlows.length}</div>
            <div className="kpi-label">Flows in View</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(255,75,92,0.12)', color: '#ff4b5c' }}>
            <Siren size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ff4b5c' }}>{maliciousCount}</div>
            <div className="kpi-label">Malicious Verdicts</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(255,154,61,0.12)', color: '#ff9a3d' }}>
            <Flame size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ff9a3d' }}>{highRiskCount}</div>
            <div className="kpi-label">High-Risk Signals</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(32,201,151,0.12)', color: '#20c997' }}>
            <Activity size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#20c997' }}>{avgConfidence.toFixed(2)}</div>
            <div className="kpi-label">Average Confidence</div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <SlidersHorizontal size={16} style={{ color: '#00e0ff' }} />
            Live Flow Explorer Controls
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-outline btn-sm" onClick={fetchFlows}>
              <RefreshCw size={12} /> Refresh
            </button>
            <button className="btn btn-outline btn-sm" onClick={downloadCSV}>
              <Download size={12} /> Export CSV
            </button>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr', gap: 10 }}>
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: 10, color: '#7f90aa' }} />
            <input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              className="form-input"
              style={{ width: '100%', paddingLeft: 32 }}
              placeholder="Search by IP, JA4, verdict, technique, or summary"
            />
          </div>

          <select className="form-select" value={verdict} onChange={(e) => setVerdict(e.target.value)}>
            {VERDICT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>

          <select className="form-select" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
            {PROTOCOL_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>

          <select className="form-select" value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
            {SORT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>
        </div>

        <div style={{ marginTop: 10, display: 'grid', gridTemplateColumns: '1.4fr auto auto', gap: 10, alignItems: 'center' }}>
          <div className="legacy-conf-slider">
            <Filter size={14} style={{ color: '#8ea2be' }} />
            <span className="legacy-conf-label">Conf</span>
            <input
              type="range"
              min="0"
              max="100"
              step="5"
              value={minConfidence}
              onChange={(event) => setMinConfidence(Number(event.target.value))}
              className="legacy-conf-range"
            />
            <span className="legacy-conf-value">{minConfidence}%</span>
          </div>

          <button
            className={`btn btn-sm ${riskOnly ? 'btn-danger' : 'btn-outline'}`}
            onClick={() => setRiskOnly((value) => !value)}
          >
            {riskOnly ? 'Risk-only ON' : 'Risk-only OFF'}
          </button>

          <button
            className="btn btn-outline btn-sm"
            onClick={() => {
              setVerdict('all');
              setProtocol('all');
              setMinConfidence(0);
              setRiskOnly(false);
              setSortBy('captured_at_desc');
            }}
          >
            Reset Filters
          </button>
        </div>

        <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <button className="badge badge-info" style={{ border: 'none', cursor: 'pointer' }} onClick={() => setVerdict('all')}>All</button>
          <button className="badge badge-danger" style={{ border: 'none', cursor: 'pointer' }} onClick={() => setVerdict('malicious')}>Malicious</button>
          <button className="badge badge-success" style={{ border: 'none', cursor: 'pointer' }} onClick={() => setVerdict('benign')}>Benign</button>
          <button className="badge badge-orange" style={{ border: 'none', cursor: 'pointer' }} onClick={() => setMinConfidence(70)}>Confidence ≥ 70%</button>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Database size={16} style={{ color: '#54a6ff' }} />
            Flow Records
          </div>
          <span className="badge badge-info">{loading ? 'Syncing...' : `${visibleFlows.length} rows`} | Last sync: {lastSync ? lastSync.toLocaleTimeString() : 'Never'}</span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Proto</th>
                <th>JA4</th>
                <th>Verdict</th>
                <th>Confidence</th>
                <th>Severity</th>
                <th>Packets</th>
                <th>Duration</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {visibleFlows.map((flow) => (
                <tr
                  key={flow.id}
                  onClick={() => handleRowClick(flow.id)}
                  style={{
                    cursor: 'pointer',
                    background: flow.verdict === 'malicious' ? 'rgba(255,75,92,0.04)' : 'transparent',
                  }}
                >
                  <td className="mono" style={{ color: '#00e0ff' }}>#{flow.id}</td>
                  <td>{flow.captured_at?.split('T')?.[1]?.split('.')?.[0] || flow.captured_at}</td>
                  <td className="mono">{flow.src_ip}:{flow.src_port}</td>
                  <td className="mono">{flow.dst_ip}:{flow.dst_port}</td>
                  <td>{getProtoName(flow.protocol)}</td>
                  <td className="mono">{flow.ja4_pred !== 'none' ? flow.ja4_pred : '-'}</td>
                  <td>
                    <span className={flow.verdict === 'malicious' ? 'badge badge-danger' : 'badge badge-success'}>
                      {flow.verdict}
                    </span>
                  </td>
                  <td>{((flow.confidence || 0) * 100).toFixed(0)}%</td>
                  <td>{Number(flow.severity || 0).toFixed(2)}</td>
                  <td>{flow.total_packets}</td>
                  <td>{Number(flow.flow_duration || 0).toFixed(2)}s</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6 }} onClick={(event) => event.stopPropagation()}>
                      <button
                        className="btn btn-outline btn-sm"
                        onClick={() => onPivot?.({ targetTab: 'ttp', search: flow.src_ip, flowId: flow.id })}
                      >
                        TTP
                      </button>
                      {flow.verdict === 'malicious' && (
                        <button
                          className="btn btn-danger btn-sm"
                          onClick={() => onPivot?.({ targetTab: 'control', sourceIp: flow.src_ip, search: flow.src_ip })}
                        >
                          Contain <ArrowRight size={11} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}

              {!loading && visibleFlows.length === 0 && (
                <tr>
                  <td colSpan={12} style={{ textAlign: 'center', padding: '32px 12px', color: '#8a9ab1' }}>
                    No flows match the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <FlowDetailPanel flow={selectedFlow} loading={detailLoading} onClose={closePanel} />
    </div>
  );
}
