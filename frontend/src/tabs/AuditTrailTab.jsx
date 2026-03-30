import { useState, useMemo, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  FileText,
  RefreshCw,
  Filter,
  Clock,
  CheckCircle2,
  XCircle,
  Server,
  ShieldOff,
  Undo2,
  Shield,
  User,
  AlertTriangle,
} from 'lucide-react';

const eventConfig = {
  created: { icon: Shield, label: 'Action Created', badgeClass: 'badge badge-info' },
  approved: { icon: CheckCircle2, label: 'Approved', badgeClass: 'badge badge-success' },
  rejected: { icon: XCircle, label: 'Rejected', badgeClass: 'badge badge-danger' },
  dispatched: { icon: Server, label: 'Dispatched', badgeClass: 'badge badge-cyan' },
  status_update: { icon: RefreshCw, label: 'Status Update', badgeClass: 'badge badge-orange' },
  rollback_requested: { icon: Undo2, label: 'Rollback', badgeClass: 'badge badge-purple' },
  dc_approved: { icon: CheckCircle2, label: 'DC Approved', badgeClass: 'badge badge-success' },
  dc_rejected: { icon: XCircle, label: 'DC Rejected', badgeClass: 'badge badge-danger' },
  dc_deleted: { icon: AlertTriangle, label: 'DC Deleted', badgeClass: 'badge badge-danger' },
  templated_dispatch: { icon: ShieldOff, label: 'Response Dispatch', badgeClass: 'badge badge-cyan' },
};

const actionFilterOptions = [
  { value: 'all', label: 'All actions' },
  { value: 'isolate_host', label: 'Isolate host' },
  { value: 'restore_host', label: 'Restore host' },
  { value: 'block_ip', label: 'Block IP' },
  { value: 'unblock_ip', label: 'Unblock IP' },
  { value: 'quarantine_host', label: 'Quarantine host' },
  { value: 'disable_ad_user', label: 'Disable AD user' },
  { value: 'enable_ad_user', label: 'Enable AD user' },
];

export default function AuditTrailTab({ api = '', globalSearch = '', autoRefreshSeconds = 10 }) {
  const [trail, setTrail] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState('all');
  const [liveMode, setLiveMode] = useState(true);

  const fetchTrail = useCallback(async () => {
    setLoading(true);
    try {
      let url = `${api}/api/control/audit-trail?limit=250`;
      if (filterType !== 'all') {
        url += `&action_type=${filterType}`;
      }
      const res = await axios.get(url);
      setTrail(res.data || []);
    } catch {
      setTrail([]);
    } finally {
      setLoading(false);
    }
  }, [api, filterType]);

  useEffect(() => {
    fetchTrail();
  }, [fetchTrail]);

  useEffect(() => {
    if (!liveMode || autoRefreshSeconds <= 0) return undefined;
    const interval = setInterval(fetchTrail, autoRefreshSeconds * 1000);
    return () => clearInterval(interval);
  }, [fetchTrail, liveMode, autoRefreshSeconds]);

  const normalizedSearch = useMemo(() => String(globalSearch || '').trim().toLowerCase(), [globalSearch]);

  const filteredTrail = useMemo(() => {
    if (!normalizedSearch) return trail;

    return trail.filter((entry) => {
      const details = JSON.stringify(entry.details || {}).toLowerCase();
      return String(entry.actor || '').toLowerCase().includes(normalizedSearch)
        || String(entry.target_info || '').toLowerCase().includes(normalizedSearch)
        || String(entry.job_target_id || '').toLowerCase().includes(normalizedSearch)
        || String(entry.job_action_type || '').toLowerCase().includes(normalizedSearch)
        || String(entry.event_type || '').toLowerCase().includes(normalizedSearch)
        || details.includes(normalizedSearch);
    });
  }, [trail, normalizedSearch]);

  const getEventMeta = (eventType) => {
    return eventConfig[eventType] || {
      icon: Clock,
      label: String(eventType || 'unknown').replace(/_/g, ' '),
      badgeClass: 'badge badge-info',
    };
  };

  const statusBadge = (status) => {
    if (!status) return <span className="badge badge-info">n/a</span>;
    if (status === 'succeeded') return <span className="badge badge-success">succeeded</span>;
    if (status === 'failed' || status === 'cancelled') return <span className="badge badge-danger">{status}</span>;
    if (status === 'dispatched' || status === 'running') return <span className="badge badge-cyan">{status}</span>;
    if (status === 'queued' || status === 'pending') return <span className="badge badge-warning">{status}</span>;
    return <span className="badge badge-info">{status}</span>;
  };

  const formatTime = (timestamp) => {
    if (!timestamp) return '-';
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <FileText size={16} style={{ color: '#54a6ff' }} />
            Audit and Governance Timeline
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className={`btn btn-sm ${liveMode ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => setLiveMode((value) => !value)}
            >
              {liveMode ? 'Live' : 'Paused'}
            </button>
            <button className="btn btn-outline btn-sm" onClick={fetchTrail}>
              <RefreshCw size={12} className={loading ? 'spin' : ''} /> Refresh
            </button>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 10, alignItems: 'center' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, color: '#9cb0c9', fontSize: 13 }}>
            <Filter size={14} />
            Filter by action type and global context search.
          </div>
          <select className="form-select" value={filterType} onChange={(event) => setFilterType(event.target.value)}>
            {actionFilterOptions.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Clock size={16} style={{ color: '#00e0ff' }} />
            Audit Entries
          </div>
          <span className="badge badge-info">{filteredTrail.length} entries</span>
        </div>

        {filteredTrail.length === 0 ? (
          <div className="empty-state">
            <FileText size={36} />
            <p>No audit entries found for the current filters.</p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto', maxHeight: 680 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event</th>
                  <th>Actor</th>
                  <th>Target</th>
                  <th>Action Type</th>
                  <th>Job Status</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredTrail.map((entry, index) => {
                  const meta = getEventMeta(entry.event_type);
                  const EventIcon = meta.icon;
                  const details = entry.details || {};
                  const detailParts = [
                    details.note ? `note: ${details.note}` : null,
                    details.template_name ? `template: ${details.template_name}` : null,
                    details.dc_id ? `dc: ${details.dc_id}` : null,
                    details.origin_agent_id ? `agent: ${details.origin_agent_id}` : null,
                    details.status ? `status: ${details.status}` : null,
                  ].filter(Boolean);

                  return (
                    <tr key={entry.id || `${entry.created_at}-${index}`}>
                      <td className="mono" style={{ color: '#95a8c3' }}>{formatTime(entry.created_at)}</td>
                      <td>
                        <span className={meta.badgeClass} style={{ display: 'inline-flex', gap: 4, alignItems: 'center' }}>
                          <EventIcon size={10} /> {meta.label}
                        </span>
                      </td>
                      <td>
                        <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                          <User size={11} /> {entry.actor || 'system'}
                        </span>
                      </td>
                      <td className="mono">{entry.target_info || entry.job_target_id || '-'}</td>
                      <td>{entry.job_action_type ? <span className="badge badge-orange">{entry.job_action_type}</span> : <span className="badge badge-info">n/a</span>}</td>
                      <td>{statusBadge(entry.job_status)}</td>
                      <td style={{ color: '#9db0c9' }}>
                        {detailParts.length > 0 ? detailParts.join(' | ') : JSON.stringify(details).slice(0, 90)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
