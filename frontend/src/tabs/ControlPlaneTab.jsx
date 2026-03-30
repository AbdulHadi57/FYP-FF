import { useState, useEffect, useMemo, useCallback } from 'react';
import axios from 'axios';
import {
  Shield,
  Server,
  Monitor,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Trash2,
  ShieldOff,
  ShieldCheck,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  Wifi,
  WifiOff,
  Clock3,
  Search,
  Filter,
} from 'lucide-react';

const STATUS_BADGES = {
  online: 'badge badge-success',
  offline: 'badge badge-danger',
  pending: 'badge badge-warning',
  approved: 'badge badge-success',
  rejected: 'badge badge-danger',
  queued: 'badge badge-info',
  dispatched: 'badge badge-cyan',
  succeeded: 'badge badge-success',
  failed: 'badge badge-danger',
  pending_approval: 'badge badge-warning',
  cancelled: 'badge badge-danger',
  running: 'badge badge-cyan',
};

const RESPONSE_ACTIONS = new Set([
  'isolate_host',
  'restore_host',
  'block_ip',
  'unblock_ip',
  'quarantine_host',
  'unquarantine_host',
  'disable_ad_user',
  'enable_ad_user',
]);

const INVERSE_ACTION_MAP = {
  isolate_host: 'restore_host',
  restore_host: 'isolate_host',
};

const isIPv4 = (value) => /^(?:\d{1,3}\.){3}\d{1,3}$/.test(String(value || '').trim());

const matchesSearch = (entry, query) => {
  if (!query) return true;
  const payload = JSON.stringify(entry?.payload || {}).toLowerCase();
  return (
    String(entry?.action_type || '').toLowerCase().includes(query)
    || String(entry?.target_id || '').toLowerCase().includes(query)
    || String(entry?.status || '').toLowerCase().includes(query)
    || String(entry?.requested_by || '').toLowerCase().includes(query)
    || String(entry?.reason || '').toLowerCase().includes(query)
    || payload.includes(query)
  );
};

const formatDateTime = (value) => {
  if (!value) return '-';
  return new Date(value).toLocaleString();
};

const statusLabel = (value) => String(value || 'unknown').replace(/_/g, ' ');

const SectionHeader = ({ icon: Icon, title, count, children }) => (
  <div className="card-header" style={{ marginBottom: 10 }}>
    <div className="card-title">
      <Icon size={16} style={{ color: '#00e0ff' }} />
      {title}
      {typeof count === 'number' && <span className="card-subtitle">({count})</span>}
    </div>
    {children}
  </div>
);

const StatusBadge = ({ status }) => (
  <span className={STATUS_BADGES[status] || 'badge badge-info'}>{statusLabel(status)}</span>
);

const DomainControllersSection = ({ api, dcs, onRefresh }) => {
  const [busyDelete, setBusyDelete] = useState('');

  const handleApproval = async (dcId, approved) => {
    try {
      await axios.post(`${api}/api/control/dcs/${dcId}/approve?approved=${approved}&approved_by=soc_analyst`);
      onRefresh();
    } catch (error) {
      alert(`Failed: ${error.response?.data?.detail || error.message}`);
    }
  };

  const handleDelete = async (dcId) => {
    if (!confirm(`Remove domain controller ${dcId} and all its agents? This cannot be undone.`)) return;
    setBusyDelete(dcId);
    try {
      const response = await axios.delete(`${api}/api/control/dcs/${dcId}`);
      alert(response?.data?.message || 'Domain controller removed.');
      onRefresh();
    } catch (error) {
      alert(`Failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setBusyDelete('');
    }
  };

  return (
    <div className="card">
      <SectionHeader icon={Server} title="Domain Controllers" count={dcs.length}>
        <button className="btn btn-outline btn-sm" onClick={onRefresh}>
          <RefreshCw size={12} /> Refresh
        </button>
      </SectionHeader>

      {dcs.length === 0 ? (
        <div className="empty-state" style={{ minHeight: 140 }}>
          <Server size={34} />
          <p>No domain controllers registered yet.</p>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Controller</th>
                <th>Domain</th>
                <th>Approval</th>
                <th>Connectivity</th>
                <th>Agents</th>
                <th>Last Seen</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {dcs.map((dc) => (
                <tr key={dc.id}>
                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      <span style={{ fontWeight: 700, color: '#dce7f9' }}>{dc.hostname || dc.id}</span>
                      <span className="mono" style={{ color: '#8da1bc' }}>{dc.id}</span>
                    </div>
                  </td>
                  <td className="mono" style={{ color: '#9ec9ff' }}>{dc.domain_fqdn || dc.fqdn || 'n/a'}</td>
                  <td><StatusBadge status={dc.approval_status} /></td>
                  <td>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      {dc.status === 'online' ? <Wifi size={12} style={{ color: '#20c997' }} /> : <WifiOff size={12} style={{ color: '#ff4b5c' }} />}
                      <StatusBadge status={dc.status} />
                    </span>
                  </td>
                  <td><span className="badge badge-info">{dc.agent_count || 0}</span></td>
                  <td>{formatDateTime(dc.last_seen)}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                      {dc.approval_status === 'pending' && (
                        <>
                          <button className="btn btn-outline btn-sm" onClick={() => handleApproval(dc.id, true)}>
                            <CheckCircle2 size={11} /> Approve
                          </button>
                          <button className="btn btn-danger btn-sm" onClick={() => handleApproval(dc.id, false)}>
                            <XCircle size={11} /> Reject
                          </button>
                        </>
                      )}
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => handleDelete(dc.id)}
                        disabled={busyDelete === dc.id}
                      >
                        <Trash2 size={11} /> {busyDelete === dc.id ? 'Removing...' : 'Remove'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

const AgentInventorySection = ({ api, agents, dcs, onRefresh }) => {
  const [expanded, setExpanded] = useState({});
  const [busyDelete, setBusyDelete] = useState('');

  const groupedAgents = useMemo(() => {
    const byDc = {};
    dcs.forEach((dc) => {
      byDc[dc.id] = { dc, agents: [] };
    });
    byDc.__unassigned__ = { dc: null, agents: [] };

    agents.forEach((agent) => {
      const key = agent.dc_id && byDc[agent.dc_id] ? agent.dc_id : '__unassigned__';
      byDc[key].agents.push(agent);
    });

    return Object.entries(byDc).filter(([, group]) => group.dc || group.agents.length > 0);
  }, [agents, dcs]);

  const toggleGroup = (groupId) => {
    setExpanded((prev) => ({ ...prev, [groupId]: !(prev[groupId] !== false) }));
  };

  const handleDeleteAgent = async (agent) => {
    if (!confirm(`Remove agent ${agent.hostname || agent.id}?`)) return;

    setBusyDelete(agent.id);
    try {
      const response = await axios.delete(`${api}/api/control/agents/${agent.id}`);
      alert(response?.data?.message || 'Agent removed.');
      onRefresh();
    } catch (error) {
      alert(`Failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setBusyDelete('');
    }
  };

  return (
    <div className="card">
      <SectionHeader icon={Monitor} title="Agent Inventory" count={agents.length} />

      {agents.length === 0 ? (
        <div className="empty-state" style={{ minHeight: 140 }}>
          <Monitor size={34} />
          <p>No agents registered yet.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {groupedAgents.map(([groupId, group]) => {
            const open = expanded[groupId] !== false;
            const groupName = group.dc
              ? `${group.dc.hostname || group.dc.id} (${group.dc.domain_fqdn || 'no domain'})`
              : 'Unassigned Agents';

            return (
              <div
                key={groupId}
                style={{ border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, overflow: 'hidden' }}
              >
                <button
                  onClick={() => toggleGroup(groupId)}
                  style={{
                    width: '100%',
                    border: 'none',
                    borderBottom: open ? '1px solid rgba(255,255,255,0.06)' : 'none',
                    background: 'rgba(255,255,255,0.03)',
                    color: '#d6e3f4',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 12px',
                    cursor: 'pointer',
                    fontFamily: 'inherit',
                  }}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                    {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    <Server size={14} style={{ color: '#00e0ff' }} />
                    <span style={{ fontWeight: 600 }}>{groupName}</span>
                    <span className="badge badge-info">{group.agents.length}</span>
                  </span>
                  {group.dc ? <StatusBadge status={group.dc.approval_status} /> : <span className="badge badge-warning">unassigned</span>}
                </button>

                {open && group.agents.length > 0 && (
                  <div style={{ overflowX: 'auto' }}>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Agent</th>
                          <th>Status</th>
                          <th>Primary IP</th>
                          <th>Domain</th>
                          <th>Last Seen</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {group.agents.map((agent) => (
                          <tr key={agent.id}>
                            <td>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                                <span style={{ color: '#dce7f9', fontWeight: 700 }}>{agent.hostname || agent.id}</span>
                                <span className="mono" style={{ color: '#8da1bc' }}>{agent.id}</span>
                              </div>
                            </td>
                            <td>
                              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                                {agent.status === 'online'
                                  ? <Wifi size={12} style={{ color: '#20c997' }} />
                                  : <WifiOff size={12} style={{ color: '#ff4b5c' }} />}
                                <StatusBadge status={agent.status} />
                              </span>
                            </td>
                            <td className="mono">{agent.primary_ip || 'n/a'}</td>
                            <td>{agent.domain_fqdn || '-'}</td>
                            <td>{formatDateTime(agent.last_seen)}</td>
                            <td>
                              <button
                                className="btn btn-danger btn-sm"
                                onClick={() => handleDeleteAgent(agent)}
                                disabled={busyDelete === agent.id}
                              >
                                <Trash2 size={11} /> {busyDelete === agent.id ? 'Removing...' : 'Remove'}
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

const ActiveResponseSection = ({
  api,
  actions,
  dcs,
  onRefresh,
  initialTargetIp = '',
  globalSearch = '',
}) => {
  const [targetIp, setTargetIp] = useState('');
  const [targetDomain, setTargetDomain] = useState('');
  const [selectedDc, setSelectedDc] = useState('');
  const [busy, setBusy] = useState(false);

  const approvedDcs = useMemo(
    () => dcs.filter((dc) => dc.approval_status === 'approved'),
    [dcs],
  );

  const normalizedSearch = useMemo(
    () => String(globalSearch || '').trim().toLowerCase(),
    [globalSearch],
  );

  useEffect(() => {
    if (initialTargetIp) {
      setTargetIp(initialTargetIp);
    }
  }, [initialTargetIp]);

  const responseActions = useMemo(
    () => actions.filter((action) => RESPONSE_ACTIONS.has(action.action_type)).filter((action) => matchesSearch(action, normalizedSearch)),
    [actions, normalizedSearch],
  );

  const handleAction = async (actionType) => {
    const ip = String(targetIp || '').trim();
    const domain = String(targetDomain || '').trim();

    if (!ip) {
      alert('Enter target IP');
      return;
    }
    if (!domain) {
      alert('Enter target domain');
      return;
    }

    let dcId = selectedDc;
    if (!dcId) {
      const normalizedDomain = domain.toLowerCase();
      dcId = approvedDcs.find((dc) => String(dc.domain_fqdn || '').trim().toLowerCase() === normalizedDomain)?.id || '';
    }

    if (!dcId) {
      alert('No approved domain controller found for this domain.');
      return;
    }

    setBusy(true);
    try {
      await axios.post(`${api}/api/control/actions`, {
        target_type: 'dc',
        target_id: dcId,
        action_type: actionType,
        payload: { target_ip: ip, domain_fqdn: domain },
        requested_by: 'soc_analyst',
        reason: `Manual ${actionType} from dashboard for ${domain}`,
        require_approval: false,
      });
      onRefresh();
    } catch (error) {
      alert(`Failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setBusy(false);
    }
  };

  const handleRollback = async (action) => {
    const inverseType = INVERSE_ACTION_MAP[action.action_type];
    if (!inverseType) {
      alert('Rollback is only supported for isolate and restore actions.');
      return;
    }

    const payload = action.payload || {};
    const ip = String(payload.target_ip || payload.ip || '').trim();
    const domainFromReason = String(action.reason || '').match(/for\s+([a-zA-Z0-9.-]+)\s*$/i)?.[1] || '';
    const domain = String(payload.domain_fqdn || domainFromReason || targetDomain || '').trim();

    if (!ip || !domain) {
      alert('Rollback requires both target IP and domain.');
      return;
    }

    setBusy(true);
    try {
      await axios.post(`${api}/api/control/actions`, {
        target_type: 'dc',
        target_id: action.target_id,
        action_type: inverseType,
        payload: { target_ip: ip, domain_fqdn: domain },
        requested_by: 'soc_analyst',
        reason: `Manual ${inverseType} from dashboard for ${domain} (rollback of ${action.id})`,
        require_approval: false,
      });
      onRefresh();
    } catch (error) {
      alert(`Failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <SectionHeader icon={ShieldOff} title="Response Operations" count={responseActions.length} />

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 1.5fr auto auto', gap: 8, marginBottom: 12 }}>
        <input
          className="form-input"
          placeholder="Target IP"
          value={targetIp}
          onChange={(event) => setTargetIp(event.target.value)}
        />
        <input
          className="form-input"
          placeholder="Target domain (e.g. aegisnet.local)"
          value={targetDomain}
          onChange={(event) => setTargetDomain(event.target.value)}
        />
        <select className="form-select" value={selectedDc} onChange={(event) => setSelectedDc(event.target.value)}>
          <option value="">Auto match approved DC</option>
          {approvedDcs.map((dc) => (
            <option key={dc.id} value={dc.id}>{dc.hostname || dc.id}</option>
          ))}
        </select>
        <button className="btn btn-danger" disabled={busy || !targetIp || !targetDomain} onClick={() => handleAction('isolate_host')}>
          <ShieldOff size={12} /> Isolate
        </button>
        <button className="btn btn-outline" disabled={busy || !targetIp || !targetDomain} onClick={() => handleAction('restore_host')}>
          <ShieldCheck size={12} /> Restore
        </button>
      </div>

      <div className="card-subtitle" style={{ marginBottom: 10, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        <Filter size={12} />
        Showing action history for containment and recovery workflows.
      </div>

      {responseActions.length === 0 ? (
        <div className="empty-state" style={{ minHeight: 130 }}>
          <Shield size={32} />
          <p>No response actions for the current filter.</p>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Action</th>
                <th>Target</th>
                <th>Status</th>
                <th>Requested By</th>
                <th>Reason</th>
                <th>Timestamp</th>
                <th>Rollback</th>
              </tr>
            </thead>
            <tbody>
              {responseActions.map((action) => {
                const destructive = action.action_type.includes('isolate')
                  || action.action_type.includes('block')
                  || action.action_type.includes('disable')
                  || action.action_type.includes('quarantine');

                return (
                  <tr key={action.id}>
                    <td>
                      <span className={destructive ? 'badge badge-danger' : 'badge badge-success'}>
                        {statusLabel(action.action_type)}
                      </span>
                    </td>
                    <td className="mono">{action.target_id}</td>
                    <td><StatusBadge status={action.status} /></td>
                    <td>{action.requested_by || 'system'}</td>
                    <td style={{ maxWidth: 280 }}>{action.reason || '-'}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        <Clock3 size={11} style={{ color: '#8da1bc' }} /> {formatDateTime(action.created_at)}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        {action.status === 'succeeded' && INVERSE_ACTION_MAP[action.action_type] && (
                          <button className="btn btn-outline btn-sm" disabled={busy} onClick={() => handleRollback(action)}>
                            <RefreshCw size={11} /> Rollback
                          </button>
                        )}
                        {action.rollback_of_action_id && (
                          <span className="card-subtitle">of {String(action.rollback_of_action_id).slice(0, 10)}...</span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default function ControlPlaneTab({
  api = '',
  globalSearch = '',
  autoRefreshSeconds = 10,
}) {
  const [dcs, setDcs] = useState([]);
  const [agents, setAgents] = useState([]);
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(true);

  const normalizedSearch = useMemo(
    () => String(globalSearch || '').trim().toLowerCase(),
    [globalSearch],
  );

  const prefillIp = useMemo(
    () => (isIPv4(globalSearch) ? String(globalSearch).trim() : ''),
    [globalSearch],
  );

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [dcRes, agentRes, actionRes] = await Promise.all([
        axios.get(`${api}/api/control/dcs`).catch(() => ({ data: [] })),
        axios.get(`${api}/api/control/agents`).catch(() => ({ data: [] })),
        axios.get(`${api}/api/control/actions?limit=120`).catch(() => ({ data: [] })),
      ]);
      setDcs(dcRes.data || []);
      setAgents(agentRes.data || []);
      setActions(actionRes.data || []);
    } catch {
      setDcs([]);
      setAgents([]);
      setActions([]);
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  useEffect(() => {
    if (!autoRefreshSeconds || autoRefreshSeconds <= 0) return undefined;
    const interval = setInterval(fetchAll, autoRefreshSeconds * 1000);
    return () => clearInterval(interval);
  }, [fetchAll, autoRefreshSeconds]);

  const approvedCount = dcs.filter((dc) => dc.approval_status === 'approved').length;
  const pendingCount = dcs.filter((dc) => dc.approval_status === 'pending').length;
  const onlineAgents = agents.filter((agent) => agent.status === 'online').length;
  const activeActionCount = actions.filter((action) => ['queued', 'running', 'dispatched'].includes(action.status)).length;

  if (loading && dcs.length === 0 && agents.length === 0 && actions.length === 0) {
    return <div className="loading-spinner"><div className="spinner" /></div>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Shield size={16} style={{ color: '#20c997' }} />
            Response Control and Governance
          </div>
          <button className="btn btn-outline btn-sm" onClick={fetchAll}>
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
        <div className="card-subtitle" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <Search size={12} />
          {normalizedSearch
            ? `Context filter active: "${normalizedSearch}"`
            : 'Use global search to prefill IP targets and filter action history.'}
        </div>
      </div>

      <div className="grid-4">
        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(84,166,255,0.12)', color: '#54a6ff' }}>
            <Server size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#54a6ff' }}>{dcs.length}</div>
            <div className="kpi-label">Domain Controllers</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(32,201,151,0.12)', color: '#20c997' }}>
            <CheckCircle2 size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#20c997' }}>{approvedCount}</div>
            <div className="kpi-label">Approved Controllers</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(0,224,255,0.12)', color: '#00e0ff' }}>
            <Monitor size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#00e0ff' }}>{onlineAgents}/{agents.length}</div>
            <div className="kpi-label">Online Agents</div>
          </div>
        </div>

        <div className="kpi-widget">
          <div className="kpi-icon" style={{ background: 'rgba(255,75,92,0.12)', color: '#ff4b5c' }}>
            <ShieldOff size={20} />
          </div>
          <div>
            <div className="kpi-value" style={{ color: '#ff4b5c' }}>{activeActionCount}</div>
            <div className="kpi-label">Active Response Jobs</div>
          </div>
        </div>
      </div>

      {pendingCount > 0 && (
        <div
          style={{
            border: '1px solid rgba(240,194,77,0.35)',
            background: 'rgba(240,194,77,0.1)',
            borderRadius: 12,
            padding: 12,
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            color: '#ffd889',
            fontSize: 13,
          }}
        >
          <AlertTriangle size={15} />
          {pendingCount} controller(s) pending approval; connected agents cannot be trusted until approved.
        </div>
      )}

      <DomainControllersSection api={api} dcs={dcs} onRefresh={fetchAll} />
      <AgentInventorySection api={api} agents={agents} dcs={dcs} onRefresh={fetchAll} />
      <ActiveResponseSection
        api={api}
        actions={actions}
        dcs={dcs}
        onRefresh={fetchAll}
        initialTargetIp={prefillIp}
        globalSearch={globalSearch}
      />
    </div>
  );
}
