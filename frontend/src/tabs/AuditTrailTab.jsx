import { useState, useMemo, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  FileText,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  User,
  AlertTriangle,
  ArrowDownToLine,
  Trash2,
} from 'lucide-react';


const eventConfig = {
  dispatched: { icon: ShieldAlert, label: 'Host Isolation', color: '#ff3366' },
  rollback_requested: { icon: ArrowDownToLine, label: 'Host Restored', color: '#00e0ff' },
  dc_approved: { icon: ShieldCheck, label: 'DC Approved', color: '#00ffa3' },
  dc_rejected: { icon: AlertTriangle, label: 'DC Rejected', color: '#ff9a3d' },
  dc_deleted: { icon: Trash2, label: 'DC Removed', color: '#ff3366' },
  agent_removed: { icon: Trash2, label: 'Agent Removed', color: '#ff3366' },
  agent_deleted: { icon: Trash2, label: 'Agent Removed', color: '#ff3366' },
};

export default function AuditTrailTab({ api = '', globalSearch = '', autoRefreshSeconds = 10 }) {
  const [trail, setTrail] = useState([]);
  const [loading, setLoading] = useState(true);
  const [liveMode, setLiveMode] = useState(true);
  const [localSearch, setLocalSearch] = useState('');

  const fetchTrail = useCallback(async () => {
    setLoading(true);
    try {
      const apiBase = api || 'http://localhost:8000';
      const res = await axios.get(`${apiBase}/api/control/audit-trail?limit=500`);
      const data = res.data || [];
      const sortedAudits = [...data].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      setTrail(sortedAudits);
    } catch {
      setTrail([]);
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    fetchTrail();
  }, [fetchTrail]);

  useEffect(() => {
    if (!liveMode || autoRefreshSeconds <= 0) return undefined;
    const interval = setInterval(fetchTrail, autoRefreshSeconds * 1000);
    return () => clearInterval(interval);
  }, [fetchTrail, liveMode, autoRefreshSeconds]);

  const activeSearch = globalSearch || localSearch;
  const normalizedSearch = useMemo(() => String(activeSearch || '').trim().toLowerCase(), [activeSearch]);

  const filteredTrail = useMemo(() => {
    if (!normalizedSearch) return trail;

    return trail.filter((entry) => {
      const details = JSON.stringify(entry.details || {}).toLowerCase();
      return String(entry.actor || '').toLowerCase().includes(normalizedSearch)
        || String(entry.target_info || '').toLowerCase().includes(normalizedSearch)
        || String(entry.job_action_type || '').toLowerCase().includes(normalizedSearch)
        || String(entry.event_type || '').toLowerCase().includes(normalizedSearch)
        || String(entry.id || '').toLowerCase().includes(normalizedSearch)
        || details.includes(normalizedSearch);
    });
  }, [trail, normalizedSearch]);

  const formatTime = (timestamp) => {
    if (!timestamp) return '-';
    const d = new Date(timestamp);
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}.${d.getMilliseconds()}`;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 120px)', gap: 15 }}>
      {/* Dense Control Deck */}
      <div className="card glass-panel" style={{ display: 'flex', flexDirection: 'column', padding: '12px 20px', gap: 12 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <FileText size={18} style={{ color: '#00e0ff' }} />
            <span style={{ fontSize: '1.2rem', fontWeight: 600, color: '#e7eefb', letterSpacing: '0.5px' }}>RAW SYSTEM LOG</span>
            <div style={{ width: 1, height: 20, background: 'rgba(255,255,255,0.1)', marginLeft: 8 }} />
            
            <div style={{ display: 'flex', alignItems: 'center', background: 'rgba(0,0,0,0.2)', padding: '4px 12px', borderRadius: 6, gap: 10 }}>
               <Search size={14} style={{ color: '#8d97aa' }} />
               <input 
                 type="text" 
                 value={localSearch}
                 onChange={(e) => setLocalSearch(e.target.value)}
                 placeholder="Search UUIDs, Hostnames, IPs..." 
                 style={{ background: 'transparent', border: 'none', color: '#fff', fontSize: '0.85rem', width: 220, outline: 'none' }} 
               />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', color: '#54a6ff', marginRight: 15 }}>{filteredTrail.length} Logs Retrieved</span>
            <button
              className={`btn btn-sm ${liveMode ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => setLiveMode(!liveMode)}
              style={{ padding: '4px 12px', fontSize: '0.8rem' }}
            >
              {liveMode ? 'Live Sync Active' : 'Live Sync Paused'}
            </button>
            <button className="btn btn-outline btn-sm" onClick={fetchTrail} style={{ padding: '4px 12px', fontSize: '0.8rem' }}>
              <RefreshCw size={12} className={loading ? 'spin' : ''} /> Refresh
            </button>
          </div>
        </div>
      </div>

      {/* High Density Table */}
      <div className="card glass-panel" style={{ flexGrow: 1, overflow: 'hidden', padding: 0 }}>
        {filteredTrail.length === 0 ? (
          <div className="empty-state" style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <FileText size={48} style={{ color: 'rgba(255,255,255,0.1)' }} />
            <p style={{ marginTop: 15, color: '#8d97aa' }}>No system logs found matching the filter constraints.</p>
          </div>
        ) : (
          <div style={{ overflowY: 'auto', maxHeight: '100%' }}>
            <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <thead style={{ position: 'sticky', top: 0, background: '#0a0f1e', zIndex: 1, boxShadow: '0 2px 10px rgba(0,0,0,0.5)' }}>
                <tr>
                  <th style={{ padding: '10px 16px', color: '#9cb0c9', fontWeight: 600 }}>Date/Time (Local)</th>
                  <th style={{ padding: '10px 16px', color: '#9cb0c9', fontWeight: 600 }}>System Event</th>
                  <th style={{ padding: '10px 16px', color: '#9cb0c9', fontWeight: 600 }}>Actor Profile</th>
                  <th style={{ padding: '10px 16px', color: '#9cb0c9', fontWeight: 600 }}>Target Entity</th>
                  <th style={{ padding: '10px 16px', color: '#9cb0c9', fontWeight: 600 }}>Op Status</th>
                  <th style={{ padding: '10px 16px', color: '#9cb0c9', fontWeight: 600 }}>Raw Data Payload</th>
                </tr>
              </thead>
              <tbody>
                {filteredTrail.map((entry, index) => {
                  const meta = eventConfig[entry.event_type] || eventConfig[entry.job_action_type] || { icon: Server, label: entry.job_action_type || 'Unknown Event', color: '#8d97aa' };
                  const EventIcon = meta.icon;
                  const isSystem = (entry.actor === 'system' || !entry.actor);
                  
                  return (
                    <tr key={entry.id || `${entry.created_at}-${index}`} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', background: index % 2 === 0 ? 'rgba(255,255,255,0.01)' : 'transparent' }}>
                      
                      {/* Timestamp */}
                      <td className="mono" style={{ padding: '8px 16px', color: '#8d97aa', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                         {formatTime(entry.created_at)}
                      </td>
                      
                      {/* Event */}
                      <td style={{ padding: '8px 16px', whiteSpace: 'nowrap' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: meta.color, fontWeight: 600 }}>
                          <EventIcon size={14} /> {meta.label.toUpperCase()}
                        </span>
                        <div style={{ color: '#5a6b84', fontSize: '0.7rem', marginTop: 2 }}>ID: {entry.id || 'N/A'}</div>
                      </td>
                      
                      {/* Actor */}
                      <td style={{ padding: '8px 16px', whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: isSystem ? '#9f8fff' : '#e7eefb' }}>
                           {isSystem ? <Cpu size={14} /> : <User size={14} />} 
                           {entry.actor}
                        </div>
                      </td>
                      
                      {/* Target */}
                      <td className="mono" style={{ padding: '8px 16px', color: '#00e0ff', fontWeight: 600, whiteSpace: 'nowrap' }}>
                        {entry.target_info || entry.job_target_id || '-'}
                      </td>
                      
                      {/* Status */}
                      <td style={{ padding: '8px 16px' }}>
                        <span style={{
                           fontSize: '0.75rem', fontWeight: 600, padding: '2px 8px', borderRadius: 4,
                           background: entry.job_status === 'succeeded' || entry.job_status === 'completed' ? 'rgba(0,255,163,0.1)' : entry.job_status === 'failed' ? 'rgba(255,51,102,0.1)' : 'rgba(255,154,61,0.1)',
                           color: entry.job_status === 'succeeded' || entry.job_status === 'completed' ? '#00ffa3' : entry.job_status === 'failed' ? '#ff3366' : '#ff9a3d'
                        }}>
                          {entry.job_status ? entry.job_status.toUpperCase() : 'UNKNOWN'}
                        </span>
                      </td>

                      {/* Raw Payload JSON */}
                      <td className="mono" style={{ padding: '8px 16px', fontSize: '0.75rem', color: '#aab8c2', width: '100%' }}>
                        <div style={{ background: 'rgba(0,0,0,0.3)', padding: '6px 10px', borderRadius: 4, overflowX: 'auto', whiteSpace: 'nowrap', maxWidth: 400 }}>
                           {JSON.stringify(entry.details || {})}
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
    </div>
  );
}
