import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ShieldAlert, Crosshair, Server, Lock, Activity, ArrowRight, Zap, Target, Search, Clock, Shield } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from 'recharts';

import MITRE_DICT from '../MITRE_DICT.json';

const TTT_COLOR_MAP = {
  'Critical': '#ff3366',
  'High': '#ff9a3d',
  'Medium': '#00e0ff',
  'Low': '#c3cedf'
};

export default function TtpMitreTab() {
  const [flows, setFlows] = useState([]);
  const [ttpStats, setTtpStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedTtp, setSelectedTtp] = useState(null);

  useEffect(() => {
    let active = true;
    const fetchTTPs = async () => {
      try {
        const [modRes, flowsRes] = await Promise.all([
           axios.get('/api/modules'),
           axios.get('/api/flows?limit=300')
        ]);
        if (!active) return;
        
        setTtpStats(modRes.data);
        
        const malFlows = (flowsRes.data || []).filter(f => f.verdict === 'malicious' && f.ttp_predictions && String(f.dst_port) !== '8000');
        
        setFlows(malFlows);
        setLoading(false);
      } catch (e) {
        console.error('Failed to fetch TTP data', e);
        if (active) setLoading(false);
      }
    };
    fetchTTPs();
    const intv = setInterval(fetchTTPs, 10000);
    return () => { active = false; clearInterval(intv); }
  }, []);

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  const activeTechniques = Object.entries(ttpStats?.ttp_technique_counts || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15);

  const tacticCounts = {};
  activeTechniques.forEach(([ttpId, count]) => {
      const meta = MITRE_DICT[ttpId] || { tactic: 'Uncategorized' };
      tacticCounts[meta.tactic] = (tacticCounts[meta.tactic] || 0) + count;
  });
  const tacticData = Object.entries(tacticCounts).map(([name, count]) => ({ name, count })).sort((a,b) => b.count - a.count);

  const correlationMap = {};
  flows.forEach(flow => {
      let parsed = [];
      try {
        parsed = typeof flow.ttp_predictions === 'string' ? JSON.parse(flow.ttp_predictions) : flow.ttp_predictions;
      } catch(e) {}
      
      const parseTTPs = Array.isArray(parsed) ? parsed : (parsed?.techniques || []);
      
      parseTTPs.forEach(t => {
          const tid = t.technique_id;
          if (!correlationMap[tid]) correlationMap[tid] = {};
          correlationMap[tid][flow.src_ip] = (correlationMap[tid][flow.src_ip] || 0) + 1;
      });
  });

  const correlationRows = [];
  Object.keys(correlationMap).forEach(tid => {
      Object.keys(correlationMap[tid]).forEach(ip => {
          correlationRows.push({ tid, ip, count: correlationMap[tid][ip] });
      });
  });
  correlationRows.sort((a, b) => b.count - a.count);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="card glass-panel" style={{ padding: 20 }}>
        <h2 style={{ margin: '0 0 8px', fontSize: '1.4rem', color: '#ff3366', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Crosshair size={24} style={{ color: '#ff3366' }} />
          MITRE ATT&CK® TTP Navigator
        </h2>
        <p style={{ margin: 0, color: '#8d97aa', fontSize: '0.9rem' }}>
          Real-time mapping of network telemetry to adversarial Tactics, Techniques, and Procedures (TTPs).
        </p>
      </div>

      <div className="grid-2" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.2fr) minmax(0, 0.8fr)', gap: 20 }}>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div className="card glass-panel" style={{ padding: 20 }}>
            <h3 style={{ margin: '0 0 16px', fontSize: '1.1rem', color: '#e7eefb', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Target size={18} style={{ color: '#00e0ff' }} /> Top Active Techniques
            </h3>
            
            <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 12 }}>
              {activeTechniques.length === 0 ? (
                <div style={{ color: '#8d97aa', fontSize: '0.9rem', textAlign: 'center', padding: '20px' }}>No adversarial techniques observed in the current window.</div>
              ) : (
                activeTechniques.map(([ttpId, count]) => {
                  const meta = MITRE_DICT[ttpId] || { name: 'Unknown Signature', tactic: 'Uncategorized', severity: 'Low' };
                  const isSelected = selectedTtp === ttpId;
                  
                  return (
                    <div 
                      key={ttpId} 
                      onClick={() => setSelectedTtp(isSelected ? null : ttpId)}
                      style={{ 
                        background: isSelected ? 'rgba(0,224,255,0.1)' : 'rgba(0,0,0,0.3)', 
                        border: `1px solid ${isSelected ? '#00e0ff' : 'rgba(255,255,255,0.05)'}`,
                        borderRadius: 8, padding: 12, cursor: 'pointer', transition: 'all 0.2s'
                      }}
                      className="table-row-zoom"
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                          <span className="mono" style={{ color: '#00e0ff', fontWeight: 600, fontSize: '0.9rem' }}>{ttpId}</span>
                          <div>
                            <div style={{ color: '#e7eefb', fontSize: '0.95rem', fontWeight: 500 }}>{meta.name}</div>
                            <div style={{ color: '#8d97aa', fontSize: '0.75rem' }}>{meta.tactic}</div>
                          </div>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                          <span className="badge" style={{ background: 'transparent', border: `1px solid ${TTT_COLOR_MAP[meta.severity]}`, color: TTT_COLOR_MAP[meta.severity] }}>
                            {meta.severity}
                          </span>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 60, justifyContent: 'flex-end' }}>
                            <Activity size={14} style={{ color: '#ff3366' }} />
                            <span style={{ color: '#ff3366', fontWeight: 600 }}>{count.toLocaleString()}</span>
                          </div>
                        </div>
                      </div>
                      
                      {isSelected && (
                        <div style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid rgba(255,255,255,0.05)', fontSize: '0.85rem', color: '#c3cedf', lineHeight: 1.5 }}>
                          {meta.desc}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
          
          <div className="card glass-panel" style={{ padding: 20 }}>
            <h3 style={{ margin: '0 0 16px', fontSize: '1.1rem', color: '#e7eefb', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Shield size={18} style={{ color: '#9f8fff' }} /> TTP by MITRE Tactic
            </h3>
            <div style={{ minHeight: 200, width: '100%' }}>
               <ResponsiveContainer width="100%" height={240}>
                 <BarChart data={tacticData} layout="vertical" margin={{ top: 10, right: 30, left: 10, bottom: 5 }}>
                   <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={true} vertical={false} />
                   <XAxis type="number" stroke="transparent" tick={{ fill: '#64748b', fontSize: 10 }} />
                   <YAxis dataKey="name" type="category" stroke="transparent" tick={{ fill: '#e7eefb', fontSize: 11 }} width={110} />
                   <Tooltip 
                     cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                     contentStyle={{ backgroundColor: 'rgba(10,15,30,0.95)', border: '1px solid rgba(159,143,255,0.4)', color: '#fff', borderRadius: 8 }}
                   />
                   <Bar dataKey="count" fill="#9f8fff" radius={[0, 4, 4, 0]} barSize={20} />
                 </BarChart>
               </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div className="card glass-panel" style={{ padding: 20, flex: 1, display: 'flex', flexDirection: 'column' }}>
             <h3 style={{ margin: '0 0 16px', fontSize: '1.1rem', color: '#e7eefb', display: 'flex', alignItems: 'center', gap: 8 }}>
               <Search size={18} style={{ color: '#ff9a3d' }} /> Live TTP Forensics
             </h3>
             <p style={{ margin: '0 0 16px', fontSize: '0.8rem', color: '#8d97aa' }}>
               Recent flows mapping to the evaluated techniques in real-time.
             </p>
             
             <div style={{ overflowY: 'auto', maxHeight: 350, paddingRight: 8, display: 'flex', flexDirection: 'column', gap: 12 }}>
               {flows.length === 0 ? (
                  <div style={{ color: '#8d97aa', fontSize: '0.9rem', textAlign: 'center', padding: '40px 20px' }}>
                    <ShieldAlert size={32} style={{ opacity: 0.3, marginBottom: 16, margin: '0 auto' }} />
                    No malicious TTP flows intercepted yet.
                  </div>
               ) : flows.map((flow, idx) => {
                 let parsed = [];
                 try {
                   parsed = typeof flow.ttp_predictions === 'string' ? JSON.parse(flow.ttp_predictions) : flow.ttp_predictions;
                 } catch(e) {}
                 
                 const parseTTPs = Array.isArray(parsed) ? parsed : (parsed?.techniques || []);
                 
                 return (
                   <div key={idx} style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,51,102,0.15)', borderRadius: 8, padding: 12 }}>
                     <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <Clock size={12} style={{ color: '#8d97aa' }} />
                          <span style={{ fontSize: '0.75rem', color: '#8d97aa' }}>{new Date(flow.captured_at).toLocaleTimeString()}</span>
                        </div>
                        <span className="badge badge-outline" style={{ borderColor: 'rgba(255,51,102,0.3)', color: '#ff3366' }}>{flow.protocol}</span>
                     </div>
                     
                     <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                        <div className="mono" style={{ color: '#e7eefb', fontSize: '0.85rem' }}>{flow.src_ip}:{flow.src_port}</div>
                        <ArrowRight size={14} style={{ color: '#ff3366' }} />
                        <div className="mono" style={{ color: '#ff3366', fontSize: '0.85rem' }}>{flow.dst_ip}:{flow.dst_port}</div>
                     </div>
                     
                     <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {parseTTPs.map((t, i) => (
                          <span key={i} className="badge badge-purple" style={{ fontSize: '0.7rem', opacity: selectedTtp && selectedTtp !== t.technique_id ? 0.3 : 1 }}>
                             {t.technique_id}
                          </span>
                        ))}
                     </div>
                   </div>
                 );
               })}
             </div>
          </div>
          
          <div className="card glass-panel" style={{ padding: 20, flex: 1 }}>
             <h3 style={{ margin: '0 0 16px', fontSize: '1.1rem', color: '#e7eefb', display: 'flex', alignItems: 'center', gap: 8 }}>
               <Server size={18} style={{ color: '#54a6ff' }} /> TTP Source IP Correlation
             </h3>
             <div style={{ overflowY: 'auto', maxHeight: 300 }}>
                 <table className="data-table" style={{ width: '100%', fontSize: '0.85rem' }}>
                    <thead>
                      <tr>
                         <th>Technique</th>
                         <th>Source IP</th>
                         <th>Flows</th>
                      </tr>
                    </thead>
                    <tbody>
                      {correlationRows.slice(0, 30).map((row, i) => (
                         <tr key={i}>
                            <td style={{ color: '#e7eefb' }}>{row.tid}</td>
                            <td className="mono" style={{ color: '#00e0ff' }}>{row.ip}</td>
                            <td style={{ color: '#ff3366' }}>{row.count}</td>
                         </tr>
                      ))}
                    </tbody>
                 </table>
                 {correlationRows.length === 0 && (
                     <div style={{ textAlign: 'center', padding: 20, color: '#8d97aa' }}>No correlations found</div>
                 )}
             </div>
          </div>

        </div>
      </div>
    </div>
  );
}
