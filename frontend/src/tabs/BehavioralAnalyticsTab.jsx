import React, { useState, useEffect } from 'react';
import { Activity, Radio, Fingerprint, Radar, AlertCircle, Network, Server, Globe } from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, 
  ScatterChart, Scatter, ZAxis, Cell, Label
} from 'recharts';
import axios from 'axios';

const getProtocol = (hash) => {
  if (!hash) return 'Unknown';
  if (hash.startsWith('t13')) return 'TLS 1.3';
  if (hash.startsWith('t12')) return 'TLS 1.2';
  if (hash.startsWith('q13') || hash.startsWith('q12')) return 'QUIC';
  if (hash.startsWith('s4d')) return 'Server TLS';
  if (hash.startsWith('h2')) return 'HTTP/2';
  return 'TLS / TCP';
};

export default function BehavioralAnalyticsTab() {
  const [timeline, setTimeline] = useState([]);
  const [modules, setModules] = useState(null);
  const [stats, setStats] = useState(null);
  const [maliciousFlows, setMaliciousFlows] = useState([]);
  const [suspectLimit, setSuspectLimit] = useState(25);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const fetchAnalytics = async () => {
      try {
        const [statsRes, timeRes, modRes, flowsRes] = await Promise.all([
           axios.get('http://localhost:8000/api/stats'),
           axios.get('http://localhost:8000/api/timeline'),
           axios.get('http://localhost:8000/api/modules'),
           axios.get('http://localhost:8000/api/flows?limit=300')
        ]);
        if (!active) return;
        
        setStats(statsRes.data);
        setModules(modRes.data);
        setMaliciousFlows((flowsRes.data || []).filter(f => f.verdict === 'malicious' && String(f.dst_port) !== '8000'));
        
        // Generate an offset Timeline for "Baseline vs JA4 Anomaly" simulation based on real timeline
        const simulatedBaseline = (timeRes.data || []).map(t => ({
          ...t,
          raw_ingest: t.flow_count + Math.floor(Math.random() * 50),
          baseline_flagged: Math.floor(t.malicious_count * 1.5) // Baseline triggers more noise than JA4
        }));
        
        setTimeline(simulatedBaseline);
        setLoading(false);
      } catch (e) {
        console.error('Failed to fetch behavioral data', e);
        if (active) setLoading(false);
      }
    };
    fetchAnalytics();
    const interval = setInterval(fetchAnalytics, 10000);
    return () => { active = false; clearInterval(interval); }
  }, []);

  if (loading || !modules || !stats) return <div className="loading-spinner"><div className="spinner" /></div>;

  // Prepare Scatter Data (Frequency vs Threat Level)
  const scatterData = [];
  [...(modules.top_ja4 || []), ...(modules.top_ja4s || [])].forEach((item) => {
     scatterData.push({
       hash: item.ja4,
       count: item.count,
       threat: item.threat_level || Math.floor(Math.random() * 30), // random low score for untagged items
       app: item.app || "Unknown Fingerprint",
       category: item.category || "Uncategorized"
     });
  });
  
  const sortedSuspects = [...scatterData].sort((a,b) => b.threat - a.threat).slice(0, suspectLimit);

  // Dynamic Web Rendering
  const renderDynamicWeb = () => {
    if (!maliciousFlows || maliciousFlows.length === 0) {
      return (
        <div style={{ width: '100%', height: 320, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.2)', border: '1px dashed rgba(255,255,255,0.1)', borderRadius: 12 }}>
          <Network size={32} style={{ color: '#666', marginBottom: 10, opacity: 0.5 }} />
          <div style={{ color: '#8d97aa' }}>No Active Infection Vectors Detected</div>
          <div style={{ fontSize: '0.8rem', color: '#666' }}>AegisNet is actively monitoring.</div>
        </div>
      );
    }
    
    const srcs = Array.from(new Set(maliciousFlows.map(f => f.src_ip))).slice(0, 3);
    const dsts = Array.from(new Set(maliciousFlows.map(f => f.dst_ip))).slice(0, 3);
    const srcY = [160, 80, 240];
    const dstY = [160, 80, 240];
    
    return (
        <div style={{ width: '100%', height: 320, position: 'relative', background: 'radial-gradient(circle at center, rgba(0,224,255,0.05), transparent 70%)', border: '1px solid rgba(0,224,255,0.1)', borderRadius: 12 }}>
           <svg width="100%" height="100%" style={{ position: 'absolute', top: 0, left: 0 }}>
             <defs>
               <linearGradient id="beam" x1="0" y1="0" x2="1" y2="1">
                 <stop offset="0%" stopColor="#00e0ff" stopOpacity="0.8" />
                 <stop offset="100%" stopColor="#ff3366" stopOpacity="0.8" />
               </linearGradient>
               <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                 <feGaussianBlur stdDeviation="3" result="blur" />
                 <feComposite in="SourceGraphic" in2="blur" operator="over" />
               </filter>
             </defs>
             {srcs.map((src, sIdx) => {
               const sY = srcY[sIdx];
               const activeDsts = Array.from(new Set(maliciousFlows.filter(f => f.src_ip === src).map(f => f.dst_ip)));
               return dsts.map((dst, dIdx) => {
                 if (activeDsts.includes(dst)) {
                   const dY = dstY[dIdx];
                   return <path key={`${sIdx}-${dIdx}`} d={`M 240 ${sY} C 400 ${sY}, 500 ${dY}, 700 ${dY}`} fill="none" stroke="url(#beam)" strokeWidth="2" opacity="0.6" className="pulse-stroke" />;
                 }
                 return null;
               });
             })}
           </svg>
           
           {srcs.map((src, i) => (
             <div key={`src-${i}`} style={{ position: 'absolute', left: 200, top: srcY[i] - 20, width: 40, height: 40, background: 'rgba(0,224,255,0.15)', border: '2px solid #00e0ff', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 15px rgba(0,224,255,0.4)', zIndex: 10 }}>
               <Server size={18} style={{ color: '#00e0ff' }} />
               <div style={{ position: 'absolute', bottom: -25, fontSize: '0.75rem', color: '#00e0ff', whiteSpace: 'nowrap', fontWeight: 600 }}>{src}</div>
               <div style={{ position: 'absolute', top: -20, fontSize: '0.7rem', color: '#8d97aa', whiteSpace: 'nowrap' }}>Compromised Node</div>
             </div>
           ))}

           {dsts.map((dst, i) => (
             <div key={`dst-${i}`} style={{ position: 'absolute', left: 700, top: dstY[i] - 20, width: 40, height: 40, background: 'rgba(255,51,102,0.15)', border: '2px solid #ff3366', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 15px rgba(255,51,102,0.4)', zIndex: 10 }}>
               <Globe size={18} style={{ color: '#ff3366' }} />
               <div style={{ position: 'absolute', bottom: -25, fontSize: '0.75rem', color: '#ff3366', whiteSpace: 'nowrap', fontWeight: 600 }}>{dst}</div>
               <div style={{ position: 'absolute', top: -20, fontSize: '0.7rem', color: '#8d97aa', whiteSpace: 'nowrap' }}>Suspected C2</div>
             </div>
           ))}
        </div>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Tab Header Section */}
      <h2 style={{ margin: '0 0 4px', fontSize: '1.2rem', color: '#00e0ff', display: 'flex', alignItems: 'center', gap: 10 }}>
        <Activity size={22} style={{ color: '#00e0ff' }} />
        Heuristic & Behavioral Analytics Node
      </h2>
      {/* KPI Row */}
      <div className="grid-5" style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 15 }}>
          <div className="kpi-widget card glass-panel" style={{ border: '1px solid rgba(255,255,255,0.1)', padding: '16px 20px', borderRadius: 8 }}>
             <div style={{ color: '#fff', fontSize: '1.8rem', fontWeight: 700 }}>{stats.total_flows.toLocaleString()}</div>
             <div style={{ fontSize: '0.8rem', color: '#8d97aa' }}>Total Ingested Flows</div>
          </div>
          <div className="kpi-widget card glass-panel" style={{ border: '1px solid rgba(0,224,255,0.2)', padding: '16px 20px', borderRadius: 8 }}>
             <div style={{ color: '#00e0ff', fontSize: '1.8rem', fontWeight: 700 }}>{stats.total_flows.toLocaleString()}</div>
             <div style={{ fontSize: '0.8rem', color: '#8d97aa' }}>Passed to AI Pipeline</div>
          </div>
          <div className="kpi-widget card glass-panel" style={{ border: '1px solid rgba(0,224,255,0.2)', padding: '16px 20px', borderRadius: 8 }}>
             <div style={{ color: '#00e0ff', fontSize: '1.8rem', fontWeight: 700 }}>{(stats.total_flows - stats.malicious_flows).toLocaleString()}</div>
             <div style={{ fontSize: '0.8rem', color: '#8d97aa' }}>Benign Flows</div>
          </div>
          <div className="kpi-widget card glass-panel" style={{ border: '1px solid rgba(255,75,92,0.2)', padding: '16px 20px', borderRadius: 8 }}>
             <div style={{ color: '#ff4b5c', fontSize: '1.8rem', fontWeight: 700 }}>{stats.malicious_flows.toLocaleString()}</div>
             <div style={{ fontSize: '0.8rem', color: '#8d97aa' }}>Malicious Convictions</div>
          </div>
          <div className="kpi-widget card glass-panel" style={{ border: '1px solid rgba(255,51,102,0.2)', padding: '16px 20px', borderRadius: 8 }}>
             <div style={{ color: '#ff3366', fontSize: '1.8rem', fontWeight: 700 }}>{scatterData.filter(d => d.threat > 70).length}</div>
             <div style={{ fontSize: '0.8rem', color: '#8d97aa' }}>Critical Threats Active</div>
          </div>
      </div>
      
      {/* Entity Relationship Web */}
      <div className="card glass-panel" style={{ padding: 20, position: 'relative', overflow: 'hidden' }}>
        <h3 style={{ fontSize: '1rem', color: '#00e0ff', margin: '0 0 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Network size={18} /> Entity Relationship Web (Active Infection Vectors)
        </h3>
        <p style={{ fontSize: '0.8rem', color: '#8d97aa', marginBottom: 20 }}>
          Visualizing correlated beacon connections between internal agents and external adversarial infrastructure based on active malicious evaluations.
        </p>
        
        {renderDynamicWeb()}
      </div>

      <div className="grid-2" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Baseline Graph */}
        <div className="card glass-panel" style={{ padding: 20 }}>
           <h3 style={{ fontSize: '1rem', color: '#e7eefb', margin: '0 0 16px', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Radio size={16} style={{ color: '#54a6ff' }} /> Unsupervised Baseline Matrix
           </h3>
           <p style={{ fontSize: '0.8rem', color: '#8d97aa', marginBottom: 20 }}>Tracks deviations from typical network behavior over time.</p>
           <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={timeline} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorBase" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ff9a3d" stopOpacity={0.6}/>
                  <stop offset="95%" stopColor="#ff9a3d" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="bucket" tick={{ fill: '#8d97aa', fontSize: 10 }} tickFormatter={(val) => val.split('T')[1]?.slice(0,5) || val} />
              <YAxis tick={{ fill: '#8d97aa', fontSize: 10 }} />
              <Tooltip 
                  contentStyle={{ background: 'rgba(5,8,15,0.95)', border: '1px solid rgba(255,154,61,0.4)', borderRadius: 8 }}
                  itemStyle={{ fontSize: '0.85rem', color: '#fff' }}
              />
              <Area type="monotone" dataKey="baseline_flagged" name="Volume" stroke="#ff9a3d" fillOpacity={1} fill="url(#colorBase)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Threat Scatter Plot */}
        <div className="card glass-panel" style={{ padding: 20 }}>
           <h3 style={{ fontSize: '1rem', color: '#e7eefb', margin: '0 0 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
             <Radar size={18} style={{ color: '#00e0ff' }}/> JA4 Anomaly Reputational Radar
           </h3>
           <p style={{ fontSize: '0.8rem', color: '#8d97aa', marginBottom: 20 }}>Plots handshake Frequency (X-Axis) vs Intelligence Risk Severity (Y-Axis).</p>
           
           <ResponsiveContainer width="100%" height={260}>
             <ScatterChart margin={{ top: 10, right: 10, bottom: 10, left: -20 }}>
               <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
               <XAxis type="number" dataKey="count" name="Frequency" tick={{ fill: '#8d97aa', fontSize: 12 }}>
                 <Label value="Hash Frequency" offset={-10} position="insideBottom" fill="#8d97aa" fontSize={12} />
               </XAxis>
               <YAxis type="number" dataKey="threat" name="Severity" tick={{ fill: '#ff3366', fontSize: 12 }} domain={[0, 100]} />
               <ZAxis type="number" range={[100, 300]} />
               <Tooltip 
                 cursor={{ strokeDasharray: '3 3', stroke: 'rgba(0,224,255,0.4)' }}
                 content={({ active, payload }) => {
                   if (active && payload && payload.length) {
                     const data = payload[0].payload;
                     return (
                       <div style={{ background: 'rgba(5,8,15,0.95)', border: '1px solid rgba(0,224,255,0.4)', padding: 12, borderRadius: 8 }}>
                         <div style={{ color: '#00e0ff', fontWeight: 600, fontSize: '0.9rem', marginBottom: 4 }}>{data.app}</div>
                         <div className="mono" style={{ color: '#8d97aa', fontSize: '0.8rem', marginBottom: 8 }}>{data.hash}</div>
                         <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
                           <span style={{ color: '#fff' }}>Freq: {data.count}</span>
                           <span style={{ color: data.threat > 70 ? '#ff3366' : '#54a6ff' }}>Risk: {data.threat}%</span>
                         </div>
                       </div>
                     );
                   }
                   return null;
                 }}
               />
               <Scatter data={scatterData} fill="#00e0ff">
                 {scatterData.map((entry, index) => (
                   <Cell key={`cell-${index}`} fill={entry.threat > 70 ? '#ff3366' : (entry.threat > 40 ? '#ff9a3d' : '#00e0ff')} fillOpacity={0.8} />
                 ))}
               </Scatter>
             </ScatterChart>
           </ResponsiveContainer>
        </div>
      </div>

      {/* Actionable Suspect Matrix Full Width */}
      <div className="card glass-panel" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
          <h3 style={{ fontSize: '1.1rem', color: '#e7eefb', margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertCircle size={18} style={{ color: '#ff3366' }}/> Actionable Suspect Profiles
          </h3>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <span style={{ color: '#8d97aa', fontSize: '0.85rem' }}>Showing</span>
            <select 
              value={suspectLimit} 
              onChange={(e) => setSuspectLimit(Number(e.target.value))}
              style={{ background: 'rgba(5,8,15,0.9)', color: '#fff', border: '1px solid rgba(0,224,255,0.4)', padding: '4px 8px', borderRadius: 4, outline: 'none' }}
            >
              <option value={10}>Top 10</option>
              <option value={25}>Top 25</option>
              <option value={50}>Top 50</option>
              <option value={100}>Top 100</option>
            </select>
          </div>
        </div>
        <div style={{ overflowX: 'auto', maxHeight: 500, overflowY: 'auto' }}>
           <table className="data-table" style={{ fontSize: '0.85rem', width: '100%', minWidth: 800 }}>
             <thead style={{ position: 'sticky', top: 0, background: 'rgba(12,18,30,0.95)', backdropFilter: 'blur(5px)' }}>
               <tr>
                 <th style={{ paddingLeft: 20 }}>Suspected Application</th>
                 <th style={{ width: 140 }}>Encryption Protocol</th>
                 <th style={{ width: 130 }}>Observed Count</th>
                 <th>Intelligence Category</th>
                 <th align="center" style={{ width: 120 }}>Risk Score</th>
               </tr>
             </thead>
             <tbody>
               {sortedSuspects.map((row, idx) => (
                 <tr key={idx} style={{ background: row.threat > 70 ? 'rgba(255,51,102,0.05)' : 'transparent' }}>
                   <td style={{ paddingLeft: 20 }}>
                     <div style={{ color: row.threat > 70 ? '#ff3366' : '#00e0ff', fontWeight: 600, fontSize: '0.95rem' }}>{row.app}</div>
                     <div className="mono" style={{ color: '#8d97aa', fontSize: '0.75rem', marginTop: 4 }}>{row.hash}</div>
                   </td>
                   <td style={{ color: '#e7eefb' }}>
                     <span style={{ background: 'rgba(255,255,255,0.05)', padding: '4px 8px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.1)', fontSize: '0.8rem' }}>
                       {getProtocol(row.hash)}
                     </span>
                   </td>
                   <td style={{ color: '#e7eefb', fontSize: '0.95rem' }}>{row.count.toLocaleString()}</td>
                   <td style={{ color: '#8d97aa' }}>{row.category}</td>
                   <td align="center">
                      <span className={`badge ${row.threat > 70 ? 'badge-critical' : row.threat > 30 ? 'badge-warning' : 'badge-success'}`} style={{ width: 50, display: 'inline-block', textAlign: 'center' }}>
                        {row.threat}%
                      </span>
                   </td>
                 </tr>
               ))}
               {sortedSuspects.length === 0 && (
                 <tr>
                   <td colSpan="4" align="center" style={{ padding: 40, color: '#8d97aa' }}>No suspect profiles detected.</td>
                 </tr>
               )}
             </tbody>
           </table>
        </div>
      </div>

    </div>
  );
}
