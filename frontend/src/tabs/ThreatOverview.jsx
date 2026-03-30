import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, Activity, Target, Network, Layers, 
  MapPin, Clock, Server, AlertTriangle, Crosshair, Fingerprint
} from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell,
  LineChart, Line, AreaChart, Area, PieChart, Pie
} from 'recharts';
import axios from 'axios';

export default function ThreatOverview() {
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [modules, setModules] = useState(null);
  
  const [severityData, setSeverityData] = useState([]);
  const [protocolData, setProtocolData] = useState([]);
  const [aptProfiles, setAptProfiles] = useState([]);

  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const fetchData = async () => {
      try {
        const [statsRes, timeRes, modRes, flowsRes, aptRes] = await Promise.all([
          axios.get('http://localhost:8000/api/stats'),
          axios.get('http://localhost:8000/api/timeline'),
          axios.get('http://localhost:8000/api/modules'),
          axios.get('http://localhost:8000/api/flows?limit=300'),
          axios.get('http://localhost:8000/api/apt-stats')
        ]);
        
        if (!active) return;
        setStats(statsRes.data);
        setTimeline(timeRes.data);
        setModules(modRes.data);
        setAptProfiles(aptRes.data.profiles || []);
        
        const flows = flowsRes.data || [];
        
        // Calculate Severity Distribution
        const sev = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        
        flows.forEach(f => {
          if (f.verdict === 'malicious') {
            if (f.severity > 0.8) sev.Critical++;
            else if (f.severity > 0.6) sev.High++;
            else if (f.severity > 0.4) sev.Medium++;
            else sev.Low++;
          }
        });

        setSeverityData([
          { name: 'Critical', value: sev.Critical, color: '#ff3366' },
          { name: 'High', value: sev.High, color: '#ff9a3d' },
          { name: 'Medium', value: sev.Medium, color: '#f4c542' },
          { name: 'Low', value: sev.Low, color: '#54a6ff' }
        ]);
        
        // Calculate Encryption Protocols (TLS 1.3 vs 1.2 vs QUIC) 
        const protoCounts = { 'TLS 1.3': 0, 'TLS 1.2': 0, 'QUIC': 0, 'Other / Custom': 0 };
        const allHashes = [...(modRes.data.top_ja4 || []), ...(modRes.data.top_ja4s || [])];
        allHashes.forEach(item => {
          const hash = item.ja4 || '';
          if (hash.startsWith('t13')) protoCounts['TLS 1.3'] += item.count;
          else if (hash.startsWith('t12')) protoCounts['TLS 1.2'] += item.count;
          else if (hash.startsWith('q13') || hash.startsWith('q12') || hash.startsWith('q20')) protoCounts['QUIC'] += item.count;
          else protoCounts['Other / Custom'] += item.count;
        });

        setProtocolData([
          { name: 'TLS 1.3', value: protoCounts['TLS 1.3'], color: '#00e0ff' },
          { name: 'TLS 1.2', value: protoCounts['TLS 1.2'], color: '#9f8fff' },
          { name: 'QUIC', value: protoCounts['QUIC'], color: '#ff9a3d' },
          { name: 'Other / Custom', value: protoCounts['Other / Custom'], color: '#54a6ff' }
        ]);
        
        setLoading(false);
      } catch (e) {
        console.error('API Error in ThreatOverview:', e);
        if (active) setLoading(false);
      }
    };
    
    fetchData();
    const interval = setInterval(fetchData, 8000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  if (loading || !stats || !modules) return <div className="loading-spinner"><div className="spinner" /></div>;

  const attackers = stats.top_attackers || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* SIEM Headline KPIs */}
      <div className="card glass-panel" style={{ padding: '0' }}>
        <div style={{ display: 'flex', flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
           <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Target size={22} style={{ color: '#00e0ff' }} />
              <div>
                <h2 style={{ margin: 0, fontSize: '1.2rem', color: '#e7eefb' }}>Encrypted Traffic Core Analysis</h2>
                <span style={{ fontSize: '0.8rem', color: '#8d97aa' }}>Passive network telemetry, JA4/JA4S fingerprinting, and ML-driven threat attribution without decryption.</span>
              </div>
           </div>
        </div>

        <div className="grid-4" style={{ padding: 20, paddingTop: 16 }}>
          <div className="kpi-widget" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(84, 166, 255, 0.1)' }}>
            <div className="kpi-icon" style={{ background: 'rgba(84,166,255,0.1)', color: '#54a6ff' }}>
              <Network size={20} />
            </div>
            <div>
              <div className="kpi-value" style={{ color: '#e7eefb' }}>{stats.total_flows.toLocaleString()}</div>
              <div className="kpi-label">Total Packets Monitored</div>
            </div>
          </div>
          <div className="kpi-widget" style={{ background: 'rgba(255, 75, 92, 0.05)', border: '1px solid rgba(255, 75, 92, 0.2)' }}>
            <div className="kpi-icon" style={{ background: 'rgba(255,75,92,0.15)', color: '#ff4b5c' }}>
              <ShieldAlert size={20} />
            </div>
            <div>
              <div className="kpi-value" style={{ color: '#ff4b5c' }}>{stats.malicious_flows.toLocaleString()}</div>
              <div className="kpi-label">Malicious Convictions</div>
            </div>
          </div>
          <div className="kpi-widget" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(159, 143, 255, 0.1)' }}>
            <div className="kpi-icon" style={{ background: 'rgba(159,143,255,0.1)', color: '#9f8fff' }}>
              <Layers size={20} />
            </div>
            <div>
              <div className="kpi-value" style={{ color: '#e7eefb' }}>{modules.ttp_total_predictions.toLocaleString()}</div>
              <div className="kpi-label">TTPs Extracted</div>
            </div>
          </div>
          <div className="kpi-widget" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 154, 61, 0.1)' }}>
            <div className="kpi-icon" style={{ background: 'rgba(255,154,61,0.1)', color: '#ff9a3d' }}>
              <Server size={20} />
            </div>
            <div>
              <div className="kpi-value" style={{ color: '#e7eefb' }}>{modules.ja4_diversity.toLocaleString()}</div>
              <div className="kpi-label">Unique JA4 Hashes</div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid-2">
        {/* Timeline Chart */}
        <div className="card glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="card-header">
            <div className="card-title">
              <Activity size={16} style={{ color: '#00e0ff' }} />
              Malicious Ingestion Timeline
            </div>
            <span className="card-subtitle">Last 60 Minutes</span>
          </div>
          <div style={{ flexGrow: 1, minHeight: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff4b5c" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#ff4b5c" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#54a6ff" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#54a6ff" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="bucket" tick={{ fill: '#8d97aa', fontSize: 10 }} tickFormatter={(val) => val.split('T')[1]?.slice(0,5) || val} />
                <YAxis tick={{ fill: '#8d97aa', fontSize: 10 }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'rgba(10,15,25,0.95)', border: '1px solid rgba(0,210,255,0.2)', borderRadius: 8, backdropFilter: 'blur(10px)' }}
                  itemStyle={{ color: '#e7eefb' }}
                />
                <Area type="monotone" dataKey="flow_count" name="Total Flows" stroke="#54a6ff" fillOpacity={1} fill="url(#colorTotal)" />
                <Area type="monotone" dataKey="malicious_count" name="Malicious" stroke="#ff4b5c" fillOpacity={1} fill="url(#colorMalicious)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* The New Pie Charts Grid for Severity and Ports */}
        <div className="grid-2" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
          
           {/* Severity Donut */}
           <div className="card glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
             <div className="card-header" style={{ paddingBottom: 0 }}>
               <div className="card-title" style={{ fontSize: '0.9rem' }}>
                 <AlertTriangle size={16} style={{ color: '#ff3366' }} />
                 Alert Severity Breakdown
               </div>
             </div>
             <div style={{ flexGrow: 1, minHeight: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
               <ResponsiveContainer width="100%" height={220}>
                 <PieChart>
                   <Pie
                     data={severityData}
                     cx="50%" cy="50%"
                     innerRadius={45} outerRadius={70}
                     paddingAngle={5}
                     dataKey="value"
                     stroke="none"
                   >
                     {severityData.map((entry, index) => (
                       <Cell key={`cell-${index}`} fill={entry.color} />
                     ))}
                   </Pie>
                   <Tooltip 
                     formatter={(value, name) => [`${value} Alerts`, name]}
                     contentStyle={{ backgroundColor: 'rgba(10,15,30,0.95)', border: '1px solid rgba(255,51,102,0.3)', borderRadius: 8 }}
                     itemStyle={{ fontSize: '0.85rem' }} 
                   />
                 </PieChart>
               </ResponsiveContainer>
             </div>
             {/* Legend */}
             <div style={{ display: 'flex', justifyContent: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 15 }}>
               {severityData.map(s => (
                 <div key={s.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.75rem', color: '#8d97aa' }}>
                   <div style={{ width: 8, height: 8, borderRadius: '50%', background: s.color }}/> {s.name}
                 </div>
               ))}
             </div>
           </div>

           {/* Encryption Protocols Donut */}
           <div className="card glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
             <div className="card-header" style={{ paddingBottom: 0 }}>
               <div className="card-title" style={{ fontSize: '0.9rem' }}>
                 <Crosshair size={16} style={{ color: '#00e0ff' }} />
                 Encryption Protocol Distribution
               </div>
             </div>
             <div style={{ flexGrow: 1, minHeight: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
               <ResponsiveContainer width="100%" height={220}>
                 <PieChart>
                   <Pie
                     data={protocolData}
                     cx="50%" cy="50%"
                     innerRadius={45} outerRadius={70}
                     paddingAngle={5}
                     dataKey="value"
                     stroke="none"
                   >
                     {protocolData.map((entry, index) => (
                       <Cell key={`cell-${index}`} fill={entry.color} />
                     ))}
                   </Pie>
                   <Tooltip 
                     formatter={(value, name) => [`${value} Flows`, name]}
                     contentStyle={{ backgroundColor: 'rgba(10,15,30,0.95)', border: '1px solid rgba(0,224,255,0.3)', borderRadius: 8 }}
                     itemStyle={{ fontSize: '0.85rem' }} 
                   />
                 </PieChart>
               </ResponsiveContainer>
             </div>
             {/* Legend */}
             <div style={{ display: 'flex', justifyContent: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 15 }}>
               {protocolData.map(s => (
                 <div key={s.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.75rem', color: '#8d97aa' }}>
                   <div style={{ width: 8, height: 8, borderRadius: '50%', background: s.color }}/> {s.name.split(' ')[0]}
                 </div>
               ))}
             </div>
           </div>
           
        </div>
      </div>

      <div className="grid-2">
        {/* Top Attackers Matrix */}
        <div className="card glass-panel" style={{ padding: 0, display: 'flex', flexDirection: 'column' }}>
          <div className="card-header" style={{ padding: '16px 20px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
            <div className="card-title">
              <MapPin size={16} style={{ color: '#ff9a3d' }} />
              Top Malicious Aggressors (Source IPs)
            </div>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Flow Volume</th>
                <th>Threat Level</th>
              </tr>
            </thead>
            <tbody>
              {attackers.map((atk, i) => (
                <tr key={i}>
                  <td className="mono" style={{ color: '#00e0ff', fontWeight: 600 }}>{atk.ip}</td>
                  <td>{atk.count.toLocaleString()}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <div className="score-bar" style={{ width: 80 }}>
                        <div className="score-bar-fill" style={{ width: `${Math.min(100, (atk.count / attackers[0].count) * 100)}%`, background: i === 0 ? '#ff3366' : '#ff9a3d' }} />
                      </div>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ padding: '10px 20px', background: 'rgba(0,0,0,0.2)', flexGrow: 1, borderTop: '1px solid rgba(255,255,255,0.02)', fontSize: '0.8rem', color: '#8d97aa', textAlign: 'center', display: 'flex', alignItems: 'flex-end', justifyContent: 'center' }}>
            Attacker volumes based on JA4 behavioral identification.
          </div>
        </div>

        {/* TTP Distribution Chart - PROPORTIONALLY FIXED */}
        <div className="card glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="card-header">
            <div className="card-title">
              <Layers size={16} style={{ color: '#9f8fff' }} />
              Extracted MITRE ATT&CK Techniques
            </div>
          </div>
          {/* Dynamically scaling the height to ensure bars never crush */}
          <div style={{ minHeight: `${Math.max(260, modules.ttp_top_techniques.length * 35 + 40)}px`, overflow: 'hidden' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={modules.ttp_top_techniques.slice(0, 10)} layout="vertical" margin={{ top: 10, right: 30, left: 10, bottom: 5 }}>
                <defs>
                  <linearGradient id="colorExec" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#ff4b5c" stopOpacity={0.7}/>
                    <stop offset="100%" stopColor="#ff4b5c" stopOpacity={1}/>
                  </linearGradient>
                  <linearGradient id="colorC2" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#9f8fff" stopOpacity={0.7}/>
                    <stop offset="100%" stopColor="#9f8fff" stopOpacity={1}/>
                  </linearGradient>
                  <linearGradient id="colorEvasion" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#ff9a3d" stopOpacity={0.7}/>
                    <stop offset="100%" stopColor="#ff9a3d" stopOpacity={1}/>
                  </linearGradient>
                  <linearGradient id="colorDefault" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#00e0ff" stopOpacity={0.5}/>
                    <stop offset="100%" stopColor="#00e0ff" stopOpacity={0.9}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={true} vertical={false} />
                <XAxis type="number" stroke="transparent" tick={{ fill: '#64748b', fontSize: 10 }} />
                {/* Expanding width space to prevent text overlap */}
                <YAxis dataKey="id" type="category" stroke="transparent" tick={{ fill: '#e7eefb', fontSize: 11, fontWeight: 700 }} width={60} />
                <Tooltip 
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  contentStyle={{ backgroundColor: 'rgba(10,15,30,0.95)', border: '1px solid rgba(0,224,255,0.4)', color: '#fff', borderRadius: 8, backdropFilter: 'blur(10px)', boxShadow: '0 0 15px rgba(0,224,255,0.1)' }}
                  formatter={(value, name, props) => [`${value} Convictions`, props.payload.name]}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={20}>
                  {modules.ttp_top_techniques.slice(0, 10).map((entry, index) => {
                    let fillColor = 'url(#colorDefault)';
                    const id = entry.id;
                    if(id.startsWith('T1059') || id.startsWith('T1082') || id.startsWith('T1219')) fillColor = 'url(#colorExec)'; 
                    if(id.startsWith('T1071') || id.startsWith('T1090') || id.startsWith('T1573')) fillColor = 'url(#colorC2)'; 
                    if(id.startsWith('T1036') || id.startsWith('T1562') || id.startsWith('T1027')) fillColor = 'url(#colorEvasion)'; 
                    
                    return <Cell key={`cell-${index}`} fill={fillColor} style={{ filter: 'drop-shadow(0 0 4px ' + (fillColor === 'url(#colorExec)' ? 'rgba(255,75,92,0.4)' : fillColor === 'url(#colorC2)' ? 'rgba(159,143,255,0.4)' : fillColor === 'url(#colorEvasion)' ? 'rgba(255,154,61,0.4)' : 'rgba(0,224,255,0.4)') + ')' }} />;
                  })}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* NEW: Active Threat Actor Profiling Section */}
      <div style={{ marginTop: 10 }}>
        <h3 style={{ fontSize: '1.2rem', color: '#e7eefb', display: 'flex', alignItems: 'center', gap: 10, marginBottom: 15 }}>
          <Fingerprint size={20} style={{ color: '#9f8fff' }} />
          Active Threat Actor Profiles
        </h3>
        <p style={{ color: '#8d97aa', fontSize: '0.85rem', marginBottom: 20 }}>
          Machine learning correlation maps active TTPs and network fingerprints directly to known Advanced Persistent Threat (APT) groups.
        </p>

        <div className="grid-3" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20 }}>
          {aptProfiles.map((pt, i) => (
             <div key={i} className="card glass-panel" style={{ padding: 20, borderTop: `3px solid ${i === 0 ? '#ff3366' : '#9f8fff'}`, background: 'rgba(10,15,25,0.8)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: 15, borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                   <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#e7eefb' }}>{pt.top_match}</div>
                   <div className="badge badge-critical" style={{ fontSize: '0.75rem', background: 'rgba(255,51,102,0.1)' }}>{(pt.top_score * 100).toFixed(1)}% Match</div>
                </div>
                
                <div style={{ marginTop: 15 }}>
                   <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                     <span style={{ color: '#8d97aa', fontSize: '0.85rem' }}>Suspect IP Tracker:</span>
                     <span className="mono" style={{ color: '#00e0ff', fontSize: '0.85rem' }}>{pt.actor_id}</span>
                   </div>
                   <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 15 }}>
                     <span style={{ color: '#8d97aa', fontSize: '0.85rem' }}>Correlated Flows:</span>
                     <span style={{ color: '#e7eefb', fontSize: '0.85rem', fontWeight: 600 }}>{pt.flow_count} hits</span>
                   </div>
                </div>

                <div style={{ marginTop: 10 }}>
                  <div style={{ color: '#8d97aa', fontSize: '0.8rem', marginBottom: 6 }}>Active Tactics (TTPs):</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {pt.ttps.map((ttp, idx) => (
                       <span key={idx} style={{ background: 'rgba(159,143,255,0.1)', color: '#9f8fff', padding: '3px 8px', borderRadius: 4, fontSize: '0.7rem', border: '1px solid rgba(159,143,255,0.3)' }}>
                         {ttp}
                       </span>
                    ))}
                  </div>
                </div>
             </div>
          ))}
        </div>
      </div>

    </div>
  );
}
