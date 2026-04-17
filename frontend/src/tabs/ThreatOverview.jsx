import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldAlert, Activity, Target, Network, Layers, 
  MapPin, Clock, Server, AlertTriangle, Crosshair, Fingerprint, Share2
} from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell,
  AreaChart, Area, PieChart, Pie, Sankey
} from 'recharts';
import ForceGraph2D from 'react-force-graph-2d';
import axios from 'axios';

// Component for custom Tooltip in Sankey
const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{ backgroundColor: 'rgba(10,15,30,0.95)', border: '1px solid rgba(0,224,255,0.4)', padding: '10px', color: '#fff', borderRadius: '8px' }}>
        <p style={{ margin: 0 }}>{`${payload[0].name}`}</p>
        <p style={{ margin: 0, color: '#00e0ff' }}>{`Flows: ${payload[0].value}`}</p>
      </div>
    );
  }
  return null;
};

export default function ThreatOverview() {
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [modules, setModules] = useState(null);
  
  const [severityData, setSeverityData] = useState([]);
  const [protocolData, setProtocolData] = useState([]);

  // ETA and Graph States
  const [etaOverview, setEtaOverview] = useState(null);
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [sankeyData, setSankeyData] = useState({ nodes: [], links: [] });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // For resizing graph
  const graphContainerRef = useRef(null);
  const [graphDim, setGraphDim] = useState({ width: 400, height: 400 });

  useEffect(() => {
    if (!graphContainerRef.current) return;
    
    const observer = new ResizeObserver((entries) => {
      for (let entry of entries) {
        const { width, height } = entry.contentRect;
        if (width > 0 && height > 0) {
            setGraphDim({ width, height });
        }
      }
    });
    
    observer.observe(graphContainerRef.current);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    let active = true;
    const fetchData = async () => {
      try {
        const [statsRes, timeRes, modRes, flowsRes, etaRes] = await Promise.all([
          axios.get('/api/stats'),
          axios.get('/api/timeline'),
          axios.get('/api/modules'),
          axios.get('/api/flows?limit=300'),
          axios.get('/api/eta/overview')
        ]);
        
        if (!active) return;
        setStats(statsRes.data);
        setTimeline(timeRes.data);
        setModules(modRes.data);
        setEtaOverview(etaRes.data);
        
        const flows = flowsRes.data || [];
        
        // Calculate Severity Distribution
        const sev = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        
        // Prepare graph data
        const nodesMap = new Map();
        const linksMap = new Map();
        
        // Prepare Sankey data
        const sankeyNodesMap = new Map(); 
        const sankeyLinksArr = []; 

        const addSankeyNode = (name) => {
            if (!sankeyNodesMap.has(name)) {
                sankeyNodesMap.set(name, sankeyNodesMap.size);
            }
            return sankeyNodesMap.get(name);
        };
        
        const addSankeyLink = (srcName, tgtName, val) => {
            const s = addSankeyNode(srcName);
            const t = addSankeyNode(tgtName);
            const existing = sankeyLinksArr.find(l => l.source === s && l.target === t);
            if (existing) existing.value += val;
            else sankeyLinksArr.push({ source: s, target: t, value: val });
        };

        flows.forEach(f => {
          if (f.verdict === 'malicious') {
            if (f.severity > 0.8) sev.Critical++;
            else if (f.severity > 0.6) sev.High++;
            else if (f.severity > 0.4) sev.Medium++;
            else sev.Low++;
            
            // Limit mapping for visuals (otherwise gets too crowded)
            if (nodesMap.size < 100) {
              const srcId = String(f.src_ip);
              const dstId = String(f.dst_ip);
              if (!nodesMap.has(srcId)) nodesMap.set(srcId, { id: srcId, group: 'attacker', name: srcId, val: 5 });
              if (!nodesMap.has(dstId)) nodesMap.set(dstId, { id: dstId, group: 'target', name: dstId, val: 3 });
              
              const linkId = `${srcId}-${dstId}`;
              if (!linksMap.has(linkId)) linksMap.set(linkId, { source: srcId, target: dstId, value: 1 });
              else linksMap.get(linkId).value += 1;
            }
            
            // Limit sankey visually (removed > 0.6 severity limit to see all attack vectors)
            if (sankeyNodesMap.size < 40) {
                const protoName = f.traffic_type || 'Unknown';
                const portName = `Port ${f.dst_port}`;
                addSankeyLink(f.src_ip, portName, 1);
                addSankeyLink(portName, protoName, 1);
            }
          }
        });

        const sNodes = Array.from(sankeyNodesMap.keys()).map(name => ({ name }));
        
        // Recharts Sankey requires at least 2 nodes and 1 link
        if (sNodes.length > 1 && sankeyLinksArr.length > 0) {
            setSankeyData({ nodes: sNodes, links: sankeyLinksArr });
        }

        setGraphData({ 
            nodes: Array.from(nodesMap.values()), 
            links: Array.from(linksMap.values()) 
        });

        setSeverityData([
          { name: 'Critical', value: sev.Critical, color: '#ff3366' },
          { name: 'High', value: sev.High, color: '#ff9a3d' },
          { name: 'Medium', value: sev.Medium, color: '#f4c542' },
          { name: 'Low', value: sev.Low, color: '#54a6ff' }
        ]);
        
        // Calculate Encryption Protocols (from ETA overview)
        const protoData = etaRes.data.tls_distribution || [];
        const protoColors = ['#00e0ff', '#9f8fff', '#ff9a3d', '#54a6ff', '#ff3366'];
        
        setProtocolData(protoData.map((d, i) => ({
            name: d.version,
            value: d.count,
            color: protoColors[i % protoColors.length]
        })));
        
        setError(null);
        setLoading(false);
      } catch (e) {
        console.error('API Error in ThreatOverview:', e);
        if (active) {
            // Only show error on first load; if data was already loaded, keep showing it
            if (!stats) setError(true);
            setLoading(false);
        }
      }
    };
    
    fetchData();
    const interval = setInterval(fetchData, 8000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  if (loading && !stats) return <div className="loading-spinner"><div className="spinner" /></div>;

  if (error && !stats) {
    return (
      <div style={{ padding: '40px', textAlign: 'center', color: '#ff4b5c', background: 'rgba(255, 75, 92, 0.05)', borderRadius: '8px', border: '1px solid rgba(255, 75, 92, 0.2)' }}>
        <AlertTriangle size={48} style={{ margin: '0 auto 16px' }} />
        <h2 style={{ margin: '0 0 10px' }}>Backend Disconnected</h2>
        <p style={{ color: '#8d97aa' }}>Unable to establish connection with the AegisNet telemetry engine. Please ensure the backend is running (`uvicorn main:app --port 8000`).</p>
      </div>
    );
  }

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
              <Fingerprint size={20} />
            </div>
            <div>
              <div className="kpi-value" style={{ color: '#e7eefb' }}>{etaOverview?.fingerprint_diversity?.total_unique?.toLocaleString() || 0}</div>
              <div className="kpi-label">Unique Fingerprints</div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid-2">
        {/* Real-time Force Graph */}
        <div className="card glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="card-header">
            <div className="card-title">
              <Share2 size={16} style={{ color: '#00e0ff' }} />
              Threat Entity Relationship Graph
            </div>
            <span className="card-subtitle">Force-Directed Node Connections</span>
          </div>
          <div ref={graphContainerRef} style={{ flexGrow: 1, minHeight: 350, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
             {graphData.nodes.length > 0 ? (
                <div style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, overflow: 'hidden', borderRadius: '8px' }}>
                    <ForceGraph2D
                    width={graphDim.width}
                    height={graphDim.height}
                    graphData={graphData}
                    nodeRelSize={6}
                    linkColor={() => 'rgba(255,75,92,0.4)'}
                    nodeColor={node => node.group === 'attacker' ? '#ff3366' : '#54a6ff'}
                    nodeLabel="id"
                    backgroundColor="transparent"
                    d3AlphaDecay={0.02}
                    d3VelocityDecay={0.4}
                    />
                </div>
             ) : (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
                    <ShieldAlert size={32} style={{ color: '#8d97aa', opacity: 0.5 }} />
                    <span style={{ color: '#8d97aa', fontSize: '0.9rem' }}>No active network threats detected</span>
                </div>
             )}
          </div>
        </div>

        {/* Attack Vector Sankey Flow */}
        <div className="card glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="card-header">
            <div className="card-title">
              <Activity size={16} style={{ color: '#ff9a3d' }} />
              Attack Vector Flow
            </div>
            <span className="card-subtitle">Source → Target Port → Protocol</span>
          </div>
          <div style={{ flexGrow: 1, minHeight: 350, position: 'relative', marginTop: 20 }}>
            {sankeyData.nodes.length > 1 ? (
                <ResponsiveContainer width="100%" height="100%">
                <Sankey
                    data={sankeyData}
                    nodePadding={20}
                    nodeWidth={10}
                    link={{ stroke: 'rgba(159, 143, 255, 0.4)' }}
                    margin={{ top: 10, right: 20, left: 20, bottom: 10 }}
                >
                    <Tooltip content={<CustomTooltip />} />
                </Sankey>
                </ResponsiveContainer>
            ) : (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 10 }}>
                    <Activity size={32} style={{ color: '#8d97aa', opacity: 0.5 }} />
                    <span style={{ color: '#8d97aa', fontSize: '0.9rem' }}>No attack vectors detected</span>
                </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid-3" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1fr)', gap: 20 }}>
        {/* Timeline Chart */}
        <div className="card glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="card-header">
            <div className="card-title">
              <Activity size={16} style={{ color: '#00e0ff' }} />
              Ingestion Timeline
            </div>
          </div>
          <div style={{ flexGrow: 1, minHeight: 220 }}>
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
        
        {/* Severity Donut */}
        <div className="card glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="card-header" style={{ paddingBottom: 0 }}>
            <div className="card-title" style={{ fontSize: '0.9rem' }}>
              <AlertTriangle size={16} style={{ color: '#ff3366' }} />
              Alert Severity
            </div>
          </div>
          <div style={{ flexGrow: 1, minHeight: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ResponsiveContainer width="100%" height={200}>
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
              Encryption Protocol
            </div>
          </div>
          <div style={{ flexGrow: 1, minHeight: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ResponsiveContainer width="100%" height={200}>
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
  );
}
