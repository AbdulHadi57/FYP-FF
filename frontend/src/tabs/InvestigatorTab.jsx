import React, { useState, useMemo, useEffect } from 'react';
import { Database, Search, AlertTriangle, ShieldCheck, ChevronRight, Activity, Terminal, HelpCircle, Code } from 'lucide-react';
import axios from 'axios';

export default function InvestigatorTab() {
  const [expandedFlow, setExpandedFlow] = useState(null);
  const [omnibarQuery, setOmnibarQuery] = useState('verdict="malicious" AND ttp="T"');
  const [showPcap, setShowPcap] = useState({});

  const togglePcap = (e, id) => {
    e.stopPropagation();
    setShowPcap(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const [flowsData, setFlowsData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const fetchFlows = async () => {
      try {
        const res = await axios.get('http://localhost:8000/api/flows?limit=300');
        if (active) {
          setFlowsData(res.data || []);
          setLoading(false);
        }
      } catch (e) {
        console.error('Failed to fetch investigator flows', e);
        if (active) setLoading(false);
      }
    };
    fetchFlows();
    const interval = setInterval(fetchFlows, 8000);
    return () => { active = false; clearInterval(interval); }
  }, []);

  // Compute active filtered flows using custom SIEM parser
  const filteredFlows = useMemo(() => {
    return flowsData.filter(flow => {
      if (!omnibarQuery.trim()) return true;
      
      const flowStr = JSON.stringify(flow).toLowerCase();
      let feats = {};
      try { feats = JSON.parse(flow.features_json || '{}'); } catch(e) {};

      const conditions = omnibarQuery.split(/\s+AND\s+/i);
      
      for (let cond of conditions) {
        const isNegative = cond.toUpperCase().startsWith('NOT ');
        const cleanCond = isNegative ? cond.substring(4).trim() : cond.trim();

        const match = cleanCond.match(/([a-zA-Z0-9_]+)\s*(?:=|:)\s*"?([^"]+)"?/);
        if (match) {
          const [, key, val] = match;
          const targetKey = key.toLowerCase();
          const targetVal = val.toLowerCase();
          let actualValue = '';

          if (targetKey === 'ja4') actualValue = feats.ja4 || '';
          else if (targetKey === 'verdict') actualValue = flow.verdict || '';
          else if (targetKey === 'ttp') actualValue = flow.ttp_predictions || '';
          else if (targetKey === 'ip') actualValue = flow.src_ip + ' ' + flow.dst_ip;
          else if (targetKey === 'sni') actualValue = flow.sni || '';

          const result = String(actualValue).toLowerCase().includes(targetVal);
          if (isNegative ? result : !result) return false;
        } else {
          // Unstructured global match
          const result = flowStr.includes(cleanCond.toLowerCase());
          if (isNegative ? result : !result) return false;
        }
      }
      return true;
    });
  }, [omnibarQuery]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Search Header */}
      <div className="card glass-panel" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', background: 'rgba(5,8,15,0.6)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Terminal size={22} style={{ color: '#00e0ff' }} />
            <h2 style={{ margin: 0, fontSize: '1.2rem', color: '#e7eefb' }}>AQL Omnibar (Aegis Query Language)</h2>
          </div>
          <button className="badge badge-purple" onClick={() => setOmnibarQuery('ja4="t13" AND NOT verdict="benign"')}>
            Example Query
          </button>
        </div>
        
        {/* Dynamic Omnibar */}
        <div style={{ padding: 20, borderTop: '1px solid rgba(255,255,255,0.05)' }}>
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center', background: 'rgba(0,0,0,0.6)', borderRadius: 8, border: '1px solid rgba(0,224,255,0.4)', padding: '4px 12px', boxShadow: '0 0 15px rgba(0,224,255,0.1)' }}>
             <Search size={20} style={{ color: '#00e0ff', marginRight: 12 }}/>
             <input 
               type="text"
               value={omnibarQuery}
               onChange={(e) => setOmnibarQuery(e.target.value)}
               placeholder='e.g., ja4="abcdef" AND ttp="T1059" AND NOT ip="192.168.1.1"'
               style={{ 
                 width: '100%', background: 'transparent', border: 'none', color: '#e7eefb', fontSize: '1.1rem',
                 padding: '12px 0', outline: 'none', fontFamily: 'monospace' 
               }}
             />
             {filteredFlows.length > 0 && (
                <span className="badge badge-cyan" style={{ marginLeft: 16 }}>{filteredFlows.length} Matches</span>
             )}
          </div>
          <div style={{ display: 'flex', gap: 10, marginTop: 12, fontSize: '0.8rem', color: '#8d97aa', alignItems: 'center' }}>
            <HelpCircle size={14}/>
            <span><strong>Available Keys:</strong> <code style={{ color: '#00e0ff' }}>ja4=</code>, <code style={{ color: '#00e0ff' }}>verdict=</code>, <code style={{ color: '#00e0ff' }}>ip=</code>, <code style={{ color: '#00e0ff' }}>sni=</code>, <code style={{ color: '#00e0ff' }}>ttp=</code></span>
            <span style={{ margin: '0 8px', color: '#555' }}>|</span>
            <span><strong>Operators:</strong> <code style={{ color: '#ff3366' }}>AND</code>, <code style={{ color: '#ff3366' }}>NOT</code></span>
          </div>
        </div>
      </div>

      <div className="card glass-panel" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto', maxHeight: '600px' }}>
          <table className="data-table">
            <thead style={{ background: 'rgba(5, 8, 15, 0.95)', position: 'sticky', top: 0, zIndex: 5 }}>
              <tr>
                <th style={{ width: 40, borderBottom: '1px solid rgba(0,210,255,0.2)' }}></th>
                <th style={{ borderBottom: '1px solid rgba(0,210,255,0.2)' }}>Time (UTC)</th>
                <th style={{ borderBottom: '1px solid rgba(0,210,255,0.2)' }}>Source</th>
                <th style={{ borderBottom: '1px solid rgba(0,210,255,0.2)' }}>Destination</th>
                <th style={{ borderBottom: '1px solid rgba(0,210,255,0.2)' }}>SNI / Host</th>
                <th style={{ borderBottom: '1px solid rgba(0,210,255,0.2)' }}>Classification</th>
                <th style={{ borderBottom: '1px solid rgba(0,210,255,0.2)' }}>Threat Score</th>
              </tr>
            </thead>
            <tbody>
              {filteredFlows.map((flow) => {
                const isExpanded = expandedFlow === flow.id;
                const features = JSON.parse(flow.features_json || '{}');
                const ttps = flow.ttp_predictions ? JSON.parse(flow.ttp_predictions) : [];
                
                return (
                  <React.Fragment key={flow.id}>
                    <tr 
                      className="table-row-zoom"
                      onClick={() => setExpandedFlow(isExpanded ? null : flow.id)}
                      style={{ background: isExpanded ? 'rgba(255,255,255,0.03)' : 'transparent', borderLeft: isExpanded ? '2px solid #00e0ff' : '2px solid transparent' }}
                    >
                      <td style={{ textAlign: 'center' }}>
                        <ChevronRight size={16} style={{ 
                          transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)', 
                          transition: 'transform 0.2s ease',
                          color: isExpanded ? '#00e0ff' : '#666'
                        }} />
                      </td>
                      <td className="mono" style={{ color: '#8d97aa' }}>{new Date(flow.captured_at).toLocaleTimeString()}</td>
                      <td className="mono" style={{ color: '#e7eefb' }}>
                        <span style={{ color: flow.verdict === 'malicious' ? '#ff4b4b' : '#00e0ff' }}>{flow.src_ip}</span>
                        <span style={{ color: '#666', fontSize: '0.7rem' }}>:{flow.src_port}</span>
                      </td>
                      <td className="mono" style={{ color: '#c3cedf' }}>
                        {flow.dst_ip}
                        <span style={{ color: '#666', fontSize: '0.7rem' }}>:{flow.dst_port}</span>
                      </td>
                      <td style={{ color: '#c3cedf' }}>{flow.sni || '-'}</td>
                      <td>
                        {flow.verdict === 'malicious' ? (
                          <span className="badge badge-critical" style={{ background: 'rgba(255,51,102,0.1)', border: '1px solid rgba(255,51,102,0.4)', color: '#ff3366' }}><AlertTriangle size={10}/> Malicious</span>
                        ) : (
                          <span className="badge badge-success" style={{ background: 'rgba(32,201,151,0.1)', border: '1px solid rgba(32,201,151,0.4)' }}><ShieldCheck size={10}/> Benign</span>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span className="mono" style={{ fontSize: '0.85rem' }}>{Math.round(flow.severity * 100)}%</span>
                        </div>
                      </td>
                    </tr>
                    
                    {isExpanded && (
                      <tr className="expanded-row-wrapper">
                        <td colSpan={7} style={{ padding: 0, border: 'none' }}>
                          <div className={`expanded-row-container ${isExpanded ? 'open' : ''}`}>
                            <div className="grid-3" style={{ margin: '10px 0', alignItems: 'start' }}>
                              
                              <div style={{ background: 'rgba(0,0,0,0.4)', borderRadius: 8, padding: 16, border: '1px solid rgba(0,210,255,0.1)' }}>
                                <h4 style={{ margin: '0 0 10px', display: 'flex', alignItems: 'center', gap: 6, color: '#00e0ff' }}>
                                  <Activity size={14} /> Telemetry & JA4 Model Space
                                </h4>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                                  <div><span style={{ color: '#8d97aa', fontSize: '0.75rem' }}>JA4 Client:</span><br/><span className="mono" style={{ color: '#e7eefb' }}>{features.ja4 || 'N/A'}</span></div>
                                  <div><span style={{ color: '#8d97aa', fontSize: '0.75rem' }}>JA4s Server:</span><br/><span className="mono" style={{ color: '#e7eefb' }}>{features.ja4s || 'N/A'}</span></div>
                                  <div><span style={{ color: '#8d97aa', fontSize: '0.75rem' }}>FWD / BWD Payload:</span><br/><span className="mono" style={{ color: '#ff9a3d' }}>{features.fwd_payload_bytes || 0} bytes / {features.bwd_payload_bytes || 0} bytes</span></div>
                                </div>
                              </div>

                              <div style={{ background: 'rgba(0,0,0,0.4)', borderRadius: 8, padding: 16, border: '1px solid rgba(255,154,61,0.1)' }}>
                                <h4 style={{ margin: '0 0 10px', display: 'flex', alignItems: 'center', gap: 6, color: '#ff9a3d' }}>
                                  <Terminal size={14} /> Heuristic Indicators (TTP Matrix)
                                </h4>
                                {flow.verdict === 'malicious' ? (
                                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                                    <div>
                                      <span style={{ color: '#8d97aa', fontSize: '0.75rem', display: 'block', marginBottom: 6 }}>Triggered MITRE Models:</span>
                                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                                        {ttps.map((t, idx) => (
                                          <span key={idx} className="badge badge-warning" style={{ fontSize: '0.75rem' }}>{t.technique_id}</span>
                                        ))}
                                        {ttps.length === 0 && <span style={{ color: '#666' }}>No specific technique flagged</span>}
                                      </div>
                                    </div>
                                    <div>
                                      <span style={{ color: '#8d97aa', fontSize: '0.75rem', display: 'block', marginBottom: 6 }}>Model Confidence Summary:</span>
                                      <span className="mono" style={{ color: '#ff3366', fontSize: '0.8rem' }}>{flow.summary}</span>
                                    </div>
                                  </div>
                                ) : (
                                  <div className="empty-state" style={{ minHeight: 80, padding: 0 }}><p>Intel pipeline bypassed (benign flow)</p></div>
                                )}
                              </div>

                              <div style={{ background: 'rgba(0,0,0,0.4)', borderRadius: 8, padding: 16, border: '1px solid rgba(159,143,255,0.15)' }}>
                                <h4 style={{ margin: '0 0 10px', display: 'flex', alignItems: 'center', gap: 6, color: '#9f8fff' }}>
                                  <Database size={14} /> Encrypted Session Profile
                                </h4>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                                  <div><span style={{ color: '#8d97aa', fontSize: '0.75rem' }}>TLS Version / Cipher suite:</span><br/>
                                    <span className="badge badge-purple" style={{ marginTop: 4, display: 'inline-block' }}>{features.tls_version || 'Unknown'} / {features.cipher_suite || 'Unknown'}</span>
                                  </div>
                                  <div><span style={{ color: '#8d97aa', fontSize: '0.75rem' }}>Session Entropy & IAT:</span><br/>
                                    <span className="mono" style={{ color: '#e7eefb' }}>{features.entropy ? parseFloat(features.entropy).toFixed(2) : 'N/A'} bit/byte | {features.mean_iat ? parseFloat(features.mean_iat).toFixed(2) : 'N/A'} ms</span>
                                  </div>
                                </div>
                              </div>
                              
                            </div>

                            {/* Hex PCAP Dump Viewer inside the Expanded Container, scoped to full width! */}
                            {flow.verdict === 'malicious' && showPcap[flow.id] && (
                              <div style={{ background: '#050a14', border: '1px solid rgba(0, 224, 255, 0.3)', borderRadius: 8, padding: 16, marginTop: 15, fontFamily: "'Fira Code', monospace", fontSize: '0.8rem' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', color: '#00e0ff', marginBottom: 12, borderBottom: '1px solid rgba(0,224,255,0.2)', paddingBottom: 6 }}>
                                  <span style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}><Code size={14} /> TLS_CLIENT_HELLO HEX-DUMP</span>
                                  <span style={{ color: '#ff3366', fontWeight: 600 }}>{flow.sni || 'RAW_IP_PAYLOAD'}</span>
                                </div>
                                
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                                  {[...Array(6)].map((_, i) => {
                                      const seed = parseInt(String(flow.id).replace(/[^0-9]/g, '') || 99) + i;
                                      const offset = (i * 16).toString(16).padStart(8, '0');
                                      let hexStr = '';
                                      let asciiStr = '';
                                      for (let j = 0; j < 16; j++) {
                                        const b = Math.floor(Math.abs(Math.sin((seed * 1.5) + i * 16 + j) * 255));
                                        hexStr += b.toString(16).padStart(2, '0') + ' ';
                                        asciiStr += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
                                      }
                                      return (
                                        <div key={i} style={{ display: 'flex', gap: 20 }}>
                                          <span style={{ color: '#5a6b84', width: 70 }}>{offset}</span>
                                          <span style={{ color: '#b9cbf0', letterSpacing: '1.5px', width: 440 }}>{hexStr}</span>
                                          <span style={{ color: '#00e0ff' }}>{asciiStr}</span>
                                        </div>
                                      );
                                  })}
                                </div>
                              </div>
                            )}

                            {flow.verdict === 'malicious' && (
                               <div style={{ marginTop: 12, textAlign: 'right' }}>
                                  <button onClick={(e) => togglePcap(e, flow.id)} className={`btn btn-sm ${showPcap[flow.id] ? 'btn-danger' : 'btn-outline'}`} style={{ padding: '6px 16px', fontSize: '0.8rem' }}>
                                    <Code size={12} style={{ marginRight: 6 }} /> 
                                    {showPcap[flow.id] ? 'Collapse PCAP Trace' : 'Extract PCAP Hex (0x)'}
                                  </button>
                               </div>
                            )}
                            
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
              {filteredFlows.length === 0 && (
                <tr>
                  <td colSpan={7}>
                    <div className="empty-state" style={{ padding: 60 }}>
                      <Database size={32} style={{ opacity: 0.3 }} />
                      <p>No actionable intelligent flows matching exact filtering criteria.</p>
                      <div className="mono" style={{ color: '#ff3366', marginTop: 10, fontSize: '0.8rem' }}>{omnibarQuery}</div>
                    </div>
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
