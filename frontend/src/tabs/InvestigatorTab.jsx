import React, { useState, useMemo } from 'react';
import { Database, Search, AlertTriangle, ShieldCheck, ChevronRight, Activity, Terminal, HelpCircle } from 'lucide-react';
import { DUMMY_FLOWS } from '../utils/dummyData';

export default function InvestigatorTab() {
  const [expandedFlow, setExpandedFlow] = useState(null);
  const [omnibarQuery, setOmnibarQuery] = useState('verdict="malicious" AND ttp="T"');

  // Compute active filtered flows using custom SIEM parser
  const filteredFlows = useMemo(() => {
    return DUMMY_FLOWS.filter(flow => {
      if (!omnibarQuery.trim()) return true;
      
      const flowStr = JSON.stringify(flow).toLowerCase();
      let feats = {};
      try { feats = JSON.parse(flow.features_json || '{}'); } catch(e) {};
      const apts = flow.apt_matches ? JSON.parse(flow.apt_matches) : [];

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
          else if (targetKey === 'apt') actualValue = apts.length > 0 ? apts[0].apt_name : '';
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
               placeholder='e.g., ja4="abcdef" AND apt="Lazarus" AND NOT ip="192.168.1.1"'
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
            <span><strong>Available Keys:</strong> <code style={{ color: '#00e0ff' }}>ja4=</code>, <code style={{ color: '#00e0ff' }}>verdict=</code>, <code style={{ color: '#00e0ff' }}>ip=</code>, <code style={{ color: '#00e0ff' }}>sni=</code>, <code style={{ color: '#00e0ff' }}>ttp=</code>, <code style={{ color: '#00e0ff' }}>apt=</code></span>
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
                const apts = flow.apt_matches ? JSON.parse(flow.apt_matches) : [];
                
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
                                  <Database size={14} /> Associated Attacker Profile (APT)
                                </h4>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                                  {apts.length > 0 ? (
                                    <>
                                      <div><span style={{ color: '#8d97aa', fontSize: '0.75rem' }}>Predicted Actor Match:</span><br/>
                                        <span className="badge badge-purple" style={{ marginTop: 4, display: 'inline-block' }}>{apts[0].apt_name}</span>
                                      </div>
                                      <div><span style={{ color: '#8d97aa', fontSize: '0.75rem' }}>STIX Profile Intersection Match:</span><br/>
                                        <span className="mono" style={{ color: '#e7eefb' }}>{Math.round(apts[0].combined_score * 100)}% STIX Overlay</span>
                                      </div>
                                    </>
                                  ) : (
                                    <div style={{ color: '#666', fontSize: '0.8rem', fontStyle: 'italic', marginTop: 10 }}>No high-confidence APT attributions associated with this localized flow event. Requires broader window aggregation.</div>
                                  )}
                                </div>
                              </div>
                              
                            </div>
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
