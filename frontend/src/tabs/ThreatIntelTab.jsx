import React, { useState } from 'react';
import { Network, Server, Users, Target, ShieldAlert, Cpu, ArrowRight, Zap, ChevronUp, ChevronDown, Globe, MapPin, Activity, AlertTriangle } from 'lucide-react';
import {
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, ResponsiveContainer
} from 'recharts';
import { DUMMY_APT_PROFILES, DUMMY_FLOWS } from '../utils/dummyData';

export default function ThreatIntelTab() {
  const [expandedActor, setExpandedActor] = useState(null);

  const aptProfiles = DUMMY_APT_PROFILES;
  
  // Find all malicious flows to map to the IPs
  const maliciousFlows = DUMMY_FLOWS.filter(f => f.verdict === 'malicious');

  // Kill Chain Mapping (Hardcoded simulation based on active alerts)
  const killChain = [
    { name: 'Reconnaissance', active: false, level: 0 },
    { name: 'Initial Access', active: true, level: 1 },
    { name: 'Defense Evasion', active: true, level: 2 },
    { name: 'Command & Control', active: true, level: 3 }, // Highest activity
    { name: 'Data Exfiltration', active: false, level: 0 }
  ];

  // Dummy C2 Infrastructure intelligence
  const c2Intel = [
    { asn: 'AS20473 (Choopa, LLC)', country: 'Russia (RU)', ip: '146.185.239.12', type: 'Bulletproof Host', flows: 1420, heat: '#ff3366' },
    { asn: 'AS16276 (OVH SAS)', country: 'France (FR)', ip: '192.99.14.8', type: 'Known C2 Node', flows: 890, heat: '#ff9a3d' },
    { asn: 'AS4436 (GTT Comms)', country: 'Romania (RO)', ip: '89.44.9.22', type: 'Compromised Proxy', flows: 340, heat: '#f4c542' },
    { asn: 'AS13335 (Cloudflare)', country: 'USA (US)', ip: '104.21.55.12', type: 'Domain Fronting', flows: 112, heat: '#00e0ff' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Pipeline Visualizer Header */}
      <div className="card glass-panel" style={{ padding: 20 }}>
        <h2 style={{ margin: '0 0 16px', fontSize: '1.2rem', color: '#e7eefb', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Target size={22} style={{ color: '#ff9a3d' }} />
          Threat Pipeline Attribution
        </h2>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) 30px minmax(0,1fr) 30px minmax(0,1fr) 30px minmax(0,1.2fr)', gap: 10, alignItems: 'center' }}>
          
          <div className="kpi-widget" style={{ padding: 12, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(0,224,255,0.2)', minHeight: 80 }}>
            <div style={{ color: '#00e0ff', fontSize: '0.8rem', fontWeight: 600, marginBottom: 4 }}>Step 1: Classification</div>
            <div style={{ fontSize: '0.75rem', color: '#8d97aa' }}>JA4 behavioral signatures trigger flow conviction.</div>
          </div>
          <ArrowRight size={20} style={{ color: '#00e0ff', opacity: 0.5, margin: '0 auto' }} />

          <div className="kpi-widget" style={{ padding: 12, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(159,143,255,0.2)', minHeight: 80 }}>
            <div style={{ color: '#9f8fff', fontSize: '0.8rem', fontWeight: 600, marginBottom: 4 }}>Step 2: TTP Extraction</div>
            <div style={{ fontSize: '0.75rem', color: '#8d97aa' }}>MITRE techniques parsed from payload traits.</div>
          </div>
          <ArrowRight size={20} style={{ color: '#9f8fff', opacity: 0.5, margin: '0 auto' }} />

          <div className="kpi-widget" style={{ padding: 12, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', minHeight: 80 }}>
            <div style={{ color: '#c3cedf', fontSize: '0.8rem', fontWeight: 600, marginBottom: 4 }}>Step 3: Rolling Window</div>
            <div style={{ fontSize: '0.75rem', color: '#8d97aa' }}>Aggregating behaviors by Source IP.</div>
          </div>
          <ArrowRight size={20} style={{ color: '#c3cedf', opacity: 0.5, margin: '0 auto' }} />

          <div className="kpi-widget" style={{ padding: 12, background: 'rgba(255,51,102,0.1)', border: '1px solid rgba(255,51,102,0.4)', minHeight: 80 }}>
            <div style={{ color: '#ff3366', fontSize: '0.8rem', fontWeight: 600, marginBottom: 4 }}>Step 4: STIX Attribution</div>
            <div style={{ fontSize: '0.75rem', color: '#8d97aa' }}>Matching aggregated footprints to known APTs.</div>
          </div>

        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Kill Chain Overlay */}
        <div className="card glass-panel" style={{ padding: 20, display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ margin: '0 0 16px', fontSize: '1.1rem', color: '#e7eefb', display: 'flex', alignItems: 'center', gap: 10 }}>
            <Activity size={20} style={{ color: '#ff3366' }} />
            Live Cyber Kill-Chain
          </h3>

          <div style={{ display: 'flex', justifySelf: 'stretch', justifyContent: 'space-between', alignItems: 'center', flexGrow: 1, padding: '20px 0', position: 'relative' }}>
            {/* The horizontal connection line behind the nodes */}
            <div style={{ position: 'absolute', top: '50%', left: '10%', right: '10%', height: 2, background: 'rgba(255,255,255,0.05)', zIndex: 0 }} />

            {killChain.map((stage, idx) => {
              // Level 3 = Pulse Red, Level 2 = Yellow, Level 1 = Blue/Quiet, Level 0 = Dead
              let bg = 'rgba(0,0,0,0.5)';
              let border = '1px solid rgba(255,255,255,0.05)';
              let color = '#666';
              let shadow = 'none';
              let iconColor = '#555';

              if (stage.level === 3) {
                bg = 'rgba(255,51,102,0.15)'; border = '1px solid rgba(255,51,102,0.8)'; color = '#ff3366'; shadow = '0 0 15px rgba(255,51,102,0.4)'; iconColor='#ff3366';
              } else if (stage.level === 2) {
                bg = 'rgba(255,154,61,0.1)'; border = '1px solid rgba(255,154,61,0.5)'; color = '#ff9a3d'; iconColor='#ff9a3d';
              } else if (stage.level === 1) {
                bg = 'rgba(0,224,255,0.05)'; border = '1px solid rgba(0,224,255,0.3)'; color = '#00e0ff'; iconColor='#00e0ff';
              }

              return (
                <div key={idx} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', zIndex: 1, gap: 10, width: '18%' }}>
                  <div style={{
                    width: 44, height: 44, borderRadius: '50%', background: bg, border, boxShadow: shadow,
                    display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'all 0.3s ease'
                  }}>
                    {stage.level > 0 ? <Activity size={20} style={{ color: iconColor }} /> : <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#444' }}/>}
                  </div>
                  <div style={{ fontSize: '0.75rem', fontWeight: 600, color: stage.level > 0 ? "#e7eefb" : "#666", textAlign: 'center' }}>
                    {stage.name}
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ fontSize: '0.8rem', color: '#8d97aa', textAlign: 'center', marginTop: 10 }}>
            <span style={{ color: '#ff3366', fontWeight: 'bold' }}>Command & Control</span> phase is highly active across encrypted payloads.
          </div>
        </div>

        {/* C2 Infrastructure Intelligence */}
        <div className="card glass-panel" style={{ padding: 20 }}>
          <h3 style={{ margin: '0 0 16px', fontSize: '1.1rem', color: '#e7eefb', display: 'flex', alignItems: 'center', gap: 10 }}>
            <Globe size={20} style={{ color: '#00e0ff' }} />
            Rogue C2 Infrastructure (Geo/ASN)
          </h3>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table" style={{ margin: 0 }}>
              <thead style={{ background: 'rgba(5, 8, 15, 0.95)' }}>
                <tr>
                  <th style={{ padding: '8px 10px', color: '#8d97aa' }}>Destination</th>
                  <th style={{ padding: '8px 10px', color: '#8d97aa' }}>Autonomous System</th>
                  <th style={{ padding: '8px 10px', color: '#8d97aa' }}>Geo</th>
                </tr>
              </thead>
              <tbody>
                {c2Intel.map((c2, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                    <td className="mono" style={{ color: '#00e0ff', padding: '10px' }}>
                       <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <AlertTriangle size={14} style={{ color: c2.heat }} />
                          {c2.ip}
                       </div>
                    </td>
                    <td style={{ color: '#e7eefb', fontSize: '0.85rem', padding: '10px' }}>
                       {c2.asn}<br/>
                       <span style={{ color: '#8d97aa', fontSize: '0.75rem' }}>{c2.type} &bull; {c2.flows} TLS Flows</span>
                    </td>
                    <td style={{ padding: '10px' }}>
                       <span className="badge badge-outline" style={{ borderColor: 'rgba(255,255,255,0.1)', color: '#c3cedf' }}>
                         <MapPin size={10} style={{ marginRight: 4 }}/>
                         {c2.country}
                       </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Actor Association Table */}
      <div className="card glass-panel" style={{ overflow: 'hidden', padding: 0 }}>
        <div className="card-header" style={{ padding: '16px 20px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
          <div className="card-title">
            <Users size={16} style={{ color: '#9f8fff' }} />
            Advanced Persistent Threat (APT) Matrix
          </div>
        </div>
        
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead style={{ background: 'rgba(5, 8, 15, 0.95)' }}>
              <tr>
                <th></th>
                <th>Aggressor Source IP</th>
                <th>Matched APT Profile</th>
                <th>Confidence Score</th>
                <th>Pipeline Aggregation</th>
              </tr>
            </thead>
            <tbody>
              {aptProfiles.map((actor, idx) => {
                const isExpanded = expandedActor === actor.actor_id;
                const confidenceValue = (actor.top_score * 100).toFixed(1);
                
                // Fetch the flows that built this profile
                const actorFlows = maliciousFlows.filter(f => f.src_ip === actor.actor_id);

                return (
                  <React.Fragment key={actor.actor_id}>
                    <tr 
                      className="table-row-zoom"
                      onClick={() => setExpandedActor(isExpanded ? null : actor.actor_id)}
                      style={{ background: isExpanded ? 'rgba(255,255,255,0.03)' : 'transparent', borderBottom: isExpanded ? 'none' : '' }}
                    >
                      <td style={{ textAlign: 'center', width: 40 }}>
                        {isExpanded ? <ChevronUp size={16} style={{ color: '#00e0ff' }}/> : <ChevronDown size={16} style={{ color: '#666' }}/>}
                      </td>
                      <td className="mono" style={{ color: '#00e0ff', fontWeight: 600, fontSize: '0.95rem' }}>{actor.actor_id}</td>
                      <td>
                         <span className="badge" style={{ background: 'rgba(255,51,102,0.2)', color: '#ff3366', border: '1px solid rgba(255,51,102,0.4)' }}>
                           {actor.top_match}
                         </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <div className="score-bar" style={{ width: 60 }}>
                            <div className="score-bar-fill" style={{ width: `${confidenceValue}%`, background: actor.top_score > 0.8 ? '#ff3366' : '#ff9a3d' }} />
                          </div>
                          <span style={{ fontSize: '0.8rem', color: '#e7eefb', fontWeight: 600 }}>{confidenceValue}%</span>
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 8 }}>
                          <span className="badge badge-outline"><Zap size={10} style={{ marginRight:4 }}/> {actor.flow_count} Flows Evaluated</span>
                          <span className="badge badge-purple">{actor.ttp_count} Unique TTPs</span>
                        </div>
                      </td>
                    </tr>

                    {/* Highly Detail Actor Expansion panel */}
                    {isExpanded && (
                      <tr className="expanded-row-wrapper">
                        <td colSpan={5} style={{ padding: 0, borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                          <div className={`expanded-row-container ${isExpanded ? 'open' : ''}`} style={{ padding: '0 20px 20px 60px' }}>
                            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 320px', gap: 24 }}>
                              
                              {/* Left side: Trace Logs */}
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                
                                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 16, borderRadius: 8, border: '1px solid rgba(255,255,255,0.05)' }}>
                                  <h4 style={{ margin: '0 0 12px', fontSize: '0.85rem', color: '#9f8fff', textTransform: 'uppercase', letterSpacing: 1 }}>Aggregated Indicator Traits</h4>
                                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                                    {actor.ttps.map(t => (
                                      <span key={t} className="badge badge-warning" style={{ fontSize: '0.7rem', padding: '4px 8px' }}>{t}</span>
                                    ))}
                                  </div>
                                </div>

                                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 16, borderRadius: 8, border: '1px solid rgba(255,255,255,0.05)' }}>
                                  <h4 style={{ margin: '0 0 12px', fontSize: '0.85rem', color: '#00e0ff', textTransform: 'uppercase', letterSpacing: 1 }}>Recent Window Flow Trace</h4>
                                  <div style={{ maxHeight: '160px', overflowY: 'auto' }}>
                                    {actorFlows.length > 0 ? actorFlows.map((flw, i) => {
                                      const ttpCount = flw.ttp_predictions ? JSON.parse(flw.ttp_predictions).length : 0;
                                      return (
                                        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.02)', fontSize: '0.8rem' }}>
                                          <span className="mono" style={{ color: '#e7eefb' }}>&rarr; {flw.dst_ip}:{flw.dst_port}</span>
                                          <span style={{ color: '#8d97aa' }}>{ttpCount} TTPs injected</span>
                                        </div>
                                      );
                                    }) : <div style={{ fontSize: '0.8rem', color: '#8d97aa' }}>No precise flows recorded in training dummy set.</div>}
                                  </div>
                                </div>

                              </div>

                              {/* Right side: Radar & Secondary matches */}
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '16px 0', borderRadius: 8, border: '1px solid rgba(255,51,102,0.1)', height: 260, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                                   <div style={{ color: '#ff3366', fontSize: '0.8rem', fontWeight: 600, width: '100%', paddingLeft: 16 }}>STIX Profile Intersection</div>
                                   <ResponsiveContainer width="100%" height="100%">
                                      <RadarChart cx="50%" cy="50%" outerRadius="65%" data={[
                                        { subject: 'Persistence', A: 85, fullMark: 100 },
                                        { subject: 'Evasion', A: 92, fullMark: 100 },
                                        { subject: 'Lateral', A: 45, fullMark: 100 },
                                        { subject: 'C2', A: 96, fullMark: 100 },
                                        { subject: 'Exfil', A: 50, fullMark: 100 },
                                      ]}>
                                        <PolarGrid stroke="rgba(255,255,255,0.1)" />
                                        <PolarAngleAxis dataKey="subject" tick={{ fill: '#8d97aa', fontSize: 10 }} />
                                        <Radar name="Footprint" dataKey="A" stroke="#ff3366" fill="#ff3366" fillOpacity={0.3} />
                                      </RadarChart>
                                    </ResponsiveContainer>
                                </div>

                                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 16, borderRadius: 8, border: '1px solid rgba(255,255,255,0.05)' }}>
                                  <h4 style={{ margin: '0 0 10px', fontSize: '0.8rem', color: '#8d97aa' }}>Alternative Approximations</h4>
                                  {actor.top_matches.slice(1, 4).map((match, i) => (
                                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', fontSize: '0.8rem' }}>
                                      <span style={{ color: '#c3cedf' }}>{match.apt_name}</span>
                                      <span style={{ color: '#ff9a3d' }}>{(match.combined_score * 100).toFixed(1)}%</span>
                                    </div>
                                  ))}
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
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
