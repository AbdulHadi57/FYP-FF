import { X, Shield, Clock, Activity } from 'lucide-react';

export default function FlowDetailPanel({ flow, loading, onClose }) {
  if (!flow && !loading) return null;

  const getProtoName = (protocolValue) => {
    if (protocolValue === 6) return 'TCP';
    if (protocolValue === 17) return 'UDP';
    if (protocolValue === 1) return 'ICMP';
    return protocolValue;
  };

  const features = flow?.features || {};

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(4, 8, 14, 0.72)',
        backdropFilter: 'blur(2px)',
        zIndex: 80,
        display: 'flex',
        justifyContent: 'flex-end',
      }}
      onClick={onClose}
    >
      <div
        onClick={(event) => event.stopPropagation()}
        style={{
          width: 'min(520px, 100vw)',
          height: '100vh',
          background: '#0f1520',
          borderLeft: '1px solid rgba(255,255,255,0.12)',
          boxShadow: '-20px 0 55px rgba(0,0,0,0.45)',
          padding: 20,
          overflowY: 'auto',
        }}
      >
        {loading && !flow ? (
          <div className="loading-spinner" style={{ paddingTop: 80 }}>
            <div className="spinner" />
          </div>
        ) : flow ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10 }}>
              <div>
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <Shield size={18} style={{ color: features.verdict === 'malicious' ? '#ff4b5c' : '#20c997' }} />
                  <h2 style={{ margin: 0, fontSize: 20, color: '#e8eff9' }}>Flow #{flow.id}</h2>
                  <span className={features.verdict === 'malicious' ? 'badge badge-danger' : 'badge badge-success'}>
                    {features.verdict || 'unknown'}
                  </span>
                </div>
                <div style={{ fontSize: 12, color: '#91a3bb' }}>
                  Captured: {features.timestamp ? new Date(features.timestamp).toLocaleString() : 'N/A'}
                </div>
              </div>

              <button className="btn btn-outline btn-sm" onClick={onClose}>
                <X size={14} /> Close
              </button>
            </div>

            <div className="grid-2" style={{ gap: 10 }}>
              <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 10, padding: 10 }}>
                <div style={{ fontSize: 11, color: '#8da1bc', marginBottom: 4 }}>Duration</div>
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: '#dce7f9', fontWeight: 600 }}>
                  <Clock size={13} style={{ color: '#00e0ff' }} />
                  {Number(features.flow_duration || 0).toFixed(4)}s
                </div>
              </div>

              <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 10, padding: 10 }}>
                <div style={{ fontSize: 11, color: '#8da1bc', marginBottom: 4 }}>Total Packets</div>
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: '#dce7f9', fontWeight: 600 }}>
                  <Activity size={13} style={{ color: '#00e0ff' }} />
                  {features.total_packets || 0}
                </div>
              </div>
            </div>

            <div className="card" style={{ padding: 12 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Flow Identity (5-Tuple)</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', rowGap: 6, columnGap: 8, fontSize: 12 }}>
                <div style={{ color: '#8ca0bb' }}>Source</div>
                <div className="mono" style={{ color: '#dbe7f7', textAlign: 'right' }}>{features.src_ip}:{features.src_port}</div>

                <div style={{ color: '#8ca0bb' }}>Destination</div>
                <div className="mono" style={{ color: '#dbe7f7', textAlign: 'right' }}>{features.dst_ip}:{features.dst_port}</div>

                <div style={{ color: '#8ca0bb' }}>Protocol</div>
                <div className="mono" style={{ color: '#dbe7f7', textAlign: 'right' }}>{getProtoName(features.protocol)}</div>

                {features.matched_sni_domain && features.matched_sni_domain !== 'None' && (
                  <>
                    <div style={{ color: '#8ca0bb' }}>SNI / Domain</div>
                    <div className="mono" style={{ color: '#74d8ff', textAlign: 'right', wordBreak: 'break-all' }}>{features.matched_sni_domain}</div>
                  </>
                )}
              </div>
            </div>

            <div className="card" style={{ padding: 12 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Extracted Features</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {Object.entries(features).map(([key, value]) => {
                  if ([
                    'src_ip',
                    'src_port',
                    'dst_ip',
                    'dst_port',
                    'protocol',
                    'timestamp',
                    'flow_duration',
                    'total_packets',
                    'verdict',
                    'matched_sni_domain',
                  ].includes(key)) {
                    return null;
                  }

                  if (value === null || value === undefined || value === '' || String(value).toLowerCase() === 'none') {
                    return null;
                  }

                  const rendered = typeof value === 'object'
                    ? JSON.stringify(value, null, 2)
                    : typeof value === 'boolean'
                      ? (value ? 'True' : 'False')
                      : String(value);

                  return (
                    <div key={key} style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: 8 }}>
                      <div style={{ fontSize: 11, color: '#00e0ff', marginBottom: 4 }}>{key}</div>
                      {typeof value === 'object' ? (
                        <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 12, color: '#c8d5e8', background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, padding: 8 }}>
                          {rendered}
                        </pre>
                      ) : (
                        <div className="mono" style={{ color: '#c8d5e8', wordBreak: 'break-word' }}>{rendered}</div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
