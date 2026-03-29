import { useState, useEffect } from 'react';
import axios from 'axios';
import {
  GitBranch, Shield, Fingerprint, Crosshair, Users,
  ArrowDown, CheckCircle2, Clock, AlertTriangle, Zap
} from 'lucide-react';

export default function DetectionPipeline({ api }) {
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [moduleStats, setModuleStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [healthRes, statsRes, modulesRes] = await Promise.all([
          axios.get(`${api}/api/health`),
          axios.get(`${api}/api/stats`),
          axios.get(`${api}/api/modules?limit=200`),
        ]);
        setHealth(healthRes.data);
        setStats(statsRes.data);
        setModuleStats(modulesRes.data);
      } catch (err) {
        console.error('Pipeline fetch error:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchAll();
    const id = setInterval(fetchAll, 20000);
    return () => clearInterval(id);
  }, [api]);

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  const pipeline = health?.pipeline || {};
  const activity = moduleStats?.module_activity || {};

  const stages = [
    {
      id: 'baseline',
      label: 'Stage 0 — Baseline Anomaly',
      icon: Shield,
      description: 'University traffic baseline model for anomaly detection. Filters out normal traffic before deeper analysis.',
      status: 'coming_soon',
      color: '#6b7280',
      stats: { info: 'Training on 1-week campus traffic capture' }
    },
    {
      id: 'ja4',
      label: 'Stage 1 — JA4 + Flow Stats',
      icon: Fingerprint,
      description: 'Primary detection using JA4 fingerprints and network flow statistics. Ensemble ML model classifies traffic as malicious or benign.',
      status: pipeline.ja4_model ? 'active' : 'inactive',
      color: '#22d3ee',
      stats: {
        'Flows Analyzed': (stats?.total_flows || 0).toLocaleString(),
        'Malicious Detected': activity.ja4 || 0,
        'Model': pipeline.ja4_model ? 'Ensemble (RF + XGB)' : 'Not Loaded',
      }
    },
    {
      id: 'ttp',
      label: 'Stage 2 — TTP Classification',
      icon: Crosshair,
      description: 'Multi-label MITRE ATT&CK technique classification. Analyzes malicious flows to predict active attack techniques (T1071, T1059, etc.).',
      status: pipeline.ttp_model ? 'active' : 'inactive',
      color: '#f97316',
      stats: {
        'Flows with TTPs': moduleStats?.ttp_total_predictions || 0,
        'Unique Techniques': Object.keys(moduleStats?.ttp_technique_counts || {}).length,
        'Model': pipeline.ttp_model ? 'MLP + TruncatedSVD' : 'Not Loaded',
        'Threshold': '0.35',
      }
    },
    {
      id: 'apt',
      label: 'Stage 3 — APT Attribution',
      icon: Users,
      description: 'Per-actor APT group attribution using MITRE ATT&CK STIX similarity. Aggregates TTPs by source IP and scores against known APT campaigns.',
      status: pipeline.apt_stix ? 'active' : 'inactive',
      color: '#ef4444',
      stats: {
        'STIX Matrix': pipeline.apt_stix ? 'Loaded' : 'Not Loaded',
        'Method': 'Jaccard + Cosine Similarity',
        'Window': 'Configurable (default: 1h)',
      }
    },
  ];

  const getStatusBadge = (status) => {
    switch (status) {
      case 'active':
        return <span className="badge badge-success"><CheckCircle2 size={10} /> Active</span>;
      case 'inactive':
        return <span className="badge badge-danger"><AlertTriangle size={10} /> Inactive</span>;
      case 'coming_soon':
        return <span className="badge badge-warning"><Clock size={10} /> Coming Soon</span>;
      default:
        return <span className="badge badge-info">Unknown</span>;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      <div className="section-title" style={{ marginBottom: 20 }}>
        <GitBranch size={20} style={{ color: '#a78bfa' }} />
        Multi-Stage Detection Pipeline
      </div>

      {/* Pipeline flow */}
      <div style={{ maxWidth: 700, margin: '0 auto', width: '100%' }}>
        {stages.map((stage, index) => (
          <div key={stage.id}>
            {/* Stage Card */}
            <div className={`pipeline-stage ${stage.status === 'active' ? 'active' : stage.status === 'coming_soon' ? 'placeholder' : ''}`}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div style={{
                    width: 44, height: 44, borderRadius: 'var(--radius-md)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: `${stage.color}15`, color: stage.color,
                    border: `1px solid ${stage.color}30`,
                  }}>
                    <stage.icon size={22} />
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 15 }}>{stage.label}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2, maxWidth: 400 }}>{stage.description}</div>
                  </div>
                </div>
                {getStatusBadge(stage.status)}
              </div>

              {/* Stats grid */}
              <div style={{
                display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
                gap: 10, marginTop: 12,
              }}>
                {Object.entries(stage.stats).map(([key, val]) => (
                  <div key={key} style={{
                    background: 'var(--bg-elevated)', borderRadius: 'var(--radius-sm)',
                    padding: '10px 12px',
                  }}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>{key}</div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: stage.color }}>{val}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Connector arrow */}
            {index < stages.length - 1 && (
              <div className="pipeline-connector">
                <div style={{
                  display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '4px 0',
                }}>
                  <div style={{ width: 2, height: 16, background: 'var(--border-subtle)' }} />
                  <ArrowDown size={16} style={{
                    color: stages[index + 1].status === 'active' ? stages[index + 1].color : 'var(--text-muted)',
                  }} />
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                    {index === 0 ? 'Anomalous traffic' :
                     index === 1 ? 'Malicious flows' :
                     index === 2 ? 'TTP predictions' : ''}
                  </div>
                  <div style={{ width: 2, height: 16, background: 'var(--border-subtle)' }} />
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Pipeline Summary */}
      <div className="card" style={{ marginTop: 24 }}>
        <div className="card-header">
          <div className="card-title">
            <Zap size={16} style={{ color: '#eab308' }} />
            Pipeline Summary
          </div>
        </div>
        <div className="grid-4">
          <div style={{ textAlign: 'center', padding: 12 }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--cyan)' }}>
              {stages.filter(s => s.status === 'active').length}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Active Stages</div>
          </div>
          <div style={{ textAlign: 'center', padding: 12 }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#22d3ee' }}>
              {(stats?.total_flows || 0).toLocaleString()}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Flows Processed</div>
          </div>
          <div style={{ textAlign: 'center', padding: 12 }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#f97316' }}>
              {moduleStats?.ttp_total_predictions || 0}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>TTP Classifications</div>
          </div>
          <div style={{ textAlign: 'center', padding: 12 }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#ef4444' }}>
              {stats?.malicious_flows || 0}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Threats Detected</div>
          </div>
        </div>
      </div>
    </div>
  );
}
