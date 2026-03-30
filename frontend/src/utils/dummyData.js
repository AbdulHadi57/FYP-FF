export const DUMMY_STATS = {
  total_flows: 14205,
  malicious_flows: 345,
  avg_severity: 0.85,
  top_source: "192.168.1.105",
  top_attackers: [
    { ip: "192.168.1.105", count: 124 },
    { ip: "10.0.0.45", count: 87 },
    { ip: "172.16.0.12", count: 42 }
  ],
  last_flow_timestamp: new Date().toISOString()
};

export const DUMMY_MODULES = {
  ja4_diversity: 145,
  ja4s_diversity: 89,
  top_ja4: [
    { ja4: "t13d1516h2_8a2d1d05b5_e7c9f80a2b", count: 450, app: "Cobalt Strike Malleable C2 Loader", threat_level: 98, category: "Command and Control" },
    { ja4: "t12d1908h2_c9b4a1_1234567890", count: 320, app: "Python 3.10 urllib (Non-Standard)", threat_level: 75, category: "Suspicious Exfiltration" },
    { ja4: "t13d1007h1_f8c9b4_0987654321", count: 210, app: "Metasploit Meterpreter Reverse HTTPS", threat_level: 96, category: "Remote Access Trojan" },
    { ja4: "t13d1007h1_f8c9b4_1223455666", count: 180 }
  ],
  top_ja4s: [
    { ja4: "t130100_e7c9f80a2b_8a2d1d05b5", count: 180, app: "Known Bad Server Configuration", threat_level: 90, category: "Malicious Infrastructure" },
    { ja4: "s4d_ff14_abc123", count: 142, app: "Apache HTTP Server 2.4", threat_level: 60, category: "Vulnerable Infrastructure" },
    { ja4: "t130300_0987654321_f8c9b4", count: 95 }
  ],
  ja4_malicious_count: 345,
  ja4_benign_count: 13860,
  threat_status_distribution: { open: 120, resolved: 225 },
  module_activity: { ja4: 345, ttp: 210, apt: 45 },
  ttp_total_predictions: 210,
  ttp_top_techniques: [
    { id: "T1190", name: "Exploit Public-Facing App", count: 45, pct: 21.4 },
    { id: "T1071", name: "App Layer Protocol", count: 35, pct: 16.6 },
    { id: "T1573", name: "Encrypted Channel", count: 30, pct: 14.2 },
    { id: "T1059", name: "Command and Scripting", count: 25, pct: 11.9 }
  ]
};

export const DUMMY_TIMELINE = Array.from({ length: 60 }).map((_, i) => ({
  bucket: new Date(Date.now() - (60 - i) * 60000).toISOString(),
  flow_count: Math.floor(Math.random() * 500) + 100,
  malicious_count: Math.floor(Math.random() * 20),
}));

export const DUMMY_FLOWS = Array.from({ length: 20 }).map((_, i) => {
  const isMalicious = i < 5;
  const ttpArray = isMalicious ? [{ technique_id: "T1190", technique_name: "Exploit Public-Facing App" }, { technique_id: "T1573", technique_name: "Encrypted Channel" }] : null;
  const aptMatch = isMalicious ? "APT29 (Cozy Bear)" : null;
  return {
    id: 1000 + i,
    captured_at: new Date(Date.now() - i * 15000).toISOString(),
    src_ip: isMalicious ? "192.168.1.105" : `10.0.0.${10 + i}`,
    src_port: Math.floor(Math.random() * 60000) + 1024,
    dst_ip: isMalicious ? "8.8.8.8" : "192.168.1.1",
    dst_port: isMalicious ? 443 : 80,
    protocol: 6,
    total_packets: Math.floor(Math.random() * 1000) + 10,
    flow_duration: Math.random() * 120,
    verdict: isMalicious ? "malicious" : "benign",
    severity: isMalicious ? 0.85 + Math.random() * 0.1 : 0.1,
    confidence: isMalicious ? 0.92 : 0.99,
    ja4_pred: isMalicious ? "malicious" : "benign",
    ttp_predictions: ttpArray ? JSON.stringify(ttpArray) : null,
    apt_matches: aptMatch ? JSON.stringify([{ apt_name: aptMatch, combined_score: 0.88 }]) : null,
    summary: isMalicious ? "High-risk fingerprint match with C2 traits" : "Normal web traffic",
    sni: isMalicious ? "update.evil.com" : "google.com",
    features_json: JSON.stringify({
      ja4: "t13d1516h2_8a2d1d05b5_e7c9f80a2b",
      ja4s: "t130100_e7c9f80a2b_8a2d1d05b5",
      fwd_payload_bytes: 540,
      bwd_payload_bytes: 12050,
      syn_flag_count: 1,
      fin_flag_count: 1
    })
  };
});

export const DUMMY_APT_PROFILES = [
  {
    actor_id: "192.168.1.105",
    flow_count: 124,
    ttp_count: 5,
    ttps: ["T1190", "T1071", "T1573", "T1059", "T1090"],
    top_match: "APT29 (Cozy Bear)",
    top_score: 0.8821,
    top_matches: [
      { apt_name: "APT29 (Cozy Bear)", combined_score: 0.8821, jaccard: 0.65, cosine: 0.72 },
      { apt_name: "Lazarus Group", combined_score: 0.6512, jaccard: 0.45, cosine: 0.55 }
    ]
  },
  {
    actor_id: "10.0.0.45",
    flow_count: 87,
    ttp_count: 3,
    ttps: ["T1078", "T1021", "T1098"],
    top_match: "FIN7",
    top_score: 0.7512,
    top_matches: [
      { apt_name: "FIN7", combined_score: 0.7512, jaccard: 0.55, cosine: 0.62 },
      { apt_name: "Sandworm Team", combined_score: 0.4211, jaccard: 0.31, cosine: 0.45 }
    ]
  }
];

export const DUMMY_AGENTS = [
  { id: "agt_1a2b3c", hostname: "WIN-WKSTN-01", status: "online", last_seen: new Date().toISOString() },
  { id: "agt_4d5e6f", hostname: "LNX-SRV-05", status: "online", last_seen: new Date().toISOString() },
  { id: "agt_7g8h9i", hostname: "WIN-EXEC-02", status: "offline", last_seen: new Date(Date.now() - 3600000).toISOString() }
];

export const DUMMY_DCS = [
  { id: "dc_alpha", hostname: "DC01-HQ", approval_status: "approved", status: "online" }
];

export const DUMMY_ACTIONS = [
  {
    id: "act_1001", target_type: "agent", target_id: "agt_1a2b3c", action_type: "isolate_host", status: "completed", 
    requested_by: "analyst1", created_at: new Date(Date.now() - 300000).toISOString()
  },
  {
    id: "act_1002", target_type: "agent", target_id: "agt_1a2b3c", action_type: "restore_host", status: "queued", 
    requested_by: "analyst1", created_at: new Date().toISOString()
  }
];

export const DUMMY_AUDITS = [
  {
    id: 5001, action_id: "act_1001", job_action_type: "isolate_host", event_type: "dispatched", actor: "system", 
    target_info: "WIN-WKSTN-01", job_status: "succeeded", details: { note: "High confidence ML baseline breach" }, created_at: new Date(Date.now() - 2900000).toISOString()
  },
  {
    id: 5002, action_id: "act_1002", job_action_type: "restore_host", event_type: "rollback_requested", actor: "analyst1", 
    target_info: "WIN-WKSTN-01", job_status: "succeeded", details: { note: "False positive confirmed." }, created_at: new Date(Date.now() - 2800000).toISOString()
  },
  {
    id: 5003, action_id: null, job_action_type: "dc_approved", event_type: "dc_approved", actor: "admin_root", 
    target_info: "DC01-HQ", job_status: "completed", details: { dc_id: "dc_alpha", ip: "172.16.0.5" }, created_at: new Date(Date.now() - 1500000).toISOString()
  },
  {
    id: 5004, action_id: null, job_action_type: "agent_removed", event_type: "dc_deleted", actor: "admin_root", 
    target_info: "LNX-SRV-05", job_status: "completed", details: { agent_id: "agt_4d5e6f", reason: "Server deprecated" }, created_at: new Date(Date.now() - 500000).toISOString()
  },
  {
    id: 5005, action_id: "act_1005", job_action_type: "isolate_host", event_type: "dispatched", actor: "analyst2", 
    target_info: "WIN-EXEC-02", job_status: "failed", details: { note: "Agent not responding to isolation command." }, created_at: new Date().toISOString()
  }
];
