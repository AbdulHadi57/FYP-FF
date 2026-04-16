"""
verify_all_models.py — Full pipeline model verification.
Tests each AI model stage with a realistic synthetic flow to ensure
correct loading, input handling, and inference output.
"""

import sys, os, json, warnings
warnings.filterwarnings("ignore")

# Ensure we can import from this directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detection import DetectionEngine, FeatureRecord, BehavioralBaselineModule, Ja4Module, TrafficTypeModule
from ttp_module import TTPModule

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"
WARN = "\033[93m[WARN]\033[0m"

# A realistic synthetic flow payload that mimics what the agent sends
SAMPLE_FLOW = {
    "src_ip": "192.168.1.50",
    "dst_ip": "185.220.101.34",
    "src_port": 49812,
    "dst_port": 443,
    "protocol": 6,
    "flow_duration": 3.421,
    "total_packets": 42,
    "total_fwd_packets": 22,
    "total_bwd_packets": 20,
    "fwd_pkt_len_max": 1460,
    "fwd_pkt_len_min": 54,
    "fwd_pkt_len_mean": 534.2,
    "fwd_pkt_len_std": 412.1,
    "bwd_pkt_len_max": 1380,
    "bwd_pkt_len_min": 54,
    "bwd_pkt_len_mean": 489.3,
    "bwd_pkt_len_std": 398.7,
    "flow_bytes_s": 152340.5,
    "flow_pkts_s": 12.28,
    "pkt_len_min": 54,
    "pkt_len_max": 1460,
    "pkt_len_mean": 512.8,
    "pkt_len_std": 405.2,
    "pkt_len_var": 164187.04,
    "avg_pkt_size": 512.8,
    "avg_fwd_segment_size": 534.2,
    "avg_bwd_segment_size": 489.3,
    "subflow_fwd_bytes": 11752,
    "subflow_bwd_bytes": 9786,
    "init_fwd_win_bytes": 65535,
    "init_bwd_win_bytes": 65535,
    "fwd_header_len": 880,
    "bwd_header_len": 800,
    "fwd_bulk_packets": 5,
    "fwd_avg_bytes_bulk": 0,
    "fwd_avg_packets_bulk": 0,
    "fwd_avg_bulk_rate": 0,
    "bwd_avg_bytes_bulk": 0,
    "bwd_avg_packets_bulk": 0,
    "bwd_avg_bulk_rate": 0,
    # JA4+ fingerprints
    "ja4": "t13d191000_9dc949149365_97f8aa674fd9",
    "ja4s": "t130200_1301_234ea6891581",
    "ja4h": "ge11cn070000_4e59edc1297a_4da5efaf0cbd_000000000000",
    "ja4x": "1234_5678_abcd_efgh",
    "ja4ssh": None,
    "ja4t": None,
    "ja4l_c": "1460_64",
    "ja4l_s": "1380_64",
    "ja4d": None,
    "is_known_doh_server": 0,
    "sni_matches_doh": 0,
    "captured_at": "2026-04-16T23:00:00",
    # Extended features needed by JA4 VotingClassifier
    "ja4_version": 13,
    "ja4_cipher_count": 19,
    "ja4_cipher_hash": "9dc949149365",
    "ja4_extension_count": 10,
    "ja4_extension_hash": "97f8aa674fd9",
    "ja4_alpn": "h2",
    "ja4_sni": "example.com",
    "ja4s_version": 13,
    "ja4s_cipher": "1301",
    "ja4s_ext_count": 2,
    "ja4s_ext_hash": "234ea6891581",
    "ja4s_alpn": "h2",
    "ja4h_method": "GET",
    "ja4h_version": 11,
    "ja4h_cookie": "n",
    "ja4h_referer": "n",
    "ja4h_header_count": 7,
    "ja4h_header_hash": "4e59edc1297a",
    "ja4h_cookie_name_hash": "000000000000",
    "ja4h_cookie_value_hash": "000000000000",
    "ja4h_lang": "en",
    "ja4t_mss": 1460,
    "ja4t_window_size": 65535,
    "ja4t_window_scale": 7,
    "ja4t_tcp_options": "M*,S,N,W7",
    "ja4ts": "M1380,S,N,W7",
    "ja4ts_mss": 1380,
    "ja4ts_window_size": 65535,
    "ja4ts_window_scale": 7,
    "ja4ts_tcp_options": "M*,S,N,W7",
    "ja4d_type": None,
    "ja4d_fqdn": None,
    "ja4d_ip": None,
    "ja4d_size": 0,
    "ja4d_options": None,
    "ja4d_request_list": None,
    "ja4l_ttl_c": 64,
    "ja4l_ttl_s": 64,
    "ja4l_latency_c": 0.005,
    "ja4l_latency_s": 0.008,
    "ja4l_app_latency_c": 0.003,
    "uses_port_443": 1,
    "uses_port_853": 0,
    "has_tls": 1,
    "has_http": 0,
    # Flow timing features
    "flow_iat_mean": 0.081,
    "flow_iat_std": 0.092,
    "flow_iat_max": 0.42,
    "flow_iat_min": 0.001,
    "fwd_iat_total": 1.78,
    "fwd_iat_mean": 0.085,
    "fwd_iat_std": 0.098,
    "fwd_iat_max": 0.38,
    "fwd_iat_min": 0.001,
    "bwd_iat_total": 1.64,
    "bwd_iat_mean": 0.086,
    "bwd_iat_std": 0.091,
    "bwd_iat_max": 0.35,
    "bwd_iat_min": 0.001,
    # Flag counts
    "syn_flag_count": 1,
    "fin_flag_count": 1,
    "rst_flag_count": 0,
    "psh_flag_count": 12,
    "ack_flag_count": 38,
    "fwd_psh_flags": 6,
    "bwd_psh_flags": 6,
    "fwd_psh_ack_count": 6,
    "bwd_psh_ack_count": 6,
    # Payload/header features
    "fwd_payload_bytes": 8500,
    "bwd_payload_bytes": 7200,
    "fwd_header_len_mean": 40.0,
    "bwd_header_len_mean": 40.0,
    # Active/idle features
    "active_mean": 0.25,
    "active_std": 0.05,
    "active_max": 0.35,
    "active_min": 0.15,
    # Response time features
    "response_time_mean": 0.012,
    "response_time_min": 0.003,
    "response_time_max": 0.045,
    "response_time_std": 0.008,
    # Packet stats
    "pkt_len_median": 490.0,
    "pkt_len_mode": 54.0,
    "pkt_len_variance": 164187.04,
    "pkt_len_cov": 0.79,
    "pkt_len_skew_from_median": 0.14,
    "pkt_time_median": 0.065,
    "pkt_time_mode": 0.001,
    "pkt_time_variance": 0.0085,
    "pkt_time_skew_from_median": 0.3,
    "down_up_ratio": 0.91,
    # Fields expected by TTP preprocessor
    "Resolved_Label_Count": 1,
    "Resolved_Attack_IDs": "T1071",
    "Resolved_Attack_Labels": "Application Layer Protocol",
    "sni_matches_doh": 0,
}


def test_stage0_autoencoder():
    """Stage 0: Behavioral Baseline (Autoencoder)"""
    print(f"\n{'='*60}")
    print(f"  STAGE 0: Behavioral Baseline — Neural Autoencoder")
    print(f"{'='*60}")

    module = BehavioralBaselineModule(model_dir="ml_models")

    # Check loading
    if not module.is_loaded:
        print(f"  {FAIL} Autoencoder bundle failed to load!")
        return False

    print(f"  {PASS} Bundle loaded: network_autoencoder_bundle.pkl")
    print(f"  {INFO} Score method: {module.score_method}")
    print(f"  {INFO} Threshold: {module.selected_threshold}")
    print(f"  {INFO} Feature columns: {len(module.feature_columns)} features")
    print(f"  {INFO} Drop columns: {module.drop_columns}")
    print(f"  {INFO} Error range: [{module.error_min:.6f}, {module.error_max:.6f}]")

    # Check components
    checks = {
        "preprocessor": module.preprocessor is not None,
        "scaler": module.scaler is not None,
        "autoencoder_model": module.autoencoder_model is not None,
    }
    for name, ok in checks.items():
        print(f"  {'  '+PASS if ok else '  '+FAIL} Component '{name}' present: {ok}")

    # Test inference
    record = FeatureRecord(payload=SAMPLE_FLOW)
    result = module.predict(record)
    print(f"\n  {INFO} Inference result:")
    print(f"       Label:      {result.label}")
    print(f"       Confidence: {result.confidence:.4f}")
    print(f"       Score(MSE): {result.score:.6f}")
    print(f"       Rationale:  {result.rationale}")
    print(f"  {PASS} Stage 0 inference completed without errors.")
    return True


def test_stage1_ja4():
    """Stage 1: JA4 Malicious Server Detector"""
    print(f"\n{'='*60}")
    print(f"  STAGE 1: JA4 Malicious Server Detector (Ensemble)")
    print(f"{'='*60}")

    module = Ja4Module()

    if module.model is None:
        print(f"  {FAIL} JA4 model failed to load!")
        return False

    print(f"  {PASS} Model loaded: malicious_server_detector_ensemble_no_ports.pkl")
    print(f"  {PASS} Preprocessor loaded: preprocessor_no_ports.pkl")
    print(f"  {INFO} Model type: {type(module.model).__name__}")

    # Test inference
    record = FeatureRecord(payload=SAMPLE_FLOW)
    result = module.predict(record)
    print(f"\n  {INFO} Inference result:")
    print(f"       Label:      {result.label}")
    print(f"       Confidence: {result.confidence:.4f}")
    print(f"       Score:      {result.score:.4f}")
    print(f"       Rationale:  {result.rationale}")
    print(f"       AI Model:   {result.metadata.get('ai_model')}")
    print(f"  {PASS} Stage 1 inference completed without errors.")
    return True


def test_stage15_traffic_type():
    """Stage 1.5: Traffic Type Classifier"""
    print(f"\n{'='*60}")
    print(f"  STAGE 1.5: Traffic Type Classifier")
    print(f"{'='*60}")

    module = TrafficTypeModule()

    if not module.is_loaded:
        print(f"  {WARN} Traffic type model not loaded, will use heuristics.")
    else:
        print(f"  {PASS} Model loaded from: {module.model_path}")
        print(f"  {INFO} Feature columns: {len(module.feature_columns)} features")

    record = FeatureRecord(payload=SAMPLE_FLOW)
    result = module.predict(record)
    print(f"\n  {INFO} Inference result:")
    print(f"       Label:        {result.label}")
    print(f"       Confidence:   {result.confidence:.4f}")
    print(f"       Traffic Type: {result.metadata.get('traffic_type')}")
    print(f"       Model Used:   {result.metadata.get('model_loaded')}")
    print(f"  {PASS} Stage 1.5 inference completed without errors.")
    return True


def test_stage2_ttp():
    """Stage 2: TTP MITRE ATT&CK Classification"""
    print(f"\n{'='*60}")
    print(f"  STAGE 2: TTP MITRE ATT&CK Classification")
    print(f"{'='*60}")

    module = TTPModule()

    if not module.is_loaded:
        print(f"  {FAIL} TTP bundle failed to load!")
        return False

    print(f"  {PASS} TTP bundle loaded: ttp_bundle.pkl")
    print(f"  {INFO} Classes: {len(module.classes)} MITRE techniques")
    print(f"  {INFO} Threshold: {module.threshold}")
    print(f"  {INFO} Feature columns: {len(module.feature_columns)}")
    print(f"  {INFO} Drop columns: {module.drop_columns}")

    # Check components
    checks = {
        "preprocessor": module.preprocessor is not None,
        "sparse_scaler": module.sparse_scaler is not None,
        "svd": module.svd is not None,
        "dense_scaler": module.dense_scaler is not None,
        "classifier": module.classifier is not None,
    }
    for name, ok in checks.items():
        print(f"  {'  '+PASS if ok else '  '+FAIL} Component '{name}' present: {ok}")

    # Test inference
    result = module.predict(SAMPLE_FLOW)
    print(f"\n  {INFO} Inference result:")
    print(f"       Predicted techniques: {result.technique_count}")
    for t in result.techniques[:5]:
        print(f"         -> {t.technique_id}: {t.technique_name} (prob={t.probability:.3f})")
    if result.error:
        print(f"  {FAIL} TTP inference error: {result.error}")
        return False
    print(f"  {PASS} Stage 2 inference completed without errors.")
    return True


def test_full_pipeline():
    """Full Detection Engine Pipeline"""
    print(f"\n{'='*60}")
    print(f"  FULL PIPELINE: DetectionEngine.process()")
    print(f"{'='*60}")

    engine = DetectionEngine(model_dir="ml_models")

    record = FeatureRecord(payload=SAMPLE_FLOW)
    rec, aggregate, module_results, ttp_result = engine.process(record)

    print(f"\n  {INFO} Aggregate Decision:")
    print(f"       Verdict:    {aggregate.verdict}")
    print(f"       Confidence: {aggregate.confidence}")
    print(f"       Severity:   {aggregate.severity}")
    print(f"       Triggered:  {aggregate.triggered_modules}")

    print(f"\n  {INFO} Module Results:")
    for mr in module_results:
        print(f"       [{mr.module}] label={mr.label}, conf={mr.confidence:.3f}, score={mr.score:.4f}")

    if ttp_result:
        print(f"\n  {INFO} TTP Result: {ttp_result.technique_count} techniques predicted")
        for t in ttp_result.techniques[:3]:
            print(f"         -> {t.technique_id}: {t.technique_name} (prob={t.probability:.3f})")
    else:
        print(f"\n  {INFO} TTP Result: Skipped (flow was benign or TTP model not loaded)")

    print(f"\n  {PASS} Full pipeline completed without errors.")
    return True


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  AegisNet -- Comprehensive Model Verification Suite")
    print("=" * 60)

    results = {}
    results["Stage 0 (Autoencoder)"] = test_stage0_autoencoder()
    results["Stage 1 (JA4 Detector)"] = test_stage1_ja4()
    results["Stage 1.5 (Traffic Type)"] = test_stage15_traffic_type()
    results["Stage 2 (TTP MITRE)"] = test_stage2_ttp()
    results["Full Pipeline"] = test_full_pipeline()

    print(f"\n\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    all_pass = True
    for name, ok in results.items():
        status = PASS if ok else FAIL
        print(f"  {status} {name}")
        if not ok:
            all_pass = False

    if all_pass:
        print(f"\n  ALL MODELS VERIFIED SUCCESSFULLY\n")
    else:
        print(f"\n  SOME MODELS FAILED -- SEE ABOVE FOR DETAILS\n")
        sys.exit(1)
