from __future__ import annotations

import json
import logging
import random
import os
import joblib
import pandas as pd
import numpy as np
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import torch
import torch.nn as nn

from ttp_module import TTPModule, TTPResult
from apt_attribution import APTAttributionModule, ActorAttribution

logger = logging.getLogger("AegisNet.Detection")


@dataclass
class FeatureRecord:
    """Lightweight view over the raw feature dictionary."""

    payload: Dict

    @property
    def src_ip(self) -> str:
        return str(self.payload.get("src_ip", "0.0.0.0"))

    @property
    def dst_ip(self) -> str:
        return str(self.payload.get("dst_ip", "0.0.0.0"))

    @property
    def src_port(self) -> int:
        value = self.payload.get("src_port")
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    @property
    def dst_port(self) -> int:
        value = self.payload.get("dst_port")
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    @property
    def protocol(self) -> int:
        value = self.payload.get("protocol")
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    @property
    def flow_duration(self) -> float:
        value = self.payload.get("flow_duration")
        try:
            return float(value) if value is not None else 0.0
        except (TypeError, ValueError):
            return 0.0

    @property
    def total_packets(self) -> int:
        value = self.payload.get("total_packets")
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0


@dataclass
class DetectionResult:
    module: str
    label: str
    confidence: float
    rationale: str
    score: float
    metadata: Dict = field(default_factory=dict)


@dataclass
class AggregateDecision:
    verdict: str
    confidence: float
    severity: float
    triggered_modules: List[str]


class DetectionModule:
    name: str = "generic"
    version: str = "0.1.0"

    def predict(self, record: FeatureRecord) -> DetectionResult:  # pragma: no cover
        raise NotImplementedError


# ──────────────────────────────────────────────────────────────────────
# Stage 0: Baseline Anomaly Detection (Deep Autoencoder)
# ──────────────────────────────────────────────────────────────────────

# --- Column lists (must match train_baseline.py exactly) ---
_IDENTIFIER_COLS = [
    "src_ip", "dst_ip", "captured_at", "dataset_name", "source_pcap",
    "matched_sni_domain", "ja4d_fqdn", "ja4d_ip",
]
_CONSTANT_COLS = [
    "fwd_urg_flags", "bwd_urg_flags", "urg_flag_count",
    "idle_mean", "idle_std", "idle_max", "idle_min",
    "uses_port_853", "dns_query_count", "dns_answer_count",
]
_DUPLICATE_DROP = [
    "subflow_fwd_packets", "subflow_bwd_packets",
    "avg_fwd_segment_size", "avg_bwd_segment_size",
    "active_mean", "active_std", "active_max", "active_min",
    "fwd_psh_ack_count", "bwd_psh_ack_count",
    "fwd_bulk_bytes", "bwd_bulk_bytes",
    "avg_pkt_size", "pkt_len_variance",
    "fwd_avg_bulk_rate", "bwd_avg_bulk_rate",
    "flow_bytes_sent", "flow_bytes_received",
]
_SPARSE_JA4_DROP = [
    "ja4x", "ja4d", "ja4d_type", "ja4d_size", "ja4d_options",
    "ja4d_request_list", "ja4ssh", "ja4h",
    "ja4h_method", "ja4h_version", "ja4h_cookie", "ja4h_referer",
    "ja4h_header_count", "ja4h_lang", "ja4h_header_hash",
    "ja4h_cookie_name_hash", "ja4h_cookie_value_hash",
]
_HIGH_CORR_DROP = [
    "ack_flag_count", "fwd_iat_total", "fwd_header_len",
    "response_time_mode", "fwd_avg_bytes_bulk", "bwd_avg_bytes_bulk",
    "fwd_avg_packets_bulk", "bwd_avg_packets_bulk",
    "subflow_fwd_bytes", "subflow_bwd_bytes",
]
_ALL_DROP = set(
    _IDENTIFIER_COLS + _CONSTANT_COLS + _DUPLICATE_DROP +
    _SPARSE_JA4_DROP + _HIGH_CORR_DROP
)

_JA4_FREQ_ENCODE = [
    "ja4", "ja4s", "ja4l_c", "ja4l_s", "ja4t", "ja4ts",
    "ja4_cipher_hash", "ja4_extension_hash",
    "ja4s_cipher", "ja4s_ext_hash",
    "ja4t_tcp_options", "ja4ts_tcp_options",
]
_JA4_CAT_ENCODE = [
    "ja4_version", "ja4_sni", "ja4_alpn", "ja4s_version", "ja4s_alpn",
]


class _DeepAutoencoder(nn.Module):
    """Mirror of the architecture used during training."""

    def __init__(self, input_dim: int, bottleneck: int = 16):
        super().__init__()
        h1 = max(input_dim // 2, 64)
        h2 = max(input_dim // 4, 32)
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, h1), nn.BatchNorm1d(h1), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(h1, h2), nn.BatchNorm1d(h2), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(h2, bottleneck), nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck, h2), nn.BatchNorm1d(h2), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(h2, h1), nn.BatchNorm1d(h1), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(h1, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


def _categorize_port(port) -> str:
    try:
        p = int(port)
    except (TypeError, ValueError):
        return "dynamic"
    if p <= 1023:
        return "well_known"
    elif p <= 49151:
        return "registered"
    return "dynamic"


class BaselineModule(DetectionModule):
    """
    Stage 0 — Unsupervised anomaly detection using a Deep Autoencoder
    trained exclusively on benign network traffic.

    Flags flows whose reconstruction error exceeds the 95th-percentile
    threshold learned from the validation set.
    """

    def __init__(self):
        self.name = "baseline-anomaly"
        self.version = "1.0.0"
        self.model = None
        self.scaler = None
        self.freq_maps = {}
        self.cat_maps = {}
        self.feature_cols = []
        self.threshold = 0.0
        self.is_loaded = False
        self._load()

    def _load(self):
        base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ml_models")
        paths = {
            "model": os.path.join(base, "baseline_autoencoder.pt"),
            "scaler": os.path.join(base, "baseline_scaler.pkl"),
            "freq": os.path.join(base, "baseline_freq_maps.pkl"),
            "cat": os.path.join(base, "baseline_cat_maps.pkl"),
            "features": os.path.join(base, "baseline_features.json"),
        }
        for tag, p in paths.items():
            if not os.path.exists(p):
                logger.warning("BaselineModule: missing %s at %s", tag, p)
                return

        try:
            with open(paths["features"]) as f:
                self.feature_cols = json.load(f)
            self.scaler = joblib.load(paths["scaler"])
            self.freq_maps = joblib.load(paths["freq"])
            self.cat_maps = joblib.load(paths["cat"])

            input_dim = len(self.feature_cols)
            self.model = _DeepAutoencoder(input_dim, bottleneck=16)
            self.model.load_state_dict(
                torch.load(paths["model"], map_location="cpu", weights_only=True)
            )
            self.model.eval()

            # Threshold = 95th percentile of validation reconstruction errors
            # Computed during training and stored in the evaluation results
            eval_path = os.path.join(base, "evaluation_results_corrected.json")
            if os.path.exists(eval_path):
                with open(eval_path) as f:
                    eval_results = json.load(f)
                self.threshold = eval_results.get("Deep Autoencoder", {}).get("threshold", 0.434)
            else:
                self.threshold = 0.434  # fallback from training

            self.is_loaded = True
            logger.info(
                "BaselineModule: loaded autoencoder (%d features, threshold=%.4f)",
                input_dim, self.threshold,
            )
        except Exception as e:
            logger.error("BaselineModule: failed to load — %s", e)

    def _preprocess_single(self, payload: Dict) -> Optional[np.ndarray]:
        """Preprocess a single flow dict into scaled feature vector."""
        try:
            row = {}
            for col in payload:
                if col in _ALL_DROP:
                    continue
                row[col] = payload[col]

            # Port categorization
            dst_port = payload.get("dst_port", 0)
            port_cat = _categorize_port(dst_port)
            row["port_well_known"] = 1.0 if port_cat == "well_known" else 0.0
            row["port_registered"] = 1.0 if port_cat == "registered" else 0.0
            row["port_dynamic"] = 1.0 if port_cat == "dynamic" else 0.0
            row.pop("dst_port", None)
            row.pop("src_port", None)

            # Protocol one-hot
            proto = payload.get("protocol", 0)
            try:
                proto = int(proto)
            except (TypeError, ValueError):
                proto = 0
            row["proto_6"] = 1.0 if proto == 6 else 0.0
            row["proto_17"] = 1.0 if proto == 17 else 0.0
            row.pop("protocol", None)

            # JA4 frequency encoding
            for col in _JA4_FREQ_ENCODE:
                val = payload.get(col)
                fmap = self.freq_maps.get(col, {})
                row[col + "_freq"] = float(fmap.get(val, 0))
                row.pop(col, None)

            # JA4 categorical encoding
            for col in _JA4_CAT_ENCODE:
                val = payload.get(col)
                cmap = self.cat_maps.get(col, {})
                row[col + "_enc"] = float(cmap.get(val, 0))
                row.pop(col, None)

            # Build vector in correct column order
            vec = np.zeros(len(self.feature_cols), dtype=np.float32)
            for i, col in enumerate(self.feature_cols):
                val = row.get(col, 0)
                try:
                    vec[i] = float(val) if val is not None else 0.0
                except (TypeError, ValueError):
                    vec[i] = 0.0

            # Replace inf/nan
            vec = np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)

            # Scale
            vec = self.scaler.transform(vec.reshape(1, -1))
            return vec

        except Exception as e:
            logger.debug("BaselineModule: preprocess error — %s", e)
            return None

    def predict(self, record: FeatureRecord) -> DetectionResult:
        if not self.is_loaded:
            return DetectionResult(
                module=self.name, label="benign", confidence=0.0,
                rationale="Baseline model not loaded", score=0.0,
                metadata={"baseline_loaded": False},
            )

        vec = self._preprocess_single(record.payload)
        if vec is None:
            return DetectionResult(
                module=self.name, label="benign", confidence=0.0,
                rationale="Preprocessing failed", score=0.0,
                metadata={"baseline_loaded": True, "preprocess_error": True},
            )

        try:
            tensor = torch.FloatTensor(vec)
            with torch.no_grad():
                recon = self.model(tensor)
                mse = torch.mean((tensor - recon) ** 2, dim=1).item()

            is_anomaly = mse > self.threshold
            # Normalize confidence: 0 at threshold, 1 at 3× threshold
            confidence = min(1.0, max(0.0, (mse - self.threshold) / (2 * self.threshold))) if is_anomaly else 0.0

            return DetectionResult(
                module=self.name,
                label="malicious" if is_anomaly else "benign",
                confidence=round(confidence, 4),
                rationale=f"Reconstruction error {mse:.4f} {'>' if is_anomaly else '<='} threshold {self.threshold:.4f}",
                score=round(mse, 6),
                metadata={
                    "baseline_loaded": True,
                    "reconstruction_error": round(mse, 6),
                    "threshold": round(self.threshold, 6),
                    "is_anomaly": is_anomaly,
                },
            )
        except Exception as e:
            logger.error("BaselineModule: inference error — %s", e)
            return DetectionResult(
                module=self.name, label="benign", confidence=0.0,
                rationale=f"Inference error: {e}", score=0.0,
                metadata={"baseline_loaded": True, "inference_error": str(e)},
            )


# ──────────────────────────────────────────────────────────────────────
# Stage 1: JA4 + Flow Stats Detection Module
# ──────────────────────────────────────────────────────────────────────

class Ja4Module(DetectionModule):
    """Primary threat detection using JA4 fingerprints and flow statistics."""

    def __init__(self, seed: Optional[int] = None):
        self.name = "ja4-module"
        self.model = None
        self.preprocessor = None
        self._load_model()

    def _load_model(self):
        """Attempt to load the real AI model and preprocessor."""
        try:
            base_path = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(base_path, "ml_models", "malicious_server_detector_ensemble_no_ports.pkl")
            preprocessor_path = os.path.join(base_path, "ml_models", "preprocessor_no_ports.pkl")

            if os.path.exists(model_path) and os.path.exists(preprocessor_path):
                self.model = joblib.load(model_path)
                self.preprocessor = joblib.load(preprocessor_path)
                logger.info("Ja4Module: Loaded real AI model from %s", model_path)
            else:
                logger.warning("Ja4Module: Model files not found at %s. Module returns benign by default.", os.path.dirname(model_path))
        except Exception as e:
            logger.error("Ja4Module: Failed to load model: %s", e)

    def predict(self, record: FeatureRecord) -> DetectionResult:
        # If model is loaded, use it for real inference
        if self.model and self.preprocessor:
            try:
                df = pd.DataFrame([record.payload])

                cols_to_drop = ['src_ip', 'dst_ip', 'Mitre_Tactics', 'Mitre_Techniques', 'ja4l_c', 'ja4l_s']
                existing_cols_to_drop = [col for col in cols_to_drop if col in df.columns]
                df_processed = df.drop(columns=existing_cols_to_drop)

                X_transformed = self.preprocessor.transform(df_processed)

                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    prediction = self.model.predict(X_transformed)[0]
                    if hasattr(self.model, "predict_proba"):
                        prob = self.model.predict_proba(X_transformed)[0][1]
                    else:
                        prob = 1.0 if prediction == 1 else 0.0

                if isinstance(prediction, str):
                    label = prediction.lower()
                else:
                    label = "malicious" if prob >= 0.8 else "benign"

                return DetectionResult(
                    module=self.name,
                    label=label,
                    confidence=float(prob),
                    rationale=f"AI Model Prediction (Score: {prob:.3f})",
                    score=float(prob),
                    metadata={"ai_model": True}
                )
            except Exception as e:
                logger.error("Ja4Module: AI inference failed: %s", e)

        # Default: benign with zero confidence
        return DetectionResult(
            module=self.name,
            label="benign",
            confidence=0.0,
            rationale="AI Model not available",
            score=0.0,
            metadata={"ai_model": False}
        )


# ──────────────────────────────────────────────────────────────────────
# Detection Engine — Multi-Stage Pipeline Orchestrator
# ──────────────────────────────────────────────────────────────────────

class DetectionEngine:
    """
    Multi-stage detection pipeline:
      Stage 0: Baseline Anomaly Detection (Deep Autoencoder — unsupervised)
      Stage 1: JA4 + Flow Stats model → malicious/benign verdict
      Stage 2: TTP Classification → MITRE ATT&CK techniques (runs on malicious flows)
      Stage 3: APT Attribution → APT group similarity (aggregated per-actor, on-demand)
    """

    def __init__(self, model_dir: str = "ml_models"):
        # Stage 0: Baseline anomaly detection
        self.baseline_module = BaselineModule()

        # Stage 1: JA4 detection
        self.ja4_module = Ja4Module()

        # Stage 2: TTP classification
        self.ttp_module = TTPModule()

        # Stage 3: APT attribution (initialized lazily, runs on-demand)
        self.apt_module = APTAttributionModule()

        logger.info(
            "DetectionEngine initialized — Baseline: %s, JA4: %s, TTP: %s, APT: %s",
            "loaded" if self.baseline_module.is_loaded else "no-model",
            "loaded" if self.ja4_module.model else "no-model",
            "loaded" if self.ttp_module.is_loaded else "no-model",
            "loaded" if self.apt_module.is_loaded else "no-stix",
        )

    def _aggregate(self, results: List[DetectionResult]) -> AggregateDecision:
        """Aggregate module results into a single verdict."""
        triggered = [res.module for res in results if res.label == "malicious"]
        verdict = "malicious" if triggered else "benign"
        if triggered:
            confidence = max(res.confidence for res in results if res.label == "malicious")
        else:
            confidence = min(res.confidence for res in results) if results else 0.0
        severity = len(triggered) / len(results) if results else 0.0
        return AggregateDecision(
            verdict=verdict,
            confidence=round(confidence, 3),
            severity=round(severity, 3),
            triggered_modules=triggered,
        )

    def process(self, record: FeatureRecord) -> tuple:
        """
        Run the detection pipeline for a single flow.

        Returns
        -------
        (record, aggregate_decision, module_results, ttp_result)
        """
        module_results = []

        # Stage 0: Baseline anomaly detection
        if self.baseline_module.is_loaded:
            baseline_result = self.baseline_module.predict(record)
            module_results.append(baseline_result)

        # Stage 1: JA4 detection
        ja4_result = self.ja4_module.predict(record)
        module_results.append(ja4_result)

        # Aggregate verdict (currently just JA4)
        aggregate = self._aggregate(module_results)

        # Stage 2: TTP classification (only run on malicious flows)
        ttp_result = None
        if aggregate.verdict == "malicious" and self.ttp_module.is_loaded:
            ttp_result = self.ttp_module.predict(record.payload)

        return record, aggregate, module_results, ttp_result

    def get_apt_attribution(
        self,
        actor_ttp_map: Dict[str, Dict[str, Any]],
        top_n: int = 5,
        window_seconds: int = 3600,
    ) -> List[ActorAttribution]:
        """
        Run Stage 3 APT attribution for multiple actors.

        Parameters
        ----------
        actor_ttp_map : dict
            {actor_id: {"ttps": [str], "flow_count": int}}
        top_n : int
            Number of top APT matches per actor.
        window_seconds : int
            Time window used for aggregation.

        Returns
        -------
        List[ActorAttribution]
        """
        return self.apt_module.attribute_actors(actor_ttp_map, top_n=top_n, window_seconds=window_seconds)
