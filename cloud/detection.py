from __future__ import annotations

import json
import logging
import random
import os
import re
import joblib
import pandas as pd
import numpy as np
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ttp_module import TTPModule, TTPResult

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


class BehavioralBaselineModule(DetectionModule):
    """Benign-only anomaly detector loaded from network baseline bundle."""

    def __init__(self, model_dir: str = "ml_models"):
        self.name = "behavioral-baseline"
        self.model_dir = model_dir
        self.bundle = None
        self.preprocessor = None
        self.scaler = None
        self.iforest_model = None
        self.cluster_model = None
        self.feature_columns: List[str] = []
        self.drop_columns: List[str] = []
        self.score_method = "iforest"
        self.selected_threshold = 0.5
        self.score_normalization: Dict[str, float] = {}
        self.iforest_weight = 0.7
        self.cluster_weight = 0.3
        self.is_loaded = False
        self._load_bundle()

    def _load_bundle(self) -> None:
        try:
            base_path = os.path.dirname(os.path.abspath(__file__))
            bundle_path = os.path.join(base_path, self.model_dir, "network_baseline_bundle.pkl")
            if not os.path.exists(bundle_path):
                logger.warning("BehavioralBaselineModule: bundle not found at %s", bundle_path)
                return

            self.bundle = joblib.load(bundle_path)
            self.preprocessor = self.bundle.get("preprocessor")
            self.scaler = self.bundle.get("scaler")

            # Support both Isolation Forest and Autoencoder bundles
            self.iforest_model = self.bundle.get("iforest_model")
            self.cluster_model = self.bundle.get("cluster_model")
            self.autoencoder_model = self.bundle.get("autoencoder_model")

            self.feature_columns = list(self.bundle.get("feature_columns", []))
            self.drop_columns = list(
                self.bundle.get("effective_drop_columns",
                    self.bundle.get("applied_drop_columns",
                        self.bundle.get("manual_drop_columns", [])))
            )
            self.score_method = str(self.bundle.get("score_method", "iforest"))
            self.selected_threshold = float(self.bundle.get("selected_threshold", 0.5))

            self.iforest_weight = float(self.bundle.get("iforest_weight", 0.7))
            self.cluster_weight = float(self.bundle.get("cluster_weight", 0.3))
            self.score_normalization = self.bundle.get("score_normalization", {})

            # For autoencoder bundles
            self.error_min = float(self.bundle.get("reconstruction_error_train_min", 0.0))
            self.error_max = float(self.bundle.get("reconstruction_error_train_max", 1.0))

            # Model is loaded if we have preprocessor + scaler + at least one model
            has_model = (self.iforest_model is not None) or (self.autoencoder_model is not None)
            self.is_loaded = all(
                [
                    self.preprocessor is not None,
                    self.scaler is not None,
                    has_model,
                    len(self.feature_columns) > 0,
                ]
            )
            logger.info(
                "BehavioralBaselineModule: loaded=%s, method=%s, threshold=%.4f, features=%d",
                self.is_loaded, self.score_method, self.selected_threshold, len(self.feature_columns)
            )
        except Exception as exc:
            logger.error("BehavioralBaselineModule: failed loading bundle: %s", exc)
            self.is_loaded = False

    @staticmethod
    def _normalize(values: np.ndarray, train_min: float, train_max: float) -> np.ndarray:
        denom = train_max - train_min
        if denom <= 1e-12:
            return np.zeros_like(values, dtype=float)
        return (values - train_min) / denom

    def _prepare_dataframe(self, payload: Dict[str, Any]) -> pd.DataFrame:
        df = pd.DataFrame([payload])
        existing_drop = [column for column in self.drop_columns if column in df.columns]
        if existing_drop:
            df = df.drop(columns=existing_drop)

        missing = [column for column in self.feature_columns if column not in df.columns]
        for column in missing:
            df[column] = np.nan

        extra = [column for column in df.columns if column not in self.feature_columns]
        if extra:
            df = df.drop(columns=extra)

        return df[self.feature_columns]

    def _compute_scores(self, payload: Dict[str, Any]) -> tuple[float, float]:
        x_df = self._prepare_dataframe(payload)
        x_transformed = self.preprocessor.transform(x_df)
        x_scaled = self.scaler.transform(x_transformed)

        if self.score_method == "iforest" and self.iforest_model is not None:
            # Training pipeline computes: anomaly_score = -model.score_samples(X)
            # This produces positive values where higher = more anomalous.
            # The selected_threshold (0.5829) is calibrated against this exact function.
            raw_scores = self.iforest_model.score_samples(x_scaled)
            anomaly_score = float(-raw_scores[0])  # Negate: higher = more anomalous

            # Normalize to 0.0-1.0 confidence using the training score range
            norm = self.score_normalization
            if norm:
                s_min = float(norm.get("iforest_min", norm.get("min", 0.0)))
                s_max = float(norm.get("iforest_max", norm.get("max", 1.0)))
            else:
                s_min, s_max = 0.3, 0.7
            denom = s_max - s_min
            if denom <= 1e-12:
                confidence = 0.5
            else:
                confidence = float(np.clip((anomaly_score - s_min) / denom, 0.0, 1.0))

            return anomaly_score, confidence

        elif self.autoencoder_model is not None:
            # Autoencoder: compute reconstruction MSE
            x_reconstructed = self.autoencoder_model.predict(x_scaled)
            mse_score = np.mean((x_scaled - x_reconstructed) ** 2, axis=1)
            mse = float(mse_score[0])
            denom = self.error_max - self.error_min
            if denom <= 1e-12:
                confidence = 0.0
            else:
                confidence = float(np.clip((mse - self.error_min) / denom, 0.0, 1.0))
            return mse, confidence

        else:
            return 0.0, 0.0

    def predict(self, record: FeatureRecord) -> DetectionResult:
        if not self.is_loaded:
            return DetectionResult(
                module=self.name,
                label="benign",
                confidence=0.0,
                rationale="Behavioral baseline bundle unavailable",
                score=0.0,
                metadata={"baseline_loaded": False},
            )

        try:
            score, raw_confidence = self._compute_scores(record.payload)
            is_anomaly = score >= self.selected_threshold
            
            # Scale confidence: if it is securely benign (score is very low), the confidence of it being benign should be high.
            final_confidence = float(raw_confidence) if is_anomaly else float(max(0.0, 1.0 - raw_confidence))

            return DetectionResult(
                module=self.name,
                label="malicious" if is_anomaly else "benign",
                confidence=final_confidence,
                rationale=(
                    f"Behavioral anomaly score {score:.4f} "
                    f"{'above' if is_anomaly else 'below'} threshold {self.selected_threshold:.4f}"
                ),
                score=score,
                metadata={
                    "baseline_loaded": True,
                    "is_anomaly": bool(is_anomaly),
                    "threshold": float(self.selected_threshold),
                    "score_method": self.score_method,
                },
            )
        except Exception as exc:
            logger.error("BehavioralBaselineModule: inference failed: %s", exc)
            return DetectionResult(
                module=self.name,
                label="benign",
                confidence=0.0,
                rationale="Behavioral inference error",
                score=0.0,
                metadata={"baseline_loaded": True, "error": str(exc)},
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
                    final_confidence = float(prob)
                else:
                    label = "malicious" if prob >= 0.8 else "benign"
                    final_confidence = float(prob) if label == "malicious" else max(0.0, 1.0 - float(prob))

                return DetectionResult(
                    module=self.name,
                    label=label,
                    confidence=final_confidence,
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


class TrafficTypeModule(DetectionModule):
    """Traffic type classifier (DNS/FTP/SSH/VPN/HTTPS/other) for live flows."""

    LABEL_CANONICAL = ("DNS", "FTP", "SSH", "VPN", "HTTPS", "other")

    def __init__(self):
        self.name = "traffic-type"
        self.model = None
        self.model_path: Optional[str] = None
        self.feature_columns: List[str] = []
        self.is_loaded = False
        self._load_model()

    @staticmethod
    def _canon(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", str(value).lower())

    @staticmethod
    def _to_float(value: Any) -> float:
        if value is None:
            return float("nan")
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        try:
            return float(value)
        except (TypeError, ValueError):
            return float("nan")

    def _candidate_model_paths(self) -> List[str]:
        base_path = os.path.dirname(os.path.abspath(__file__))
        env_path = os.getenv("AEGIS_TRAFFIC_MODEL_PATH")

        candidates: List[str] = []
        if env_path:
            candidates.append(env_path)

        candidates.extend(
            [
                os.path.join(base_path, "ml_models", "random_forest.joblib"),
                os.path.join(base_path, "ml_models", "extra_trees.joblib"),
                os.path.join(base_path, "ml_models", "hist_gradient_boosting.joblib"),
                os.path.join(base_path, "ml_models", "logistic_regression.joblib"),
            ]
        )
        return candidates

    def _extract_feature_columns(self, model: Any) -> List[str]:
        if hasattr(model, "feature_names_in_"):
            return [str(c) for c in model.feature_names_in_]

        preprocessor = None
        if hasattr(model, "named_steps"):
            preprocessor = model.named_steps.get("preprocessor")
        if preprocessor is not None and hasattr(preprocessor, "feature_names_in_"):
            return [str(c) for c in preprocessor.feature_names_in_]

        return []

    def _load_model(self) -> None:
        for path in self._candidate_model_paths():
            try:
                resolved = os.path.abspath(path)
                if not os.path.exists(resolved):
                    continue

                loaded = joblib.load(resolved)
                feature_columns = self._extract_feature_columns(loaded)
                if not feature_columns:
                    logger.warning("TrafficTypeModule: model at %s has no feature schema", resolved)
                    continue

                self.model = loaded
                self.model_path = resolved
                self.feature_columns = feature_columns
                self.is_loaded = True
                logger.info("TrafficTypeModule: loaded model from %s", resolved)
                return
            except Exception as exc:
                logger.warning("TrafficTypeModule: failed loading %s (%s)", path, exc)

        self.is_loaded = False
        logger.warning("TrafficTypeModule: model unavailable, falling back to heuristics")

    def _normalize_label(self, raw_label: Any) -> str:
        text = str(raw_label or "").strip().lower()
        if text in {"dns"} or "dns" in text:
            return "DNS"
        if text in {"ftp"} or "ftp" in text:
            return "FTP"
        if text in {"ssh"} or "ssh" in text:
            return "SSH"
        if text in {"vpn"} or "vpn" in text:
            return "VPN"
        if text in {"https", "http", "web"} or "https" in text:
            return "HTTPS"
        if text in {"other", "others", "unknown", "misc"}:
            return "other"
        return "other"

    def _heuristic_label(self, payload: Dict[str, Any]) -> str:
        src_port = int(payload.get("src_port") or 0)
        dst_port = int(payload.get("dst_port") or 0)
        protocol = int(payload.get("protocol") or 0)
        ports = {src_port, dst_port}

        if int(payload.get("is_known_doh_server") or 0) == 1 or int(payload.get("sni_matches_doh") or 0) == 1:
            return "DNS"
        if ports.intersection({53, 5353, 853}):
            return "DNS"
        if ports.intersection({20, 21}):
            return "FTP"
        if 22 in ports:
            return "SSH"
        if ports.intersection({1194, 1701, 1723, 500, 4500, 51820, 1197}):
            return "VPN"
        if ports.intersection({443, 8443, 9443}) or protocol == 443:
            return "HTTPS"
        return "other"

    def _build_expected_frame(self, payload: Dict[str, Any]) -> pd.DataFrame:
        payload_key_by_canon = {self._canon(k): k for k in payload.keys()}

        alias_map: Dict[str, Any] = {
            "totalfwdpacket": "total_fwd_packets",
            "totalbwdpackets": "total_bwd_packets",
            "totallengthoffwdpacket": "subflow_fwd_bytes",
            "totallengthofbwdpacket": "subflow_bwd_bytes",
            "fwdpacketlengthmax": "fwd_pkt_len_max",
            "fwdpacketlengthmin": "fwd_pkt_len_min",
            "fwdpacketlengthmean": "fwd_pkt_len_mean",
            "fwdpacketlengthstd": "fwd_pkt_len_std",
            "bwdpacketlengthmax": "bwd_pkt_len_max",
            "bwdpacketlengthmin": "bwd_pkt_len_min",
            "bwdpacketlengthmean": "bwd_pkt_len_mean",
            "bwdpacketlengthstd": "bwd_pkt_len_std",
            "flowbytess": "flow_bytes_s",
            "flowpacketss": "flow_pkts_s",
            "fwdheaderlength": "fwd_header_len",
            "bwdheaderlength": "bwd_header_len",
            "fwdpacketss": lambda p: (self._to_float(p.get("total_fwd_packets")) / max(self._to_float(p.get("flow_duration")), 1e-6)),
            "bwdpacketss": lambda p: (self._to_float(p.get("total_bwd_packets")) / max(self._to_float(p.get("flow_duration")), 1e-6)),
            "packetlengthmin": "pkt_len_min",
            "packetlengthmax": "pkt_len_max",
            "packetlengthmean": "pkt_len_mean",
            "packetlengthstd": "pkt_len_std",
            "packetlengthvariance": "pkt_len_var",
            "averagepacketsize": "avg_pkt_size",
            "fwdsegmentsizeavg": "avg_fwd_segment_size",
            "bwdsegmentsizeavg": "avg_bwd_segment_size",
            "fwdbytesbulkavg": "fwd_avg_bytes_bulk",
            "fwdpacketbulkavg": "fwd_avg_packets_bulk",
            "fwdbulkrateavg": "fwd_avg_bulk_rate",
            "bwdbytesbulkavg": "bwd_avg_bytes_bulk",
            "bwdpacketbulkavg": "bwd_avg_packets_bulk",
            "bwdbulkrateavg": "bwd_avg_bulk_rate",
            "fwdinitwinbytes": "init_fwd_win_bytes",
            "bwdinitwinbytes": "init_bwd_win_bytes",
            "fwdactdatapkts": "fwd_bulk_packets",
            "fwdsegsizemin": "fwd_pkt_len_min",
        }

        row: Dict[str, float] = {}
        for col in self.feature_columns:
            canon_col = self._canon(col)

            value: Any = None
            if col in payload:
                value = payload.get(col)
            elif canon_col in payload_key_by_canon:
                value = payload.get(payload_key_by_canon[canon_col])
            elif canon_col in alias_map:
                alias = alias_map[canon_col]
                if callable(alias):
                    try:
                        value = alias(payload)
                    except Exception:
                        value = float("nan")
                else:
                    value = payload.get(alias)
            else:
                value = float("nan")

            row[col] = self._to_float(value)

        return pd.DataFrame([row], columns=self.feature_columns)

    def predict(self, record: FeatureRecord) -> DetectionResult:
        payload = record.payload
        heuristic = self._heuristic_label(payload)

        if not self.is_loaded or self.model is None:
            return DetectionResult(
                module=self.name,
                label=heuristic,
                confidence=0.80,
                rationale="Traffic type inferred by protocol/port heuristic (model unavailable)",
                score=0.45,
                metadata={"model_loaded": False, "traffic_type": heuristic},
            )

        try:
            x = self._build_expected_frame(payload)
            pred = self.model.predict(x)[0]
            label = self._normalize_label(pred)

            confidence = 0.6
            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba(x)
                confidence = float(np.max(proba[0]))

            # Use deterministic fallback on very uncertain predictions.
            if confidence < 0.45:
                label = heuristic

            return DetectionResult(
                module=self.name,
                label=label,
                confidence=float(np.clip(confidence, 0.0, 1.0)),
                rationale=f"Traffic classifier predicted {label}",
                score=float(np.clip(confidence, 0.0, 1.0)),
                metadata={
                    "model_loaded": True,
                    "model_path": self.model_path,
                    "traffic_type": label,
                    "raw_prediction": str(pred),
                },
            )
        except Exception as exc:
            logger.error("TrafficTypeModule: inference failed: %s", exc)
            return DetectionResult(
                module=self.name,
                label=heuristic,
                confidence=0.35,
                rationale="Traffic classifier failed, heuristic used",
                score=0.35,
                metadata={"model_loaded": True, "traffic_type": heuristic, "error": str(exc)},
            )


# ──────────────────────────────────────────────────────────────────────
# Detection Engine — Multi-Stage Pipeline Orchestrator
# ──────────────────────────────────────────────────────────────────────

class DetectionEngine:
    """
    Multi-stage detection pipeline:
      Stage 0: Baseline Anomaly Detection (placeholder — coming soon)
      Stage 1: JA4 + Flow Stats model → malicious/benign verdict
      Stage 2: TTP Classification → MITRE ATT&CK techniques (runs on malicious flows)
    """

    def __init__(self, model_dir: str = "ml_models"):
        # Stage 0: Behavioral anomaly baseline
        self.behavior_module = BehavioralBaselineModule(model_dir=model_dir)

        # Stage 1: JA4 detection
        self.ja4_module = Ja4Module()

        # Stage 2: TTP classification
        self.ttp_module = TTPModule()

        # Stage 1.5: Traffic type classification
        self.traffic_type_module = TrafficTypeModule()

        logger.info(
            "DetectionEngine initialized — Behavioral: %s, JA4: %s, TTP: %s, TrafficType: %s",
            "loaded" if self.behavior_module.is_loaded else "no-model",
            "loaded" if self.ja4_module.model else "no-model",
            "loaded" if self.ttp_module.is_loaded else "no-model",
            "loaded" if self.traffic_type_module.is_loaded else "heuristic-only",
        )

    def _aggregate(self, results: List[DetectionResult]) -> AggregateDecision:
        """Aggregate module results into a single verdict."""
        # Exclude ETA/traffic-type classification from malicious threat scaling
        threat_results = [res for res in results if res.module != "traffic-type"]
        
        triggered = [res.module for res in threat_results if res.label == "malicious"]
        verdict = "malicious" if triggered else "benign"
        if triggered:
            confidence = max(res.confidence for res in threat_results if res.label == "malicious")
        else:
            confidence = min(res.confidence for res in threat_results) if threat_results else 0.0
        
        severity = len(triggered) / len(threat_results) if threat_results else 0.0
        
        return AggregateDecision(
            verdict=verdict,
            confidence=round(confidence, 3),
            severity=round(severity, 3),
            triggered_modules=triggered,
        )

    def process(self, record: FeatureRecord) -> tuple:
        """
        Run the multi-stage detection pipeline for a single flow.

        Pipeline flow:
          Stage 0 (Behavioral Baseline) -> anomaly gate
          Stage 1 (JA4 Detection)       -> only if Stage 0 flagged anomaly
          Stage 1.5 (Traffic Type)      -> always runs (informational)
          Stage 2 (TTP Classification)  -> only if final verdict is malicious

        Returns
        -------
        (record, aggregate_decision, module_results, ttp_result)
        """
        # Stage 0: Behavioral anomaly detection (gate)
        behavior_result = self.behavior_module.predict(record)

        # Stage 1: JA4 detection — ONLY if Stage 0 flagged as anomaly
        if behavior_result.label == "malicious":
            ja4_result = self.ja4_module.predict(record)
        else:
            ja4_result = DetectionResult(
                module="ja4-module",
                label="benign",
                confidence=0.0,
                rationale="Skipped: Stage 0 baseline did not flag anomaly",
                score=0.0,
                metadata={"ai_model": False, "skipped_by_gate": True},
            )

        # Stage 1.5: Traffic type classification (always runs, informational only)
        traffic_type_result = self.traffic_type_module.predict(record)
        module_results = [behavior_result, ja4_result, traffic_type_result]

        # Aggregate verdict
        aggregate = self._aggregate(module_results)

        # Stage 2: TTP classification (only run on malicious flows)
        ttp_result = None
        if aggregate.verdict == "malicious" and self.ttp_module.is_loaded:
            ttp_result = self.ttp_module.predict(record.payload)

        return record, aggregate, module_results, ttp_result


