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
      Stage 0: Baseline Anomaly Detection (placeholder — coming soon)
      Stage 1: JA4 + Flow Stats model → malicious/benign verdict
      Stage 2: TTP Classification → MITRE ATT&CK techniques (runs on malicious flows)
      Stage 3: APT Attribution → APT group similarity (aggregated per-actor, on-demand)
    """

    def __init__(self, model_dir: str = "ml_models"):
        # Stage 1: JA4 detection
        self.ja4_module = Ja4Module()

        # Stage 2: TTP classification
        self.ttp_module = TTPModule()

        # Stage 3: APT attribution (initialized lazily, runs on-demand)
        self.apt_module = APTAttributionModule()

        logger.info(
            "DetectionEngine initialized — JA4: %s, TTP: %s, APT: %s",
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
        # Stage 1: JA4 detection
        ja4_result = self.ja4_module.predict(record)
        module_results = [ja4_result]

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
