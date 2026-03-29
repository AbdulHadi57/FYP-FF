"""
ttp_module.py — MITRE ATT&CK TTP Multi-Label Classification Module.

Loads the trained MLP bundle (OneVsRest + MLPClassifier with TruncatedSVD)
and predicts which MITRE ATT&CK techniques are present in a given flow.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger("AegisNet.TTPModule")


@dataclass
class TTPPrediction:
    """A single predicted MITRE technique for a flow."""
    technique_id: str
    technique_name: str
    probability: float
    is_subtechnique: bool = False
    parent_id: Optional[str] = None


@dataclass
class TTPResult:
    """Aggregated TTP prediction result for a single flow."""
    techniques: List[TTPPrediction]
    raw_probabilities: Dict[str, float] = field(default_factory=dict)
    model_available: bool = True
    error: Optional[str] = None

    @property
    def technique_ids(self) -> List[str]:
        return [t.technique_id for t in self.techniques]

    @property
    def technique_count(self) -> int:
        return len(self.techniques)

    def to_dict(self) -> List[Dict[str, Any]]:
        return [
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
                "probability": round(t.probability, 4),
                "is_subtechnique": t.is_subtechnique,
                "parent_id": t.parent_id,
            }
            for t in self.techniques
        ]


class TTPModule:
    """
    Loads the TTP bundle and predicts MITRE ATT&CK techniques per flow.

    The bundle contains:
      - preprocessor: ColumnTransformer (numeric imputer + categorical one-hot)
      - sparse_scaler: MaxAbsScaler
      - svd: TruncatedSVD
      - dense_scaler: StandardScaler
      - classifier: OneVsRestClassifier(MLPClassifier)
      - classes: list[str] — MITRE technique IDs
      - threshold: float — probability cutoff
      - feature_columns: list[str] — expected feature columns
      - drop_columns: list[str] — columns to drop before inference
      - attack_id_to_meta: dict — technique ID → metadata
    """

    def __init__(self, bundle_path: Optional[str] = None):
        self.name = "ttp-module"
        self.bundle = None
        self.preprocessor = None
        self.sparse_scaler = None
        self.svd = None
        self.dense_scaler = None
        self.classifier = None
        self.classes: List[str] = []
        self.threshold: float = 0.35
        self.feature_columns: List[str] = []
        self.drop_columns: List[str] = []
        self.attack_id_to_meta: Dict[str, Any] = {}

        if bundle_path is None:
            base_path = os.path.dirname(os.path.abspath(__file__))
            bundle_path = os.path.join(base_path, "ml_models", "ttp_bundle.pkl")

        self._load_bundle(bundle_path)

    def _load_bundle(self, path: str) -> None:
        """Load the trained TTP model bundle."""
        if not os.path.exists(path):
            logger.warning("TTP bundle not found at %s. Module will return empty predictions.", path)
            return

        try:
            bundle = joblib.load(path)
            self.preprocessor = bundle["preprocessor"]
            self.sparse_scaler = bundle["sparse_scaler"]
            self.svd = bundle["svd"]
            self.dense_scaler = bundle["dense_scaler"]
            self.classifier = bundle["classifier"]
            self.classes = bundle["classes"]
            self.threshold = bundle.get("threshold", 0.35)
            self.feature_columns = bundle.get("feature_columns", [])
            self.drop_columns = bundle.get("drop_columns", [])
            self.attack_id_to_meta = bundle.get("attack_id_to_meta", {})
            self.bundle = bundle
            logger.info(
                "TTP bundle loaded: %d classes, threshold=%.2f, %d features",
                len(self.classes), self.threshold, len(self.feature_columns),
            )
        except Exception as exc:
            logger.error("Failed to load TTP bundle: %s", exc)

    @property
    def is_loaded(self) -> bool:
        return self.classifier is not None

    def predict(self, feature_payload: Dict[str, Any]) -> TTPResult:
        """
        Predict MITRE ATT&CK techniques for a single flow.

        Parameters
        ----------
        feature_payload : dict
            Raw feature dictionary from the capture agent.

        Returns
        -------
        TTPResult with list of predicted techniques above threshold.
        """
        if not self.is_loaded:
            return TTPResult(techniques=[], model_available=False, error="TTP model not loaded")

        try:
            # Build single-row DataFrame
            df = pd.DataFrame([feature_payload])

            # Drop columns that were excluded during training
            cols_to_drop = [c for c in self.drop_columns if c in df.columns]
            if cols_to_drop:
                df = df.drop(columns=cols_to_drop)

            # Also drop identity/label columns that shouldn't be features
            extra_drops = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                           "Mitre_Tactics", "Mitre_Techniques", "Label", "ja4l_c", "ja4l_s"]
            extra_drops = [c for c in extra_drops if c in df.columns]
            if extra_drops:
                df = df.drop(columns=extra_drops)

            # Ensure feature columns align — add missing columns as NaN
            for col in self.feature_columns:
                if col not in df.columns:
                    df[col] = np.nan

            # Reorder to match training column order (only keep known features)
            known_cols = [c for c in self.feature_columns if c in df.columns]
            extra_cols = [c for c in df.columns if c not in self.feature_columns]
            # Use all known + any extra (preprocessor's remainder="drop" handles extras)
            df = df[known_cols + extra_cols]

            # Run the inference pipeline
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")

                # Step 1: Preprocessor (ColumnTransformer)
                X_sparse = self.preprocessor.transform(df)

                # Step 2: MaxAbsScaler
                X_sparse = self.sparse_scaler.transform(X_sparse)

                # Step 3: TruncatedSVD
                X_dense = self.svd.transform(X_sparse)

                # Step 4: StandardScaler
                X_dense = self.dense_scaler.transform(X_dense)

                # Step 5: Predict probabilities
                probabilities = self.classifier.predict_proba(X_dense)[0]

            # Threshold to get active techniques
            predictions: List[TTPPrediction] = []
            raw_probs: Dict[str, float] = {}

            for i, technique_id in enumerate(self.classes):
                prob = float(probabilities[i])
                raw_probs[technique_id] = prob

                if prob >= self.threshold:
                    meta = self.attack_id_to_meta.get(technique_id, {})
                    predictions.append(TTPPrediction(
                        technique_id=technique_id,
                        technique_name=meta.get("name", technique_id),
                        probability=prob,
                        is_subtechnique=meta.get("is_subtechnique", "." in technique_id),
                        parent_id=meta.get("parent_attack_id"),
                    ))

            # If no technique passes threshold, take the top-1 as fallback
            if not predictions and len(probabilities) > 0:
                top_idx = int(np.argmax(probabilities))
                top_id = self.classes[top_idx]
                top_prob = float(probabilities[top_idx])
                meta = self.attack_id_to_meta.get(top_id, {})
                predictions.append(TTPPrediction(
                    technique_id=top_id,
                    technique_name=meta.get("name", top_id),
                    probability=top_prob,
                    is_subtechnique=meta.get("is_subtechnique", "." in top_id),
                    parent_id=meta.get("parent_attack_id"),
                ))

            # Sort by probability descending
            predictions.sort(key=lambda t: t.probability, reverse=True)

            return TTPResult(
                techniques=predictions,
                raw_probabilities=raw_probs,
                model_available=True,
            )

        except Exception as exc:
            logger.error("TTP inference failed: %s", exc, exc_info=True)
            return TTPResult(techniques=[], model_available=True, error=str(exc))
