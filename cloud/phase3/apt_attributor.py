"""
apt_attributor.py — Orchestrates the Phase 3 Threat Intel Engine.

Ties together:
  STIXIngestor  → ATT&CK APT-to-TTP matrix
  TTPAggregator → BehavioralProfiles from Phase 2 DataFrame
  SimilarityEngine → ranked APTMatch lists per actor

Quick-start
-----------
>>> from phase3 import Phase3Attributor
>>> import pandas as pd

>>> attributor = Phase3Attributor()
>>> df = pd.read_csv("phase2_predictions.csv")   # Output from Phase 2
>>> results = attributor.attribute(df, actor_col="src_ip", top_n=5)
>>> for actor_id, matches in results.items():
...     print(f"\\n=== {actor_id} ===")
...     for m in matches:
...         print(m)
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

import pandas as pd

from .models import APTMatch, BehavioralProfile
from .similarity_engine import SimilarityEngine
from .stix_ingestor import STIXIngestor
from .ttp_aggregator import TTPAggregator

logger = logging.getLogger(__name__)


class Phase3Attributor:
    """
    End-to-end Phase 3 orchestrator: Phase 2 DataFrame → ranked APT attributions.

    Parameters
    ----------
    stix_cache_path : Path-like, optional
        Custom path to cache the MITRE ATT&CK STIX JSON.
        Defaults to ``~/.cache/phase3/enterprise-attack.json``.
    force_stix_refresh : bool
        Force re-download of the STIX bundle even if a valid cache exists.
    aggregator_threshold : float
        Probability threshold above which a TTP column is considered *active*
        for a given flow (used by TTPAggregator).
    ttp_prefix : str
        Optional prefix to strip from TTP column names (e.g. ``"ttp_"``).
    alpha : float
        Weight of Jaccard vs Cosine in the combined score (default 0.6/0.4).
    min_profile_ttps : int
        Profiles with fewer active TTPs than this are skipped.
    """

    def __init__(
        self,
        stix_cache_path: Optional[os.PathLike] = None,
        force_stix_refresh: bool = False,
        aggregator_threshold: float = 0.5,
        ttp_prefix: str = "",
        alpha: float = 0.6,
        min_profile_ttps: int = 1,
    ) -> None:
        self._ingestor = STIXIngestor(
            cache_path=stix_cache_path,
            force_refresh=force_stix_refresh,
        )
        self._threshold = aggregator_threshold
        self._ttp_prefix = ttp_prefix
        self._engine = SimilarityEngine(alpha=alpha, min_profile_ttps=min_profile_ttps)

        # Populated on first call to attribute()
        self._apt_matrix: Optional[dict[str, frozenset[str]]] = None
        self._all_ttps: Optional[frozenset[str]] = None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def load_stix(self) -> None:
        """
        Explicitly pre-load the STIX matrix.

        This is called automatically on the first ``attribute()`` call but can
        be triggered ahead of time (e.g., during application startup) to avoid
        latency on the first request.
        """
        self._apt_matrix = self._ingestor.get_apt_ttp_matrix()
        self._all_ttps = self._ingestor.get_all_techniques()
        logger.info(
            "STIX matrix loaded: %d APT groups, %d unique techniques.",
            len(self._apt_matrix),
            len(self._all_ttps),
        )

    def attribute(
        self,
        phase2_df: pd.DataFrame,
        actor_col: str = "actor_id",
        ttp_columns: Optional[list[str]] = None,
        top_n: int = 10,
    ) -> dict[str, list[APTMatch]]:
        """
        Attribute network activity to APT groups.

        Parameters
        ----------
        phase2_df  : pd.DataFrame
            Phase 2 output. One row per network flow.
            Must contain ``actor_col`` plus one column per TTP.
        actor_col  : str
            Column name used to group flows into actor profiles.
        ttp_columns : list[str], optional
            Explicit TTP column names. If None, all non-actor columns are used.
        top_n      : int
            Return the top-N APT matches per actor.

        Returns
        -------
        dict[str, list[APTMatch]]
            Keys are actor IDs (values from ``actor_col``).
            Values are sorted lists of :class:`APTMatch` (best match first).
        """
        if self._apt_matrix is None:
            self.load_stix()

        # 1. Aggregate per-flow rows → BehavioralProfiles
        aggregator = TTPAggregator(
            actor_col=actor_col,
            threshold=self._threshold,
            ttp_prefix=self._ttp_prefix,
            ttp_columns=ttp_columns,
        )
        profiles: list[BehavioralProfile] = aggregator.aggregate(phase2_df)

        # 2. Score every profile against the ATT&CK matrix
        results = self._engine.score_all_profiles(
            profiles=profiles,
            apt_matrix=self._apt_matrix,  # type: ignore[arg-type]
            all_ttps=self._all_ttps,       # type: ignore[arg-type]
            top_n=top_n,
        )

        logger.info(
            "Attribution complete for %d actor(s).",
            len(results),
        )
        return results

    def attribute_profile(
        self,
        profile: BehavioralProfile,
        top_n: int = 10,
    ) -> list[APTMatch]:
        """
        Attribute a single pre-built :class:`BehavioralProfile` directly.

        Useful when you already have a profile (e.g., from a live feed) and
        want to skip the aggregation step.
        """
        if self._apt_matrix is None:
            self.load_stix()

        return self._engine.score_profile(
            profile=profile,
            apt_matrix=self._apt_matrix,       # type: ignore[arg-type]
            all_ttps=self._all_ttps,            # type: ignore[arg-type]
            top_n=top_n,
        )

    # ------------------------------------------------------------------ #
    # Convenience: export results to JSON
    # ------------------------------------------------------------------ #

    def results_to_json(
        self,
        results: dict[str, list[APTMatch]],
        output_path: Optional[os.PathLike] = None,
        indent: int = 2,
    ) -> str:
        """
        Serialize attribution results to JSON.

        Parameters
        ----------
        results     : Return value of :meth:`attribute`.
        output_path : If provided, also write the JSON to this file.
        indent      : JSON indentation level.

        Returns
        -------
        str  — JSON string.
        """
        serializable: dict = {}
        for actor_id, matches in results.items():
            serializable[actor_id] = [
                {
                    "apt_name": m.apt_name,
                    "apt_id": m.apt_id,
                    "combined_score": m.combined_score,
                    "jaccard": m.jaccard,
                    "cosine": m.cosine,
                    "coverage_pct": m.coverage_pct,
                    "matched_ttps": sorted(m.matched_ttps),
                    "total_apt_ttps": m.total_apt_ttps,
                }
                for m in matches
            ]

        json_str = json.dumps(serializable, indent=indent)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(json_str, encoding="utf-8")
            logger.info("Attribution results written → %s", output_path)

        return json_str

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def apt_matrix(self) -> dict[str, frozenset[str]]:
        """The loaded APT→TTP matrix (loads STIX on first access)."""
        if self._apt_matrix is None:
            self.load_stix()
        return self._apt_matrix  # type: ignore[return-value]

    @property
    def all_ttps(self) -> frozenset[str]:
        """Full universe of known technique IDs."""
        if self._all_ttps is None:
            self.load_stix()
        return self._all_ttps  # type: ignore[return-value]
