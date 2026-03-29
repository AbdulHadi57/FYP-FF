"""
apt_attribution.py — APT Group Attribution Module (Phase 3 Wrapper).

Wraps the Phase 3 Threat Intel Engine to provide APT group attribution
based on aggregated TTP predictions per actor (source IP) within
a configurable time window.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional

import pandas as pd

logger = logging.getLogger("AegisNet.APTAttribution")

# Lazy import — the phase3 package is copied into cloud/phase3/
_phase3_loaded = False
_Phase3Attributor = None
_BehavioralProfile = None


def _ensure_phase3():
    global _phase3_loaded, _Phase3Attributor, _BehavioralProfile
    if _phase3_loaded:
        return
    try:
        from phase3 import Phase3Attributor
        from phase3.models import BehavioralProfile
        _Phase3Attributor = Phase3Attributor
        _BehavioralProfile = BehavioralProfile
        _phase3_loaded = True
        logger.info("Phase 3 APT attribution engine loaded successfully.")
    except ImportError as exc:
        logger.error("Failed to import phase3 package: %s", exc)
        _phase3_loaded = False


@dataclass
class APTMatchResult:
    """Single APT group match for an actor."""
    apt_name: str
    apt_id: str
    combined_score: float
    jaccard: float
    cosine: float
    coverage_pct: float
    matched_ttps: List[str]
    total_apt_ttps: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "apt_name": self.apt_name,
            "apt_id": self.apt_id,
            "combined_score": round(self.combined_score, 4),
            "jaccard": round(self.jaccard, 4),
            "cosine": round(self.cosine, 4),
            "coverage_pct": round(self.coverage_pct, 1),
            "matched_ttps": sorted(self.matched_ttps),
            "total_apt_ttps": self.total_apt_ttps,
        }


@dataclass
class ActorAttribution:
    """Full attribution result for a single actor (source IP)."""
    actor_id: str
    ttps_observed: List[str]
    flow_count: int
    top_matches: List[APTMatchResult]
    window_seconds: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "ttps_observed": sorted(self.ttps_observed),
            "ttp_count": len(self.ttps_observed),
            "flow_count": self.flow_count,
            "window_seconds": self.window_seconds,
            "top_matches": [m.to_dict() for m in self.top_matches],
        }


class APTAttributionModule:
    """
    Wraps the Phase 3 engine for use in the AegisNet pipeline.

    Usage:
        module = APTAttributionModule()
        results = module.attribute_actors(actor_ttp_map, top_n=5)
    """

    def __init__(self, alpha: float = 0.6, stix_cache_path: Optional[str] = None):
        self.name = "apt-attribution"
        self.alpha = alpha
        self._attributor = None
        self._stix_cache_path = stix_cache_path
        self._init_attributor()

    def _init_attributor(self) -> None:
        """Initialize the Phase 3 attributor (lazy load STIX on first use)."""
        _ensure_phase3()
        if not _phase3_loaded or _Phase3Attributor is None:
            logger.warning("Phase 3 not available. APT attribution disabled.")
            return
        try:
            kwargs = {"alpha": self.alpha}
            if self._stix_cache_path:
                kwargs["stix_cache_path"] = self._stix_cache_path
            self._attributor = _Phase3Attributor(**kwargs)
            logger.info("APT Attribution module initialized (alpha=%.2f)", self.alpha)
        except Exception as exc:
            logger.error("Failed to initialize Phase 3 attributor: %s", exc)

    @property
    def is_loaded(self) -> bool:
        return self._attributor is not None

    def attribute_single_actor(
        self,
        actor_id: str,
        ttp_ids: List[str],
        flow_count: int = 0,
        top_n: int = 5,
        window_seconds: int = 3600,
    ) -> ActorAttribution:
        """
        Attribute a single actor's TTP set to APT groups.

        Parameters
        ----------
        actor_id : str
            Source IP or campaign identifier.
        ttp_ids : list[str]
            Union of MITRE technique IDs observed for this actor.
        flow_count : int
            Number of malicious flows contributing to this profile.
        top_n : int
            Return top-N APT group matches.
        window_seconds : int
            Time window used for aggregation (for metadata only).

        Returns
        -------
        ActorAttribution with ranked APT matches.
        """
        if not self.is_loaded or _BehavioralProfile is None:
            return ActorAttribution(
                actor_id=actor_id,
                ttps_observed=ttp_ids,
                flow_count=flow_count,
                top_matches=[],
                window_seconds=window_seconds,
            )

        try:
            profile = _BehavioralProfile(
                actor_id=actor_id,
                ttps=frozenset(ttp_ids),
                flow_count=flow_count,
            )

            matches = self._attributor.attribute_profile(profile, top_n=top_n)

            results = []
            for m in matches:
                results.append(APTMatchResult(
                    apt_name=m.apt_name,
                    apt_id=m.apt_id,
                    combined_score=m.combined_score,
                    jaccard=m.jaccard,
                    cosine=m.cosine,
                    coverage_pct=m.coverage_pct,
                    matched_ttps=sorted(m.matched_ttps),
                    total_apt_ttps=m.total_apt_ttps,
                ))

            return ActorAttribution(
                actor_id=actor_id,
                ttps_observed=ttp_ids,
                flow_count=flow_count,
                top_matches=results,
                window_seconds=window_seconds,
            )

        except Exception as exc:
            logger.error("APT attribution failed for %s: %s", actor_id, exc)
            return ActorAttribution(
                actor_id=actor_id,
                ttps_observed=ttp_ids,
                flow_count=flow_count,
                top_matches=[],
                window_seconds=window_seconds,
            )

    def attribute_actors(
        self,
        actor_ttp_map: Dict[str, Dict[str, Any]],
        top_n: int = 5,
        window_seconds: int = 3600,
    ) -> List[ActorAttribution]:
        """
        Attribute multiple actors at once.

        Parameters
        ----------
        actor_ttp_map : dict
            {actor_id: {"ttps": [str], "flow_count": int}}
        top_n : int
            Top-N matches per actor.
        window_seconds : int
            Time window for metadata.

        Returns
        -------
        List[ActorAttribution]
        """
        results = []
        for actor_id, data in actor_ttp_map.items():
            ttp_ids = data.get("ttps", [])
            flow_count = data.get("flow_count", 0)
            result = self.attribute_single_actor(
                actor_id=actor_id,
                ttp_ids=ttp_ids,
                flow_count=flow_count,
                top_n=top_n,
                window_seconds=window_seconds,
            )
            results.append(result)
        return results

    def get_stix_stats(self) -> Dict[str, Any]:
        """Return STIX matrix statistics for display in dashboard."""
        if not self.is_loaded:
            return {"loaded": False, "apt_groups": 0, "total_techniques": 0}

        try:
            matrix = self._attributor.apt_matrix
            all_ttps = self._attributor.all_ttps
            return {
                "loaded": True,
                "apt_groups": len(matrix),
                "total_techniques": len(all_ttps),
                "top_groups": [
                    {"name": name, "technique_count": len(ttps)}
                    for name, ttps in sorted(matrix.items(), key=lambda x: len(x[1]), reverse=True)[:15]
                ],
            }
        except Exception:
            return {"loaded": False, "apt_groups": 0, "total_techniques": 0}
