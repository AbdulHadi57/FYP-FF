"""
similarity_engine.py — Compute Jaccard & Cosine similarity between a
BehavioralProfile's TTP set and each APT group in the ATT&CK matrix.

Mathematical definitions
-------------------------
Given:
  P = set of TTPs in the actor's behavioral profile
  A = set of TTPs documented for a given APT group
  U = universe of all known technique IDs

Jaccard similarity:
  J(P, A) = |P ∩ A| / |P ∪ A|

Cosine similarity (on binary indicator vectors over U):
  cos(P, A) = (p⃗ · a⃗) / (||p⃗|| * ||a⃗||)

Combined score:
  score = α * J(P, A) + (1 - α) * cos(P, A)
"""

from __future__ import annotations

import logging
import math
from typing import Sequence

from .models import APTMatch, BehavioralProfile

logger = logging.getLogger(__name__)


class SimilarityEngine:
    """
    Scores every APT group in the ATT&CK matrix against a :class:`BehavioralProfile`
    and returns a ranked list of :class:`APTMatch` results.

    Parameters
    ----------
    alpha : float
        Weight given to Jaccard similarity in the combined score (default 0.6).
        Cosine weight = 1 - alpha.
    min_profile_ttps : int
        Minimum number of active TTPs required in a profile;
        profiles with fewer TTPs are skipped with a warning.
    """

    def __init__(self, alpha: float = 0.6, min_profile_ttps: int = 1) -> None:
        if not 0.0 <= alpha <= 1.0:
            raise ValueError(f"alpha must be in [0, 1], got {alpha}")
        self.alpha = alpha
        self.min_profile_ttps = min_profile_ttps

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def score_profile(
        self,
        profile: BehavioralProfile,
        apt_matrix: dict[str, frozenset[str]],
        all_ttps: frozenset[str],
        top_n: int = 10,
    ) -> list[APTMatch]:
        """
        Rank all APT groups against one behavioral profile.

        Parameters
        ----------
        profile    : BehavioralProfile to compare.
        apt_matrix : {apt_name: frozenset[technique_ids]} from STIXIngestor.
        all_ttps   : Universe of technique IDs (used to build binary vectors).
        top_n      : Return only the top-N matches.

        Returns
        -------
        list[APTMatch]  sorted by combined_score descending.
        """
        if len(profile.ttps) < self.min_profile_ttps:
            logger.warning(
                "Profile '%s' has only %d TTP(s) — below min_profile_ttps=%d. "
                "Returning empty ranking.",
                profile.actor_id,
                len(profile.ttps),
                self.min_profile_ttps,
            )
            return []

        # Build a sorted list of all TTP IDs for stable vector indexing
        sorted_ttps = sorted(all_ttps)

        # Binary vector for the profile
        profile_vec = _binary_vector(profile.ttps, sorted_ttps)

        matches: list[APTMatch] = []
        for apt_name, apt_ttps in apt_matrix.items():
            if not apt_ttps:
                continue

            intersection = profile.ttps & apt_ttps
            union = profile.ttps | apt_ttps

            # --- Jaccard ---
            jaccard = len(intersection) / len(union) if union else 0.0

            # --- Cosine ---
            apt_vec = _binary_vector(apt_ttps, sorted_ttps)
            cosine = _cosine(profile_vec, apt_vec)

            # --- Combined ---
            combined = self.alpha * jaccard + (1.0 - self.alpha) * cosine

            # Coverage: what fraction of the actor's TTPs overlap with this APT?
            coverage_pct = (
                100.0 * len(intersection) / len(profile.ttps) if profile.ttps else 0.0
            )

            # Derive APT ID if embedded in name (heuristic) — will be overridden
            # by attributor when it has the full STIX-id lookup.
            matches.append(
                APTMatch(
                    apt_name=apt_name,
                    apt_id="",  # populated by attributor
                    jaccard=round(jaccard, 6),
                    cosine=round(cosine, 6),
                    combined_score=round(combined, 6),
                    matched_ttps=set(intersection),
                    total_apt_ttps=len(apt_ttps),
                    coverage_pct=round(coverage_pct, 2),
                )
            )

        matches.sort(key=lambda m: m.combined_score, reverse=True)
        return matches[:top_n]

    def score_all_profiles(
        self,
        profiles: list[BehavioralProfile],
        apt_matrix: dict[str, frozenset[str]],
        all_ttps: frozenset[str],
        top_n: int = 10,
    ) -> dict[str, list[APTMatch]]:
        """
        Convenience: score every profile and return ``{actor_id: [APTMatch, ...]}``.
        """
        results: dict[str, list[APTMatch]] = {}
        for profile in profiles:
            results[profile.actor_id] = self.score_profile(
                profile=profile,
                apt_matrix=apt_matrix,
                all_ttps=all_ttps,
                top_n=top_n,
            )
        return results

    # ------------------------------------------------------------------ #
    # Static / standalone helpers (importable for unit tests)
    # ------------------------------------------------------------------ #

    @staticmethod
    def jaccard(set_a: frozenset[str], set_b: frozenset[str]) -> float:
        """
        Compute Jaccard similarity between two sets.

        Returns 0.0 if both sets are empty.
        """
        union = set_a | set_b
        if not union:
            return 0.0
        return len(set_a & set_b) / len(union)

    @staticmethod
    def cosine(set_a: frozenset[str], set_b: frozenset[str]) -> float:
        """
        Compute cosine similarity between two sets represented as binary vectors
        over their joint universe.

        Returns 0.0 if either set is empty.
        """
        if not set_a or not set_b:
            return 0.0
        sorted_ttps = sorted(set_a | set_b)
        vec_a = _binary_vector(set_a, sorted_ttps)
        vec_b = _binary_vector(set_b, sorted_ttps)
        return _cosine(vec_a, vec_b)


# --------------------------------------------------------------------------- #
# Private helpers
# --------------------------------------------------------------------------- #


def _binary_vector(ttp_set: frozenset[str], sorted_ttps: list[str]) -> list[float]:
    """Return a binary indicator list for ttp_set over the sorted_ttps universe."""
    lookup = set(ttp_set)
    return [1.0 if t in lookup else 0.0 for t in sorted_ttps]


def _cosine(vec_a: list[float], vec_b: list[float]) -> float:
    """Compute cosine similarity between two equal-length numeric lists."""
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)
