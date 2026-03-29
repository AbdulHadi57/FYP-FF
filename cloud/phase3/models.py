"""
models.py — Shared dataclasses for Phase 3 Threat Intel Engine.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BehavioralProfile:
    """
    Represents the aggregated tactical footprint of a single actor
    (e.g., a source IP or a campaign cluster).

    Attributes
    ----------
    actor_id   : Unique identifier for the threat actor (e.g., source IP, campaign label).
    ttps       : Frozen set of MITRE ATT&CK technique IDs predicted for this actor.
    flow_count : Number of network flows that contributed to this profile.
    metadata   : Arbitrary key/value pairs (e.g., first_seen, last_seen timestamps).
    """

    actor_id: str
    ttps: frozenset[str]
    flow_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"BehavioralProfile(actor_id={self.actor_id!r}, "
            f"ttps={sorted(self.ttps)}, flows={self.flow_count})"
        )


@dataclass
class APTMatch:
    """
    Represents a single APT attribution candidate with similarity scores.

    Attributes
    ----------
    apt_name       : Human-readable name of the APT group (e.g., "APT28").
    apt_id         : MITRE ATT&CK intrusion-set ID (e.g., "G0007").
    jaccard        : Jaccard similarity between actor profile and APT TTP set.
    cosine         : Cosine similarity between binary TTP vectors.
    combined_score : Weighted combination: α*jaccard + (1-α)*cosine.
    matched_ttps   : Set of TTPs that appear in both the profile and the APT's known set.
    total_apt_ttps : Total number of TTPs documented for this APT group.
    coverage_pct   : Percentage of the actor's TTPs that overlap with this APT.
    """

    apt_name: str
    apt_id: str
    jaccard: float
    cosine: float
    combined_score: float
    matched_ttps: set[str]
    total_apt_ttps: int
    coverage_pct: float

    def __repr__(self) -> str:
        return (
            f"APTMatch({self.apt_name!r}, "
            f"combined={self.combined_score:.3f}, "
            f"jaccard={self.jaccard:.3f}, "
            f"cosine={self.cosine:.3f}, "
            f"coverage={self.coverage_pct:.1f}%)"
        )
