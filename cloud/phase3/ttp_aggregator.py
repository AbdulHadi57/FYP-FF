"""
ttp_aggregator.py — Aggregate per-flow TTP predictions into actor BehavioralProfiles.

Expected Phase 2 DataFrame schema
-----------------------------------
The other developer's Phase 2 output should be a pandas DataFrame where:
  - One column identifies the actor (default: ``"actor_id"``). This can be a
    source IP, a session ID, a campaign label, or any grouping key.
  - The remaining TTP columns are either:
      (a) boolean / int (0 or 1), or
      (b) float probability in [0, 1].
    Column names must be valid MITRE technique IDs, e.g. ``"T1071"``, ``"T1059.001"``.
    Alternatively a configurable prefix (e.g. ``"ttp_"``) can be stripped automatically.

Usage example
-------------
>>> import pandas as pd
>>> from phase3.ttp_aggregator import TTPAggregator
>>> df = pd.read_csv("phase2_predictions.csv")
>>> aggregator = TTPAggregator(actor_col="src_ip", threshold=0.5)
>>> profiles = aggregator.aggregate(df)
>>> for p in profiles:
...     print(p)
"""

from __future__ import annotations

import logging
from typing import Optional, Sequence

import pandas as pd

from .models import BehavioralProfile

logger = logging.getLogger(__name__)


class TTPAggregator:
    """
    Converts a per-flow Phase 2 prediction DataFrame into a list of
    :class:`~phase3.models.BehavioralProfile` objects, one per actor.

    Parameters
    ----------
    actor_col : str
        Name of the column that identifies the threat actor / grouping key.
        Typical values: ``"src_ip"``, ``"actor_id"``, ``"campaign_id"``.
    threshold : float
        Minimum probability value to consider a TTP *active* for a given flow.
        Rows with a column value >= threshold are treated as positive.
    ttp_prefix : str, optional
        If TTP columns are prefixed (e.g., ``"ttp_T1071"``), this prefix will
        be stripped to recover the raw technique ID (``"T1071"``).
    ttp_columns : list[str], optional
        Explicit list of TTP column names to consider.  If ``None``, all
        columns except ``actor_col`` are treated as TTP columns (after prefix
        stripping).
    """

    def __init__(
        self,
        actor_col: str = "actor_id",
        threshold: float = 0.5,
        ttp_prefix: str = "",
        ttp_columns: Optional[Sequence[str]] = None,
    ) -> None:
        self.actor_col = actor_col
        self.threshold = threshold
        self.ttp_prefix = ttp_prefix
        self._explicit_ttp_columns = list(ttp_columns) if ttp_columns else None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def aggregate(self, df: pd.DataFrame) -> list[BehavioralProfile]:
        """
        Aggregate per-flow predictions into actor behavioral profiles.

        Parameters
        ----------
        df : pd.DataFrame
            Phase 2 prediction DataFrame.

        Returns
        -------
        list[BehavioralProfile]
            One :class:`BehavioralProfile` per unique actor.
        """
        if self.actor_col not in df.columns:
            raise ValueError(
                f"actor_col '{self.actor_col}' not found in DataFrame. "
                f"Available columns: {list(df.columns)}"
            )

        ttp_cols = self._resolve_ttp_columns(df)
        if not ttp_cols:
            raise ValueError(
                "No TTP columns found in the DataFrame. "
                "Check ttp_columns / ttp_prefix arguments."
            )

        logger.info(
            "Aggregating %d flows, %d TTP columns, grouped by '%s'.",
            len(df),
            len(ttp_cols),
            self.actor_col,
        )

        profiles: list[BehavioralProfile] = []

        for actor_id, group in df.groupby(self.actor_col, sort=False):
            active_ttps: set[str] = set()

            for col in ttp_cols:
                technique_id = col[len(self.ttp_prefix) :] if self.ttp_prefix else col
                # A TTP is active if *any* flow in the group exceeds the threshold
                if (group[col] >= self.threshold).any():
                    active_ttps.add(technique_id)

            profile = BehavioralProfile(
                actor_id=str(actor_id),
                ttps=frozenset(active_ttps),
                flow_count=len(group),
                metadata={
                    "first_seen": group.index[0] if not group.empty else None,
                    "last_seen": group.index[-1] if not group.empty else None,
                },
            )
            profiles.append(profile)
            logger.debug("Profile built: %s", profile)

        logger.info("Built %d behavioral profiles.", len(profiles))
        return profiles

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _resolve_ttp_columns(self, df: pd.DataFrame) -> list[str]:
        """Determine which DataFrame columns are TTP feature columns."""
        if self._explicit_ttp_columns:
            missing = [c for c in self._explicit_ttp_columns if c not in df.columns]
            if missing:
                raise ValueError(f"Explicit ttp_columns not in DataFrame: {missing}")
            return self._explicit_ttp_columns

        # Auto-detect: every column except actor_col that starts with the prefix
        candidates = [c for c in df.columns if c != self.actor_col]
        if self.ttp_prefix:
            candidates = [c for c in candidates if c.startswith(self.ttp_prefix)]
        return candidates
