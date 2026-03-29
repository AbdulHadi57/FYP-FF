"""
stix_ingestor.py — Download, cache, and parse the MITRE ATT&CK Enterprise STIX bundle.

This module:
  1. Downloads the STIX 2.0 JSON bundle from the official mitre/cti GitHub repo.
  2. Caches it to disk to avoid repeated downloads.
  3. Parses intrusion-set objects (APT groups) and their "uses" relationships to
     attack-pattern objects (techniques), resolving MITRE technique IDs (e.g., T1071).
  4. Exposes ``get_apt_ttp_matrix()`` → dict[apt_name, frozenset[technique_id]].
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

MITRE_CTI_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "phase3"
DEFAULT_CACHE_FILE = DEFAULT_CACHE_DIR / "enterprise-attack.json"
CACHE_TTL_SECONDS = 86_400 * 7  # 7 days


# --------------------------------------------------------------------------- #
# STIXIngestor
# --------------------------------------------------------------------------- #


class STIXIngestor:
    """
    Downloads and parses the MITRE ATT&CK Enterprise STIX bundle to build an
    APT-to-TTP mapping matrix.

    Parameters
    ----------
    cache_path : Path-like, optional
        Where to save / load the cached STIX JSON.
        Defaults to ``~/.cache/phase3/enterprise-attack.json``.
    force_refresh : bool
        Re-download even if a fresh cache exists.
    timeout : int
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        cache_path: Optional[os.PathLike] = None,
        force_refresh: bool = False,
        timeout: int = 30,
    ) -> None:
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_FILE
        self.force_refresh = force_refresh
        self.timeout = timeout
        self._matrix: Optional[dict[str, frozenset[str]]] = None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def get_apt_ttp_matrix(self) -> dict[str, frozenset[str]]:
        """
        Return the APT → TTP mapping.

        Returns
        -------
        dict[str, frozenset[str]]
            Keys are APT group names (e.g., ``"APT28"``).
            Values are frozensets of MITRE technique IDs (e.g., ``{"T1071", "T1059"}``).
        """
        if self._matrix is None:
            stix_data = self._load_stix()
            self._matrix = self._parse_matrix(stix_data)
        return self._matrix

    def get_all_techniques(self) -> frozenset[str]:
        """Return the universe of all technique IDs across every APT group."""
        matrix = self.get_apt_ttp_matrix()
        return frozenset(t for ttps in matrix.values() for t in ttps)

    # ------------------------------------------------------------------ #
    # Internal — I/O
    # ------------------------------------------------------------------ #

    def _load_stix(self) -> dict:
        """Load STIX JSON: return from cache or download fresh."""
        if self._cache_is_valid() and not self.force_refresh:
            logger.info("Loading STIX from cache: %s", self.cache_path)
            return self._read_cache()

        logger.info("Downloading MITRE ATT&CK STIX bundle …")
        try:
            response = requests.get(MITRE_CTI_URL, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            self._write_cache(data)
            logger.info("STIX bundle cached → %s", self.cache_path)
            return data
        except requests.RequestException as exc:
            logger.warning("Download failed (%s). Falling back to cache/fixture.", exc)
            if self.cache_path.exists():
                return self._read_cache()
            # Last resort: tiny self-contained fixture so tests never need network
            logger.warning("No cache found — using built-in minimal fixture.")
            return _minimal_stix_fixture()

    def _cache_is_valid(self) -> bool:
        if not self.cache_path.exists():
            return False
        age = time.time() - self.cache_path.stat().st_mtime
        return age < CACHE_TTL_SECONDS

    def _read_cache(self) -> dict:
        with self.cache_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def _write_cache(self, data: dict) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with self.cache_path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh)

    # ------------------------------------------------------------------ #
    # Internal — Parsing
    # ------------------------------------------------------------------ #

    def _parse_matrix(self, stix_data: dict) -> dict[str, frozenset[str]]:
        """
        Parse a STIX 2.x bundle dict into {apt_name: frozenset[technique_id]}.

        Logic
        -----
        1. Index all ``attack-pattern`` objects by their STIX ID, recording the
           MITRE external reference ID (e.g., ``"T1071"``).
        2. Index all ``intrusion-set`` objects (APT groups) by their STIX ID.
        3. Walk every ``relationship`` of type ``"uses"`` where
           source_ref is an intrusion-set and target_ref is an attack-pattern.
        4. Sub-techniques (e.g., T1071.001) are kept as-is and *also* added
           as their parent (T1071) to allow coarse matching.
        """
        objects = stix_data.get("objects", [])

        # Pass 1 — index attack-pattern STIX-ID → technique-ID string
        technique_index: dict[str, str] = {}  # stix_id → technique_id
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                    technique_index[obj["id"]] = ref["external_id"]
                    break

        # Pass 2 — index intrusion-set STIX-ID → group name
        group_index: dict[str, str] = {}  # stix_id → name
        group_mitre_id: dict[str, str] = {}  # stix_id → G-ID
        for obj in objects:
            if obj.get("type") != "intrusion-set":
                continue
            name = obj.get("name", obj["id"])
            group_index[obj["id"]] = name
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    group_mitre_id[obj["id"]] = ref.get("external_id", "")
                    break

        # Pass 3 — walk relationships
        apt_ttps: dict[str, set[str]] = {}
        for obj in objects:
            if (
                obj.get("type") != "relationship"
                or obj.get("relationship_type") != "uses"
            ):
                continue
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            if src not in group_index or tgt not in technique_index:
                continue

            apt_name = group_index[src]
            technique_id = technique_index[tgt]

            apt_ttps.setdefault(apt_name, set()).add(technique_id)

            # Also add parent technique if this is a sub-technique (T1234.001 → T1234)
            if "." in technique_id:
                parent = technique_id.split(".")[0]
                apt_ttps[apt_name].add(parent)

        # Freeze sets
        matrix = {name: frozenset(ttps) for name, ttps in apt_ttps.items()}
        logger.info(
            "Parsed %d APT groups, %d unique techniques.",
            len(matrix),
            len(self.get_all_techniques()) if self._matrix else "?",
        )
        return matrix


# --------------------------------------------------------------------------- #
# Minimal fixture — used when both network and cache are unavailable
# --------------------------------------------------------------------------- #


def _minimal_stix_fixture() -> dict:
    """
    A tiny self-contained STIX 2.x bundle with two fake APT groups and a handful
    of techniques — just enough for unit tests that run without network access.
    """
    return {
        "type": "bundle",
        "id": "bundle--fixture",
        "objects": [
            # Techniques
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Spearphishing Attachment",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1566.001"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "name": "PowerShell",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059.001"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--3",
                "name": "Exfiltration Over C2",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1041"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--4",
                "name": "Application Layer Protocol",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1071"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--5",
                "name": "Credential Dumping",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1003"}
                ],
            },
            # APT groups
            {
                "type": "intrusion-set",
                "id": "intrusion-set--apt28",
                "name": "APT28",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "G0007"}
                ],
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--apt29",
                "name": "APT29",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "G0016"}
                ],
            },
            # Relationships — APT28 uses T1566.001, T1059.001, T1041, T1071
            {
                "type": "relationship",
                "id": "relationship--r1",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt28",
                "target_ref": "attack-pattern--1",
            },
            {
                "type": "relationship",
                "id": "relationship--r2",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt28",
                "target_ref": "attack-pattern--2",
            },
            {
                "type": "relationship",
                "id": "relationship--r3",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt28",
                "target_ref": "attack-pattern--3",
            },
            {
                "type": "relationship",
                "id": "relationship--r4",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt28",
                "target_ref": "attack-pattern--4",
            },
            # APT29 uses T1059.001, T1003, T1071
            {
                "type": "relationship",
                "id": "relationship--r5",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt29",
                "target_ref": "attack-pattern--2",
            },
            {
                "type": "relationship",
                "id": "relationship--r6",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt29",
                "target_ref": "attack-pattern--5",
            },
            {
                "type": "relationship",
                "id": "relationship--r7",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--apt29",
                "target_ref": "attack-pattern--4",
            },
        ],
    }
