from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from collections import Counter
import json
import importlib
import sqlite3
import logging
import datetime
import re

from detection import DetectionEngine, FeatureRecord
from database import get_db_connection
from models import (
    Flow, Stats, TimelinePoint, FlowDetail, ModuleStats,
    ForensicsStats, ActionableEvent, ResolutionRequest,
    IngestRequest, IngestModuleResult, IngestResponse,
    TTPStatsResponse, APTStatsResponse,
)
from control_plane import router as control_plane_router, compat_router as control_plane_compat_router
from ja4_reputation import ja4_engine
from ja4_sync import start_background_sync

import os

logger = logging.getLogger("AegisNet.API")

_SAFE_FILTER_KEY_RE = re.compile(r"^[A-Za-z0-9_]+$")


def _clamp_limit(limit: int, min_value: int = 1, max_value: int = 1000) -> int:
    return max(min_value, min(limit, max_value))


def _parse_numeric_range(raw: str) -> Optional[tuple[float, float]]:
    parts = [p.strip() for p in raw.split("-")]
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    try:
        return float(parts[0]), float(parts[1])
    except ValueError:
        return None

app = FastAPI(title="AegisNet API")
app.include_router(control_plane_router)
app.include_router(control_plane_compat_router)


def _detect_ws_backend() -> Optional[str]:
    for module_name in ("websockets", "wsproto"):
        try:
            importlib.import_module(module_name)
            return module_name
        except Exception:
            continue
    return None


@app.on_event("startup")
def ensure_websocket_backend_available() -> None:
    ws_backend = _detect_ws_backend()
    if not ws_backend:
        raise RuntimeError(
            "No WebSocket backend is available for Uvicorn/FastAPI. "
            "Install dependencies with: pip install 'uvicorn[standard]'"
        )
    start_background_sync(interval_hours=6)

# Enable CORS for React frontend
_cors_origins = os.getenv("AEGIS_CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────
# Database Migration Helper
# ──────────────────────────────────────────────────────────────────────

def run_migrations():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(flows)")
        columns = [info[1] for info in cursor.fetchall()]

        if "is_resolved" not in columns:
            conn.execute("ALTER TABLE flows ADD COLUMN is_resolved INTEGER DEFAULT 0")
        if "resolution_note" not in columns:
            conn.execute("ALTER TABLE flows ADD COLUMN resolution_note TEXT")
        if "ttp_predictions" not in columns:
            conn.execute("ALTER TABLE flows ADD COLUMN ttp_predictions TEXT")
        if "apt_matches" not in columns:
            conn.execute("ALTER TABLE flows ADD COLUMN apt_matches TEXT")

        conn.commit()
    except Exception as e:
        logger.warning("Migration warning: %s", e)
    finally:
        conn.close()

# Run migrations on startup
run_migrations()

# Initialize Detection Engine (global)
engine = DetectionEngine(model_dir="ml_models")


# ──────────────────────────────────────────────────────────────────────
# Health
# ──────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "ws_backend": _detect_ws_backend() or "missing",
        "pipeline": {
            "ja4_model": engine.ja4_module.model is not None,
            "ttp_model": engine.ttp_module.is_loaded,
            "apt_stix": engine.apt_module.is_loaded,
        }
    }


# ──────────────────────────────────────────────────────────────────────
# Core Stats
# ──────────────────────────────────────────────────────────────────────

@app.get("/api/stats", response_model=Stats)
def get_stats():
    conn = get_db_connection()
    try:
        total = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        malicious = conn.execute("SELECT COUNT(*) FROM flows WHERE verdict = 'malicious'").fetchone()[0]
        avg_sev = conn.execute("SELECT AVG(severity) FROM flows").fetchone()[0] or 0.0

        top_attackers_rows = conn.execute("""
            SELECT src_ip, COUNT(*) as cnt 
            FROM flows 
            WHERE verdict = 'malicious' 
            GROUP BY src_ip 
            ORDER BY cnt DESC 
            LIMIT 5
        """).fetchall()
        top_attackers = [{"ip": row["src_ip"], "count": row["cnt"]} for row in top_attackers_rows]
        top_src = top_attackers[0]["ip"] if top_attackers else "N/A"
        last_seen = conn.execute("SELECT MAX(captured_at) FROM flows").fetchone()[0]

        return Stats(
            total_flows=total,
            malicious_flows=malicious,
            avg_severity=round(avg_sev, 2),
            top_source=top_src,
            top_attackers=top_attackers,
            last_flow_timestamp=last_seen
        )
    finally:
        conn.close()


@app.get("/api/timeline", response_model=List[TimelinePoint])
def get_timeline(limit: int = 60):
    conn = get_db_connection()
    try:
        query = """
            SELECT substr(captured_at, 1, 16) AS minute_bucket,
                   COUNT(*) AS flow_count,
                   SUM(CASE WHEN verdict = 'malicious' THEN 1 ELSE 0 END) AS malicious_count
            FROM flows
            GROUP BY minute_bucket
            ORDER BY minute_bucket DESC
            LIMIT ?
        """
        rows = conn.execute(query, (limit,)).fetchall()
        results = []
        for row in reversed(rows):
            results.append(TimelinePoint(
                bucket=row["minute_bucket"],
                flow_count=row["flow_count"],
                malicious_count=row["malicious_count"]
            ))
        return results
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────
# Flows
# ──────────────────────────────────────────────────────────────────────

@app.get("/api/flows", response_model=List[Flow])
def get_flows(limit: int = 100, search: str = None, filters: str = None, min_id: int = None):
    limit = _clamp_limit(limit)
    conn = get_db_connection()
    try:
        query = """
            SELECT id, captured_at, src_ip, src_port, dst_ip, dst_port, protocol,
                   total_packets, flow_duration, verdict, 
                   ja4_pred, ttp_predictions, apt_matches,
                   confidence, severity, summary, features_json
            FROM flows
        """
        params = []
        where_clauses = []

        if min_id is not None:
            where_clauses.append("id > ?")
            params.append(min_id)

        if search:
            search_str = f"%{search}%"
            or_clauses = [
                "src_ip LIKE ?",
                "dst_ip LIKE ?",
                "verdict LIKE ?",
                "severity LIKE ?"
            ]
            params.extend([search_str, search_str, search_str, search_str])
            or_clauses.append("CAST(src_port AS TEXT) LIKE ?")
            params.append(search_str)
            or_clauses.append("CAST(dst_port AS TEXT) LIKE ?")
            params.append(search_str)
            or_clauses.append("CAST(id AS TEXT) LIKE ?")
            params.append(search_str)
            where_clauses.append(f"({' OR '.join(or_clauses)})")

        if filters:
            try:
                filter_dict = json.loads(filters)
                if not isinstance(filter_dict, dict):
                    raise ValueError("filters must be a JSON object")

                main_cols = ["id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "verdict",
                            "ja4_pred", "total_packets", "flow_duration", "severity"]

                for col, val in filter_dict.items():
                    if not val:
                        continue
                    val_str = str(val)

                    if col in main_cols:
                        parsed_range = _parse_numeric_range(val_str) if "-" in val_str else None
                        if parsed_range is not None:
                            where_clauses.append(f"{col} BETWEEN ? AND ?")
                            params.extend([parsed_range[0], parsed_range[1]])
                        else:
                            if col in ["src_ip", "dst_ip", "verdict", "ja4_pred", "protocol", "severity"]:
                                where_clauses.append(f"{col} LIKE ?")
                                params.append(f"%{val_str}%")
                            else:
                                where_clauses.append(f"{col} = ?")
                                params.append(val_str)
                    else:
                        if not _SAFE_FILTER_KEY_RE.fullmatch(col):
                            logger.warning("Ignoring unsafe filter key: %s", col)
                            continue

                        json_col = f"json_extract(features_json, '$.{col}')"
                        parsed_range = _parse_numeric_range(val_str) if "-" in val_str else None
                        if parsed_range is not None:
                            where_clauses.append(f"{json_col} BETWEEN ? AND ?")
                            params.extend([parsed_range[0], parsed_range[1]])
                        else:
                            where_clauses.append(f"{json_col} LIKE ?")
                            params.append(f"%{val_str}%")
            except Exception as e:
                logger.warning("Filter Error: %s", e)

        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, tuple(params)).fetchall()

        results = []
        for row in rows:
            flow_dict = dict(row)
            try:
                feats = json.loads(flow_dict.get("features_json", "{}"))
                flow_dict["sni"] = feats.get("matched_sni_domain", None)
            except:
                flow_dict["sni"] = None
            results.append(Flow(**flow_dict))

        return results
    finally:
        conn.close()


@app.get("/api/flows/{flow_id}", response_model=FlowDetail)
def get_flow_detail(flow_id: int):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT id, features_json FROM flows WHERE id = ?", (flow_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Flow not found")
        try:
            features = json.loads(row["features_json"])
        except:
            features = {}
        return FlowDetail(id=row["id"], features=features)
    finally:
        conn.close()


@app.get("/api/flows/{flow_id}/record")
def get_flow_details(flow_id: int):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Flow not found")
        flow = dict(row)
        if flow.get("features_json"):
            try:
                flow["features"] = json.loads(flow["features_json"])
            except:
                flow["features"] = {}
        return flow
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────
# Module Stats (JA4 + TTP + APT)
# ──────────────────────────────────────────────────────────────────────

@app.get("/api/modules", response_model=ModuleStats)
def get_module_stats(limit: int = 1000):
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, src_ip, dst_ip, captured_at, verdict, ja4_pred, ttp_predictions, apt_matches, protocol, features_json FROM flows ORDER BY captured_at DESC LIMIT ?",
            (limit,)
        ).fetchall()

        ja4_set = set()
        ja4s_set = set()
        ja4_io = Counter()
        ja4s_io = Counter()
        ja4h_io = Counter()
        ja4x_io = Counter()
        ja4ssh_io = Counter()
        ja4t_io = Counter()
        ja4ts_io = Counter()
        ja4l_io = Counter()
        ja4d_io = Counter()

        # TTP aggregation
        ttp_technique_counter = Counter()
        ttp_technique_names = {}
        ttp_total_predictions = 0
        ttp_recent_flows = []

        for row in rows:
            try:
                feats = json.loads(row["features_json"])

                def add_metric(key, counter):
                    val = feats.get(key, "None")
                    if val != "None":
                        counter[val] += 1

                add_metric("ja4", ja4_io)
                if feats.get("ja4", "None") != "None": ja4_set.add(feats["ja4"])
                add_metric("ja4s", ja4s_io)
                if feats.get("ja4s", "None") != "None": ja4s_set.add(feats["ja4s"])
                add_metric("ja4h", ja4h_io)
                add_metric("ja4x", ja4x_io)
                add_metric("ja4ssh", ja4ssh_io)
                add_metric("ja4t", ja4t_io)
                add_metric("ja4ts", ja4ts_io)
                add_metric("ja4d", ja4d_io)

                ja4l_c = feats.get("ja4l_c", "None")
                ja4l_s = feats.get("ja4l_s", "None")
                if ja4l_c != "None": ja4l_io[f"C:{ja4l_c}"] += 1
                if ja4l_s != "None": ja4l_io[f"S:{ja4l_s}"] += 1

                # Parse TTP predictions from flow
                ttp_json = row["ttp_predictions"]
                if ttp_json:
                    try:
                        ttps = json.loads(ttp_json)
                        if isinstance(ttps, list) and len(ttps) > 0:
                            ttp_total_predictions += 1
                            for t in ttps:
                                tid = t.get("technique_id", "")
                                tname = t.get("technique_name", tid)
                                ttp_technique_counter[tid] += 1
                                ttp_technique_names[tid] = tname

                            if len(ttp_recent_flows) < 30:
                                ttp_recent_flows.append({
                                    "flow_id": row["id"],
                                    "src_ip": row["src_ip"],
                                    "dst_ip": row["dst_ip"],
                                    "captured_at": row["captured_at"],
                                    "techniques": [t.get("technique_id") for t in ttps],
                                    "technique_count": len(ttps),
                                })
                    except:
                        pass

            except:
                pass

        def get_top(counter):
            top_list = []
            for k, v in counter.most_common(20):
                rep = ja4_engine.get_reputation(k)
                if rep:
                    top_list.append({"hash": k, "count": v, "app": rep.get("app"), "threat_level": rep.get("threat_level"), "category": rep.get("category")})
                else:
                    top_list.append({"hash": k, "count": v, "app": "Unknown Fingerprint", "threat_level": 20, "category": "Unclassified"})
            return top_list

        # JA4 malicious/benign counts
        ja4_mal_count = 0
        ja4_ben_count = 0
        ja4_mal_flows = []

        recent_features = {
            'ja4': [], 'ja4s': [], 'ja4h': [], 'ja4x': [],
            'ja4ssh': [], 'ja4t': [], 'ja4ts': [], 'ja4l': [], 'ja4d': []
        }

        for row in rows:
            try:
                feats = json.loads(row["features_json"])
                if feats.get("ja4", "None") != "None" or feats.get("ja4s", "None") != "None":
                    if row["ja4_pred"] == "malicious":
                        ja4_mal_count += 1
                    else:
                        ja4_ben_count += 1

                for feature_type in ['ja4', 'ja4s', 'ja4h', 'ja4x', 'ja4ssh', 'ja4t', 'ja4ts', 'ja4l', 'ja4d']:
                    val = feats.get(feature_type, None)
                    has_val = False
                    display_val = "N/A"
                    if isinstance(val, list) and len(val) > 0:
                        has_val = True
                        display_val = str(val[0])
                    elif val and str(val) != "None":
                        has_val = True
                        display_val = str(val)
                    if has_val and len(recent_features[feature_type]) < 20:
                        recent_features[feature_type].append({
                            "id": row["id"],
                            "captured_at": row["captured_at"],
                            "src_ip": row["src_ip"],
                            "dst_ip": row["dst_ip"],
                            "sni": feats.get("matched_sni_domain", None) or feats.get("ja4_sni", "N/A"),
                            "value": display_val
                        })
            except:
                pass

        # JA4 Malicious Flows (explicit query)
        ja4_rows = conn.execute("""
            SELECT id, src_ip, dst_ip, captured_at, verdict, protocol, features_json 
            FROM flows 
            WHERE ja4_pred = 'malicious' 
            ORDER BY captured_at DESC 
            LIMIT 50
        """).fetchall()

        for row in ja4_rows:
            try:
                f = json.loads(row["features_json"])
                ja4_hash = f.get("ja4", "N/A")
                rep = ja4_engine.get_reputation(ja4_hash) if ja4_hash != "N/A" else None
                ja4_mal_flows.append({
                    "id": row["id"],
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "captured_at": row["captured_at"],
                    "verdict": row["verdict"],
                    "ja4": ja4_hash,
                    "protocol": row["protocol"],
                    "ja4_sni": f.get("ja4_sni", "N/A"),
                    "sni": f.get("matched_sni_domain", "N/A"),
                    "ja4_version": f.get("ja4_version", "N/A"),
                    "ja4_alpn": f.get("ja4_alpn", "N/A"),
                    "app": rep.get("app") if rep else "Unknown Fingerprint",
                    "threat_level": rep.get("threat_level") if rep else 20,
                    "category": rep.get("category") if rep else "Unclassified"
                })
            except:
                pass

        # Threat Status
        status_counts = conn.execute("""
            SELECT is_resolved, COUNT(*) 
            FROM flows 
            WHERE verdict = 'malicious'
            GROUP BY is_resolved
        """).fetchall()

        open_count = 0
        resolved_count = 0
        for row in status_counts:
            if row[0] == 1:
                resolved_count = row[1]
            else:
                open_count = row[1]
        threat_status = {"open": open_count, "resolved": resolved_count}

        # Module Activity
        mod_activity_rows = conn.execute("""
            SELECT module_name, COUNT(*) 
            FROM module_decisions 
            WHERE label = 'malicious' 
            GROUP BY module_name
        """).fetchall()

        module_activity = {"ja4": 0, "ttp": ttp_total_predictions, "apt": 0}
        for row in mod_activity_rows:
            name = row[0]
            count = row[1]
            if name == 'ja4-module': module_activity["ja4"] = count

        # TTP top techniques
        total_ttp_count = sum(ttp_technique_counter.values())
        ttp_top = []
        for tid, count in ttp_technique_counter.most_common(20):
            ttp_top.append({
                "id": tid,
                "name": ttp_technique_names.get(tid, tid),
                "count": count,
                "pct": round(100 * count / total_ttp_count, 1) if total_ttp_count > 0 else 0,
            })

        return ModuleStats(
            ja4_diversity=len(ja4_set),
            ja4s_diversity=len(ja4s_set),
            top_ja4=get_top(ja4_io),
            top_ja4s=get_top(ja4s_io),
            top_ja4h=get_top(ja4h_io),
            top_ja4x=get_top(ja4x_io),
            top_ja4ssh=get_top(ja4ssh_io),
            top_ja4t=get_top(ja4t_io),
            top_ja4ts=get_top(ja4ts_io),
            top_ja4l=get_top(ja4l_io),
            top_ja4d=get_top(ja4d_io),
            ja4_malicious_count=module_activity["ja4"],
            ja4_benign_count=ja4_ben_count,
            ja4_malicious_flows=ja4_mal_flows,
            # TTP
            ttp_technique_counts=dict(ttp_technique_counter),
            ttp_technique_names=ttp_technique_names,
            ttp_total_predictions=ttp_total_predictions,
            ttp_top_techniques=ttp_top,
            ttp_recent_flows=ttp_recent_flows,
            # General
            recent_features=recent_features,
            module_activity=module_activity,
            threat_status_distribution=threat_status,
        )
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────
# TTP Stats Endpoint
# ──────────────────────────────────────────────────────────────────────

@app.get("/api/ttp-stats", response_model=TTPStatsResponse)
def get_ttp_stats(limit: int = 500):
    """Get TTP technique distribution and recent predictions."""
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, src_ip, dst_ip, captured_at, ttp_predictions FROM flows WHERE ttp_predictions IS NOT NULL ORDER BY captured_at DESC LIMIT ?",
            (limit,)
        ).fetchall()

        technique_counter = Counter()
        technique_names = {}
        recent_flows = []

        for row in rows:
            try:
                ttps = json.loads(row["ttp_predictions"])
                if not isinstance(ttps, list):
                    continue
                for t in ttps:
                    tid = t.get("technique_id", "")
                    technique_counter[tid] += 1
                    technique_names[tid] = t.get("technique_name", tid)

                if len(recent_flows) < 30:
                    recent_flows.append({
                        "flow_id": row["id"],
                        "src_ip": row["src_ip"],
                        "dst_ip": row["dst_ip"],
                        "captured_at": row["captured_at"],
                        "techniques": [t.get("technique_id") for t in ttps],
                    })
            except:
                pass

        total = sum(technique_counter.values())
        distribution = []
        for tid, count in technique_counter.most_common(30):
            distribution.append({
                "id": tid,
                "name": technique_names.get(tid, tid),
                "count": count,
                "pct": round(100 * count / total, 1) if total > 0 else 0,
            })

        return TTPStatsResponse(
            total_predictions=len(rows),
            unique_techniques=len(technique_counter),
            technique_distribution=distribution,
            recent_ttp_flows=recent_flows,
            model_loaded=engine.ttp_module.is_loaded,
        )
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────
# APT Attribution Stats Endpoint
# ──────────────────────────────────────────────────────────────────────

@app.get("/api/apt-stats", response_model=APTStatsResponse)
def get_apt_stats(window: int = 3600, top_n: int = 5):
    """
    Aggregate TTP predictions per actor (src_ip) within the time window
    and run APT attribution on-demand.
    """
    conn = get_db_connection()
    try:
        # Calculate cutoff time
        cutoff = (datetime.datetime.utcnow() - datetime.timedelta(seconds=window)).isoformat()

        # Get all malicious flows with TTP predictions within window
        rows = conn.execute("""
            SELECT src_ip, ttp_predictions 
            FROM flows 
            WHERE verdict = 'malicious' 
            AND ttp_predictions IS NOT NULL
            AND captured_at >= ?
            ORDER BY captured_at DESC
        """, (cutoff,)).fetchall()

        # Aggregate TTPs per actor
        actor_ttp_map = {}  # {src_ip: {"ttps": set(), "flow_count": int}}
        for row in rows:
            src_ip = row["src_ip"]
            if src_ip not in actor_ttp_map:
                actor_ttp_map[src_ip] = {"ttps": set(), "flow_count": 0}
            actor_ttp_map[src_ip]["flow_count"] += 1
            try:
                ttps = json.loads(row["ttp_predictions"])
                if isinstance(ttps, list):
                    for t in ttps:
                        actor_ttp_map[src_ip]["ttps"].add(t.get("technique_id", ""))
            except:
                pass

        # Convert sets to lists for the attribution module
        attribution_input = {}
        for actor_id, data in actor_ttp_map.items():
            attribution_input[actor_id] = {
                "ttps": list(data["ttps"]),
                "flow_count": data["flow_count"],
            }

        # Run APT attribution
        attributions = engine.get_apt_attribution(
            actor_ttp_map=attribution_input,
            top_n=top_n,
            window_seconds=window,
        )

        # Build response
        apt_group_counter = Counter()
        apt_group_scores = {}
        actor_profiles = []

        for attr in attributions:
            top_match_name = attr.top_matches[0].apt_name if attr.top_matches else "None"
            top_match_score = attr.top_matches[0].combined_score if attr.top_matches else 0.0

            actor_profiles.append({
                "actor_id": attr.actor_id,
                "ttp_count": len(attr.ttps_observed),
                "flow_count": attr.flow_count,
                "top_match": top_match_name,
                "top_score": round(top_match_score, 4),
                "ttps": attr.ttps_observed[:10],  # Limit for UI
            })

            for m in attr.top_matches:
                apt_group_counter[m.apt_name] += 1
                if m.apt_name not in apt_group_scores:
                    apt_group_scores[m.apt_name] = []
                apt_group_scores[m.apt_name].append(m.combined_score)

        top_apt_groups = []
        for name, count in apt_group_counter.most_common(15):
            scores = apt_group_scores[name]
            top_apt_groups.append({
                "apt_name": name,
                "match_count": count,
                "avg_score": round(sum(scores) / len(scores), 4),
                "max_score": round(max(scores), 4),
            })

        stix_stats = engine.apt_module.get_stix_stats()

        return APTStatsResponse(
            actor_count=len(actor_profiles),
            top_apt_groups=top_apt_groups,
            actor_profiles=actor_profiles,
            stix_stats=stix_stats,
            window_seconds=window,
        )
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────
# Forensics
# ──────────────────────────────────────────────────────────────────────

@app.get("/api/forensics", response_model=ForensicsStats)
def get_forensics_stats(limit: int = 1000):
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT features_json, dst_port, src_ip FROM flows ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

        flag_counts = Counter()
        payload_fwd = []
        payload_bwd = []
        port_counts = Counter()
        src_ip_counts = Counter()

        for row in rows:
            port_counts[str(row["dst_port"])] += 1
            src_ip_counts[row["src_ip"]] += 1
            try:
                feats = json.loads(row["features_json"])
                if feats.get("syn_flag_count", 0) > 0: flag_counts["SYN"] += 1
                if feats.get("fin_flag_count", 0) > 0: flag_counts["FIN"] += 1
                if feats.get("rst_flag_count", 0) > 0: flag_counts["RST"] += 1
                if feats.get("psh_flag_count", 0) > 0: flag_counts["PSH"] += 1
                if feats.get("ack_flag_count", 0) > 0: flag_counts["ACK"] += 1
                payload_fwd.append(feats.get("fwd_payload_bytes", 0))
                payload_bwd.append(feats.get("bwd_payload_bytes", 0))
            except:
                pass

        return ForensicsStats(
            flag_counts=[{"flag": k, "count": v} for k, v in flag_counts.most_common()],
            payload_stats={"fwd": payload_fwd, "bwd": payload_bwd},
            top_ports=[{"port": k, "count": v} for k, v in port_counts.most_common(10)],
            top_source_ips=[{"ip": k, "count": v} for k, v in src_ip_counts.most_common(10)]
        )
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────
# Ingest (Main pipeline entry point)
# ──────────────────────────────────────────────────────────────────────

@app.post("/api/ingest")
def ingest_flow(data: IngestRequest):
    conn = get_db_connection()
    try:
        # 1. Build FeatureRecord
        payload = data.payload.copy()
        payload.update({
            "src_ip": data.src_ip,
            "dst_ip": data.dst_ip,
            "src_port": data.src_port,
            "dst_port": data.dst_port,
            "protocol": data.protocol,
            "total_packets": data.total_packets,
            "flow_duration": data.flow_duration
        })
        record = FeatureRecord(payload=payload)

        # 2. Run Detection Pipeline (JA4 + TTP)
        processed_record, aggregate, results, ttp_result = engine.process(record)

        # 3. Extract JA4 prediction
        ja4_pred = "none"
        for res in results:
            if "ja4" in res.module.lower():
                ja4_pred = res.label

        # 4. Serialize TTP predictions
        ttp_json = None
        if ttp_result and ttp_result.techniques:
            ttp_json = json.dumps(ttp_result.to_dict())

        # 5. Store
        features_json = json.dumps(payload)
        with conn:
            cursor = conn.execute("""
                INSERT INTO flows (
                    captured_at, src_ip, dst_ip, src_port, dst_port, protocol,
                    total_packets, flow_duration, ja4, ja4s, ja4h,
                    ja4_pred, ttp_predictions,
                    verdict, confidence, severity, summary, features_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data.captured_at, data.src_ip, data.dst_ip, data.src_port, data.dst_port, data.protocol,
                data.total_packets, data.flow_duration,
                payload.get("ja4", "None"), payload.get("ja4s", "None"), payload.get("ja4h", "None"),
                ja4_pred, ttp_json,
                aggregate.verdict, aggregate.confidence, aggregate.severity,
                f"{data.src_ip}:{data.src_port} -> {data.dst_ip}:{data.dst_port}",
                features_json
            ))
            flow_id = cursor.lastrowid

            for res in results:
                conn.execute("""
                    INSERT INTO module_decisions (
                        flow_id, module_name, label, confidence, score, rationale
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (flow_id, res.module, res.label, res.confidence, res.score, res.rationale))

        return {
            "status": "ok",
            "flow_id": flow_id,
            "verdict": aggregate.verdict,
            "ttp_count": ttp_result.technique_count if ttp_result else 0,
        }
    except Exception as e:
        logger.error("Ingest Error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────
# Event Resolution
# ──────────────────────────────────────────────────────────────────────

@app.post("/api/events/{event_id}/resolve")
def resolve_event(event_id: str, request: ResolutionRequest):
    conn = get_db_connection()
    try:
        if event_id.startswith("evt_flow_"):
            flow_id_raw = event_id.replace("evt_flow_", "", 1)
            if not flow_id_raw.isdigit():
                raise HTTPException(status_code=400, detail="Invalid flow event id")

            flow_id = int(flow_id_raw)
            cursor = conn.execute(
                "UPDATE flows SET is_resolved = 1, resolution_note = ? WHERE id = ?",
                (request.note, flow_id),
            )
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Flow not found")
            conn.commit()
            return {"status": "success", "message": "Event marked as resolved"}
        else:
            return {"status": "success", "message": "Event acknowledged (virtual)"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────
# Events (Synthesized from flows + system)
# ──────────────────────────────────────────────────────────────────────

@app.get("/api/events", response_model=List[ActionableEvent])
def get_events(limit: int = 50, status: str = "all", module: Optional[str] = None, min_confidence: float = 0.0):
    conn = get_db_connection()
    events = []

    try:
        if status != "system":
            rows = conn.execute("""
                SELECT f.id, f.captured_at, f.src_ip, f.dst_ip, f.features_json, f.confidence, 
                       f.protocol, f.is_resolved, f.resolution_note, f.ttp_predictions,
                       md.module_name, md.rationale
                FROM flows f
                LEFT JOIN module_decisions md ON f.id = md.flow_id AND md.label = 'malicious'
                WHERE f.verdict = 'malicious'
                GROUP BY f.id
                ORDER BY f.confidence DESC, f.id DESC LIMIT 100
            """).fetchall()

            for row in rows:
                try:
                    is_resolved = row["is_resolved"] == 1
                    if status == "open" and is_resolved: continue
                    if status == "resolved" and not is_resolved: continue

                    row_conf = row["confidence"] if row["confidence"] is not None else 0.0
                    if row_conf < min_confidence: continue

                    feats = json.loads(row["features_json"])
                    ja4 = feats.get("ja4", "N/A")

                    db_module = row["module_name"]

                    if db_module == 'ja4-module':
                        event_type = "Malicious JA4 Fingerprint Match"
                        module_source = "ja4"
                    else:
                        event_type = "High Confidence Malicious Flow"
                        module_source = "ja4"

                    # Enrich with TTP info if available
                    ttp_info = ""
                    ttp_json = row["ttp_predictions"]
                    if ttp_json:
                        try:
                            ttps = json.loads(ttp_json)
                            if isinstance(ttps, list) and len(ttps) > 0:
                                ttp_names = [t.get("technique_id", "") for t in ttps[:3]]
                                ttp_info = f" TTPs: {', '.join(ttp_names)}."
                                module_source = "ttp"
                                event_type = f"MITRE ATT&CK TTPs Detected ({len(ttps)} techniques)"
                        except:
                            pass

                    if module and module.lower() != module_source: continue

                    events.append(ActionableEvent(
                        id=f"evt_flow_{row['id']}",
                        timestamp=row["captured_at"],
                        severity="critical" if not is_resolved else "info",
                        category="threat",
                        module_source=module_source,
                        confidence=row["confidence"],
                        title=f"{event_type} from {row['src_ip']}",
                        message=f"{row['rationale'] or 'Detected malicious traffic.'} Targeting {row['dst_ip']}.{ttp_info}",
                        source_ip=row["src_ip"],
                        affected_asset=row["dst_ip"],
                        action_required=not is_resolved,
                        recommended_action="Isolate source IP immediately." if not is_resolved else "No actions required",
                        status="open" if not is_resolved else "resolved",
                        resolution_note=row["resolution_note"],
                        flow_id=row["id"]
                    ))
                except Exception as e:
                    pass

        # System logs
        if status == "system" or status == "all":
            base_time = datetime.datetime.now()
            logs = [
                {
                    "id": "sys_log_001",
                    "offset": 0,
                    "title": "Pipeline Status",
                    "msg": f"Detection pipeline operational. JA4: {'Active' if engine.ja4_module.model else 'No Model'}, TTP: {'Active' if engine.ttp_module.is_loaded else 'No Model'}, APT: {'Active' if engine.apt_module.is_loaded else 'No STIX'}.",
                    "severity": "info"
                },
                {
                    "id": "sys_log_002",
                    "offset": 5,
                    "title": "Interface Monitor",
                    "msg": "Capture interface is operating in promiscuous mode.",
                    "severity": "info"
                },
            ]
            for log in logs:
                t = (base_time - datetime.timedelta(minutes=log["offset"])).isoformat()
                events.append(ActionableEvent(
                    id=log["id"],
                    timestamp=t,
                    severity=log["severity"],
                    category="system",
                    module_source="system",
                    confidence=None,
                    title=log["title"],
                    message=log["msg"],
                    source_ip="localhost",
                    action_required=False,
                    recommended_action="Monitor system health.",
                    status="system",
                    flow_id=None
                ))

    except Exception as e:
        logger.error("Error generating events: %s", e)
    finally:
        conn.close()

    events.sort(key=lambda x: (x.confidence if x.confidence is not None else 0, x.timestamp), reverse=True)
    return events[:limit]
