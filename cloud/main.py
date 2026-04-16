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
import requests
import threading

from detection import DetectionEngine, FeatureRecord
from database import get_db_connection
from models import (
    Flow, Stats, TimelinePoint, FlowDetail, ModuleStats,
    ForensicsStats, ActionableEvent, ResolutionRequest,
    TTPStatsResponse, IngestRequest, IngestResponse
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
    allow_origins=["*"],
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
        if "traffic_type" not in columns:
            conn.execute("ALTER TABLE flows ADD COLUMN traffic_type TEXT DEFAULT 'other'")
        if "traffic_type_confidence" not in columns:
            conn.execute("ALTER TABLE flows ADD COLUMN traffic_type_confidence REAL DEFAULT 0")

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
            "behavioral_model": engine.behavior_module.is_loaded,
            "ja4_model": engine.ja4_module.model is not None,
            "ttp_model": engine.ttp_module.is_loaded,
            "traffic_type_model": engine.traffic_type_module.is_loaded,
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


# ──────────────────────────────────────────────────────────────────────
# Threat Intelligence
# ──────────────────────────────────────────────────────────────────────

GEOIP_CACHE = {}
GEOIP_CACHE_LOCK = threading.Lock()

@app.get("/api/c2-intel")
def get_c2_intel():
    """Dynamically fetches top malicious IP destinations and enriches with ip-api.com"""
    conn = get_db_connection()
    try:
        # Get top unique malicious destination IPs natively
        rows = conn.execute("""
            SELECT dst_ip, COUNT(*) as cnt
            FROM flows
            WHERE verdict = 'malicious'
            GROUP BY dst_ip
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()
        
        results = []
        for row in rows:
            ip = row["dst_ip"]
            flows = row["cnt"]
            
            # Skip local/private IP ranges and IPv6 if desired (we'll skip local for now)
            if not ip or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.") or ip.startswith("172."):
                continue
                
            # Check Memory Cache
            with GEOIP_CACHE_LOCK:
                cached = GEOIP_CACHE.get(ip)
                
            if cached:
                geo_data = cached
            else:
                try:
                    resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,as", timeout=3)
                    data = resp.json()
                    if data.get("status") == "success":
                        geo_data = {
                            "geo": f"{data.get('country', 'Unknown')} ({data.get('countryCode', 'N/A')})",
                            "asn": data.get("as", data.get("isp", "Unknown ASN"))
                        }
                    else:
                        geo_data = {"geo": "Reserved Range", "asn": "Unknown ASN"}
                    
                    # Cache the result to avoid Rate Limiting
                    with GEOIP_CACHE_LOCK:
                        GEOIP_CACHE[ip] = geo_data
                except Exception as e:
                    logger.warning(f"Failed to lookup GeoIP for {ip}: {e}")
                    geo_data = {"geo": "Lookup Failed", "asn": "Lookup Failed"}
                    
            results.append({
                "ip": ip,
                "asn": geo_data["asn"],
                "geo": geo_data["geo"],
                "classification": "Suspected C2 Node",
                "flows": flows
            })
            
        return results
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
                     confidence, severity, traffic_type, traffic_type_confidence,
                     summary, features_json
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
        rows = conn.execute("""
            SELECT id, src_ip, dst_ip, captured_at, verdict, ja4_pred, ttp_predictions, protocol, 
            json_extract(features_json, '$.ja4') as ja4,
            json_extract(features_json, '$.ja4s') as ja4s,
            json_extract(features_json, '$.ja4h') as ja4h,
            json_extract(features_json, '$.ja4x') as ja4x,
            json_extract(features_json, '$.ja4ssh') as ja4ssh,
            json_extract(features_json, '$.ja4t') as ja4t,
            json_extract(features_json, '$.ja4ts') as ja4ts,
            json_extract(features_json, '$.ja4l_c') as ja4l_c,
            json_extract(features_json, '$.ja4l_s') as ja4l_s,
            json_extract(features_json, '$.ja4d') as ja4d,
            json_extract(features_json, '$.matched_sni_domain') as matched_sni_domain,
            json_extract(features_json, '$.ja4_sni') as ja4_sni
            FROM flows 
            ORDER BY captured_at DESC 
            LIMIT ?
        """, (limit,)).fetchall()

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
                def add_metric(key, counter):
                    val = row[key] if row[key] is not None else "None"
                    if val != "None":
                        counter[val] += 1

                add_metric("ja4", ja4_io)
                if row["ja4"] is not None: ja4_set.add(row["ja4"])
                add_metric("ja4s", ja4s_io)
                if row["ja4s"] is not None: ja4s_set.add(row["ja4s"])
                add_metric("ja4h", ja4h_io)
                add_metric("ja4x", ja4x_io)
                add_metric("ja4ssh", ja4ssh_io)
                add_metric("ja4t", ja4t_io)
                add_metric("ja4ts", ja4ts_io)
                add_metric("ja4d", ja4d_io)

                ja4l_c = row["ja4l_c"] if row["ja4l_c"] is not None else "None"
                ja4l_s = row["ja4l_s"] if row["ja4l_s"] is not None else "None"
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
                if row["ja4"] is not None or row["ja4s"] is not None:
                    if row["ja4_pred"] == "malicious":
                        ja4_mal_count += 1
                    else:
                        ja4_ben_count += 1

                for feature_type in ['ja4', 'ja4s', 'ja4h', 'ja4x', 'ja4ssh', 'ja4t', 'ja4ts', 'ja4l', 'ja4d']:
                    val = row[feature_type] if feature_type not in ['ja4l'] else None
                    if feature_type == 'ja4l':
                        # ja4l handled separately
                        pass
                    
                    # We map ja4l_c / ja4l_s to 'ja4l' for ui array appending
                    has_val = False
                    display_val = "N/A"
                    if feature_type == 'ja4l':
                         if row['ja4l_c'] is not None and str(row['ja4l_c']) != 'None':
                             if len(recent_features['ja4l']) < 20:
                                 sni_val = row["matched_sni_domain"] or row["ja4_sni"] or "N/A"
                                 recent_features['ja4l'].append({
                                     "id": row["id"],
                                     "captured_at": row["captured_at"],
                                     "src_ip": row["src_ip"],
                                     "dst_ip": row["dst_ip"],
                                     "sni": sni_val,
                                     "value": f"C:{row['ja4l_c']}"
                                 })
                         if row['ja4l_s'] is not None and str(row['ja4l_s']) != 'None':
                             if len(recent_features['ja4l']) < 20:
                                 sni_val = row["matched_sni_domain"] or row["ja4_sni"] or "N/A"
                                 recent_features['ja4l'].append({
                                     "id": row["id"],
                                     "captured_at": row["captured_at"],
                                     "src_ip": row["src_ip"],
                                     "dst_ip": row["dst_ip"],
                                     "sni": sni_val,
                                     "value": f"S:{row['ja4l_s']}"
                                 })
                    else:
                         if val is not None and str(val) != "None":
                             has_val = True
                             display_val = str(val)
                         if has_val and len(recent_features[feature_type]) < 20:
                             sni_val = row["matched_sni_domain"] or row["ja4_sni"] or "N/A"
                             recent_features[feature_type].append({
                                 "id": row["id"],
                                 "captured_at": row["captured_at"],
                                 "src_ip": row["src_ip"],
                                 "dst_ip": row["dst_ip"],
                                 "sni": sni_val,
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

        module_activity = {"behavioral": 0, "ja4": 0, "ttp": ttp_total_predictions}
        for row in mod_activity_rows:
            name = row[0]
            count = row[1]
            if name == 'behavioral-baseline': module_activity["behavioral"] = count
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


@app.get("/api/behavioral/overview")
def get_behavioral_overview(limit: int = 300):
    limit = _clamp_limit(limit, 20, 2000)
    conn = get_db_connection()
    try:
        total_flows = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]

        anomaly_count = conn.execute(
            """
            SELECT COUNT(DISTINCT flow_id)
            FROM module_decisions
            WHERE module_name = 'behavioral-baseline' AND label = 'malicious'
            """
        ).fetchone()[0]

        benign_count = conn.execute(
            """
            SELECT COUNT(DISTINCT flow_id)
            FROM module_decisions
            WHERE module_name = 'behavioral-baseline' AND label = 'benign'
            """
        ).fetchone()[0]

        timeline_rows = conn.execute(
            """
            SELECT
                substr(f.captured_at, 1, 16) AS bucket,
                COUNT(*) AS total,
                SUM(CASE WHEN md.label = 'malicious' THEN 1 ELSE 0 END) AS anomalies,
                SUM(CASE WHEN md.label = 'benign' THEN 1 ELSE 0 END) AS normals
            FROM flows f
            LEFT JOIN module_decisions md
                ON md.flow_id = f.id
                AND md.module_name = 'behavioral-baseline'
            GROUP BY bucket
            ORDER BY bucket DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        timeline = [
            {
                "bucket": row["bucket"],
                "total": int(row["total"] or 0),
                "anomalies": int(row["anomalies"] or 0),
                "normals": int(row["normals"] or 0),
            }
            for row in reversed(timeline_rows)
        ]

        anomaly_rows = conn.execute(
            """
            SELECT f.id, f.captured_at, f.src_ip, f.dst_ip, f.dst_port, f.protocol,
                   f.verdict, md.confidence, md.score, md.rationale
            FROM module_decisions md
            JOIN flows f ON f.id = md.flow_id
            WHERE md.module_name = 'behavioral-baseline' AND md.label = 'malicious'
            ORDER BY f.captured_at DESC
            LIMIT 50
            """
        ).fetchall()

        normal_rows = conn.execute(
            """
            SELECT f.id, f.captured_at, f.src_ip, f.dst_ip, f.dst_port, f.protocol,
                   f.verdict, md.confidence, md.score, md.rationale
            FROM module_decisions md
            JOIN flows f ON f.id = md.flow_id
            WHERE md.module_name = 'behavioral-baseline' AND md.label = 'benign'
            ORDER BY f.captured_at DESC
            LIMIT 50
            """
        ).fetchall()

        anomalies = [
            {
                "id": row["id"],
                "captured_at": row["captured_at"],
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "dst_port": row["dst_port"],
                "protocol": row["protocol"],
                "verdict": row["verdict"],
                "confidence": float(row["confidence"] or 0.0),
                "score": float(row["score"] or 0.0),
                "rationale": row["rationale"] or "",
            }
            for row in anomaly_rows
        ]

        normals = [
            {
                "id": row["id"],
                "captured_at": row["captured_at"],
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "dst_port": row["dst_port"],
                "protocol": row["protocol"],
                "verdict": row["verdict"],
                "confidence": float(row["confidence"] or 0.0),
                "score": float(row["score"] or 0.0),
                "rationale": row["rationale"] or "",
            }
            for row in normal_rows
        ]

        return {
            "model_loaded": bool(engine.behavior_module.is_loaded),
            "total_flows": int(total_flows),
            "anomaly_count": int(anomaly_count),
            "normal_count": int(benign_count),
            "timeline": timeline,
            "anomalies": anomalies,
            "normals": normals,
        }
    finally:
        conn.close()


@app.get("/api/traffic-types/overview")
def get_traffic_type_overview(limit: int = 300):
    limit = _clamp_limit(limit, 20, 2000)
    conn = get_db_connection()
    try:
        labels = ["DNS", "FTP", "SSH", "VPN", "HTTPS", "other"]
        palette = {
            "DNS": "#00d8ff",
            "FTP": "#ff9a3d",
            "SSH": "#ff5470",
            "VPN": "#9f8fff",
            "HTTPS": "#54a6ff",
            "other": "#8d97aa",
        }

        total_predictions = conn.execute(
            "SELECT COUNT(*) FROM flows WHERE traffic_type IS NOT NULL"
        ).fetchone()[0]

        dist_rows = conn.execute(
            """
            SELECT COALESCE(NULLIF(traffic_type, ''), 'other') AS label, COUNT(*) AS cnt
            FROM flows
            GROUP BY label
            """
        ).fetchall()
        counts = {label: 0 for label in labels}
        for row in dist_rows:
            label = str(row["label"] or "other")
            if label not in counts:
                label = "other"
            counts[label] += int(row["cnt"] or 0)

        distribution = []
        for label in labels:
            count = counts[label]
            pct = (100.0 * count / total_predictions) if total_predictions else 0.0
            distribution.append(
                {
                    "label": label,
                    "count": count,
                    "pct": round(pct, 2),
                    "color": palette[label],
                }
            )

        timeline_rows = conn.execute(
            """
            SELECT
                substr(captured_at, 1, 16) AS bucket,
                SUM(CASE WHEN traffic_type = 'DNS' THEN 1 ELSE 0 END) AS dns,
                SUM(CASE WHEN traffic_type = 'FTP' THEN 1 ELSE 0 END) AS ftp,
                SUM(CASE WHEN traffic_type = 'SSH' THEN 1 ELSE 0 END) AS ssh,
                SUM(CASE WHEN traffic_type = 'VPN' THEN 1 ELSE 0 END) AS vpn,
                SUM(CASE WHEN traffic_type = 'HTTPS' THEN 1 ELSE 0 END) AS https,
                SUM(CASE WHEN traffic_type = 'other' OR traffic_type IS NULL OR traffic_type = '' THEN 1 ELSE 0 END) AS other,
                COUNT(*) AS total
            FROM flows
            GROUP BY bucket
            ORDER BY bucket DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        timeline = []
        for row in reversed(timeline_rows):
            timeline.append(
                {
                    "bucket": row["bucket"],
                    "DNS": int(row["dns"] or 0),
                    "FTP": int(row["ftp"] or 0),
                    "SSH": int(row["ssh"] or 0),
                    "VPN": int(row["vpn"] or 0),
                    "HTTPS": int(row["https"] or 0),
                    "other": int(row["other"] or 0),
                    "total": int(row["total"] or 0),
                }
            )

        recent_rows = conn.execute(
            """
            SELECT id, captured_at, src_ip, dst_ip, src_port, dst_port, protocol,
                   verdict, traffic_type, traffic_type_confidence
            FROM flows
            ORDER BY id DESC
            LIMIT 60
            """
        ).fetchall()

        recent = []
        for row in recent_rows:
            label = str(row["traffic_type"] or "other")
            if label not in labels:
                label = "other"
            recent.append(
                {
                    "id": row["id"],
                    "captured_at": row["captured_at"],
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "src_port": row["src_port"],
                    "dst_port": row["dst_port"],
                    "protocol": row["protocol"],
                    "verdict": row["verdict"],
                    "traffic_type": label,
                    "traffic_type_confidence": float(row["traffic_type_confidence"] or 0.0),
                }
            )

        return {
            "model_loaded": bool(engine.traffic_type_module.is_loaded),
            "total_predictions": int(total_predictions),
            "known_labels": labels,
            "distribution": distribution,
            "timeline": timeline,
            "recent": recent,
        }
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
# ──────────────────────────────────────────────────────────────────────
# ETA Stats Endpoint
# ──────────────────────────────────────────────────────────────────────

@app.get("/api/eta/overview")
def get_eta_overview(limit: int = 1000):
    """
    Get Encrypted Traffic Analytics overview features instead of APT.
    """
    conn = get_db_connection()
    try:
        rows = conn.execute("""
            SELECT id, src_ip, dst_ip, captured_at, verdict, features_json
            FROM flows 
            ORDER BY captured_at DESC 
            LIMIT ?
        """, (limit,)).fetchall()

        ja4_set = set()
        ja4s_set = set()
        ja4h_set = set()
        ja4ssh_set = set()
        ja4t_set = set()
        ja4x_set = set()
        ja4d_set = set()
        
        tls_versions = Counter()
        alpn_protocols = Counter()
        
        malicious_hashes = Counter()
        malicious_ips = {}

        for row in rows:
            try:
                feats = json.loads(row["features_json"])
                
                def add_hash(key, target_set):
                    val = feats.get(key)
                    if val and str(val) not in ("None", ""):
                        target_set.add(str(val))
                        
                add_hash("ja4", ja4_set)
                add_hash("ja4s", ja4s_set)
                add_hash("ja4h", ja4h_set)
                add_hash("ja4ssh", ja4ssh_set)
                add_hash("ja4t", ja4t_set)
                add_hash("ja4x", ja4x_set)
                add_hash("ja4d", ja4d_set)
                
                ja4_str = str(feats.get("ja4", ""))
                if ja4_str.startswith("t13"): tls_versions["TLS 1.3"] += 1
                elif ja4_str.startswith("t12"): tls_versions["TLS 1.2"] += 1
                elif ja4_str.startswith("t11"): tls_versions["TLS 1.1"] += 1
                elif ja4_str.startswith("t10"): tls_versions["TLS 1.0"] += 1
                elif ja4_str.startswith("q"): tls_versions["QUIC"] += 1
                elif ja4_str and ja4_str != "None": tls_versions["Other"] += 1
                
                alpn = feats.get("ja4_alpn")
                if alpn:
                    alpn_protocols[str(alpn)] += 1
                    
                if row["verdict"] == "malicious" and ja4_str and ja4_str != "None":
                    malicious_hashes[ja4_str] += 1
                    if ja4_str not in malicious_ips:
                        malicious_ips[ja4_str] = set()
                    malicious_ips[ja4_str].add(row["src_ip"])
                
            except:
                pass

        total_tls = sum(tls_versions.values())
        tls_dist = []
        for v, count in tls_versions.most_common():
            tls_dist.append({"version": v, "count": count, "pct": round((count/total_tls)*100, 1) if total_tls else 0})

        mal_hashes = []
        for h, count in malicious_hashes.most_common(5):
            mal_hashes.append({
                "ja4": h,
                "flow_count": count,
                "malicious_pct": 100.0,
                "source_ips": list(malicious_ips[h])[:3]
            })

        return {
            "fingerprint_diversity": {
                "ja4": len(ja4_set),
                "ja4s": len(ja4s_set),
                "ja4h": len(ja4h_set),
                "ja4ssh": len(ja4ssh_set),
                "ja4t": len(ja4t_set),
                "ja4x": len(ja4x_set),
                "ja4d": len(ja4d_set),
                "total_unique": len(ja4_set) + len(ja4s_set) + len(ja4h_set) + len(ja4ssh_set) + len(ja4t_set) + len(ja4x_set) + len(ja4d_set)
            },
            "tls_distribution": tls_dist,
            "top_malicious_fingerprints": mal_hashes,
            "alpn_distribution": [{"alpn": k, "count": v} for k, v in alpn_protocols.most_common(5)]
        }
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
        traffic_type = "other"
        traffic_type_confidence = 0.0
        for res in results:
            if "ja4" in res.module.lower():
                ja4_pred = res.label
            if res.module == "traffic-type":
                traffic_type = str(res.label or "other")
                traffic_type_confidence = float(res.confidence or 0.0)

        # 4. Serialize TTP predictions
        ttp_json = None
        if ttp_result and ttp_result.techniques:
            ttp_json = json.dumps(ttp_result.to_dict())

        # 5. Store
        payload["traffic_type"] = traffic_type
        payload["traffic_type_confidence"] = traffic_type_confidence
        features_json = json.dumps(payload)
        with conn:
            cursor = conn.execute("""
                INSERT INTO flows (
                    captured_at, src_ip, dst_ip, src_port, dst_port, protocol,
                    total_packets, flow_duration, ja4, ja4s, ja4h,
                    ja4_pred, ttp_predictions,
                    verdict, confidence, severity,
                    traffic_type, traffic_type_confidence,
                    summary, features_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data.captured_at, data.src_ip, data.dst_ip, data.src_port, data.dst_port, data.protocol,
                data.total_packets, data.flow_duration,
                payload.get("ja4", "None"), payload.get("ja4s", "None"), payload.get("ja4h", "None"),
                ja4_pred, ttp_json,
                aggregate.verdict, aggregate.confidence, aggregate.severity,
                traffic_type, traffic_type_confidence,
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
            "traffic_type": traffic_type,
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
                SELECT f.id, f.captured_at, f.src_ip, f.dst_ip, f.confidence, 
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

                    db_module = row["module_name"]

                    if db_module == 'ja4-module':
                        event_type = "Malicious JA4 Fingerprint Match"
                        module_source = "ja4"
                    elif db_module == 'behavioral-baseline':
                        event_type = "Behavioral Anomaly Detection"
                        module_source = "behavioral"
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
            msg = f"Detection pipeline operational. JA4: {'Active' if engine.ja4_module.model else 'No Model'}, TTP: {'Active' if engine.ttp_module.is_loaded else 'No Model'}."
            logs = [
                {
                    "id": "sys_log_001",
                    "offset": 0,
                    "title": "Pipeline Status",
                    "msg": msg,
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
