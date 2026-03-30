import requests
import json
import os
import csv
from io import StringIO
import threading
import time

TI_DB_PATH = os.path.join(os.path.dirname(__file__), "ti_database.json")
JA4_MAPPING_URL = "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv"

def determine_threat_level(app_name: str) -> int:
    app_lower = app_name.lower()
    if any(x in app_lower for x in ["cobalt strike", "sliver", "havoc", "qakbot", "pikabot", "darkgate", "lumma"]):
        return 99 # Severe threat
    elif "c2" in app_lower or "dropper" in app_lower or "beacon" in app_lower:
        return 95 
    elif "vpn" in app_lower or "ngrok" in app_lower:
        return 60 # Suspicious
    elif "python" in app_lower or "curl" in app_lower or "golang" in app_lower:
        return 40 # Moderate (tools)
    elif "browser" in app_lower or "safari" in app_lower or "firefox" in app_lower or "cloudflare" in app_lower:
        return 5 # Benign
    return 20 # Unknown

def determine_category(threat_level: int, app_name: str) -> str:
    app_lower = app_name.lower()
    if threat_level >= 90:
        return "Command and Control"
    elif threat_level >= 60:
        return "Suspicious Tool"
    elif threat_level >= 40:
        return "Scripting Engine"
    else:
        return "Benign Networking"

def sync_ja4_database():
    print(f"[JA4 Sync] Starting sync from {JA4_MAPPING_URL}...")
    try:
        response = requests.get(JA4_MAPPING_URL, timeout=10)
        response.raise_for_status()
        csv_data = response.text
        
        # Parse existing DB
        db = {}
        if os.path.exists(TI_DB_PATH):
            with open(TI_DB_PATH, "r") as f:
                db = json.load(f)
                
        reader = csv.DictReader(StringIO(csv_data))
        updates = 0
        for row in reader:
            ja4 = row.get("ja4")
            if not ja4 or len(ja4) < 10:
                continue
                
            # Construct name
            app = row.get("Application") or ""
            lib = row.get("Library") or ""
            
            name_parts = []
            if app: name_parts.append(app)
            if lib: name_parts.append(f"({lib})")
            
            full_name = " ".join(name_parts).strip()
            if not full_name:
                continue
                
            threat_level = determine_threat_level(full_name)
            category = determine_category(threat_level, full_name)
            
            db[ja4] = {
                "app": full_name,
                "threat_level": threat_level,
                "category": category,
                "description": f"Imported from FoxIO JA4+ Mappings. Notes: {row.get('Notes', 'None')}"
            }
            updates += 1
            
        with open(TI_DB_PATH, "w") as f:
            json.dump(db, f, indent=2)
            
        print(f"[JA4 Sync] Completed successfully. Added/Updated {updates} fingerprints.")
        
    except Exception as e:
        print(f"[JA4 Sync] Failed to sync database: {e}")

def start_background_sync(interval_hours=6):
    def sync_loop():
        # Do an initial sync first
        sync_ja4_database()
        while True:
            time.sleep(interval_hours * 3600)
            sync_ja4_database()
            
    thread = threading.Thread(target=sync_loop, daemon=True)
    thread.start()
    print("[JA4 Sync] Background synchronizer started.")

if __name__ == "__main__":
    # If run directly, just do a one-off sync
    sync_ja4_database()
