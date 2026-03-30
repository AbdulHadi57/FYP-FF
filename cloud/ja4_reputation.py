import json
import os
from typing import Dict, Any, Optional

class JA4ReputationEngine:
    def __init__(self, db_path: str = "ti_database.json"):
        self.db_path = os.path.join(os.path.dirname(__file__), db_path)
        self.ti_database: Dict[str, Any] = {}
        self.load_database()

    def load_database(self):
        """Loads the JSON snapshot of known JA4 signatures."""
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, "r", encoding="utf-8") as f:
                    self.ti_database = json.load(f)
                print(f"[*] JA4 Reputation Engine loaded {len(self.ti_database)} threat signatures.")
            else:
                print(f"[!] Warning: JA4 TI database not found at {self.db_path}.")
        except Exception as e:
            print(f"[!] Error loading JA4 TI database: {e}")

    def get_reputation(self, ja4_hash: str) -> Optional[Dict[str, Any]]:
        """
        Looks up a JA4 hash in the TI database.
        Returns the reputation dictionary if found, else None.
        """
        if not ja4_hash:
            return None
        return self.ti_database.get(ja4_hash.strip().lower())

# Singleton instance for easy import across Cloud Backend
ja4_engine = JA4ReputationEngine()
